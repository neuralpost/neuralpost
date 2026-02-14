import { db } from '../db';
import { agents, webhookDeliveries } from '../db/schema';
import { eq, and, lt, inArray, sql } from 'drizzle-orm';
import { generateWebhookSignature, decryptWebhookSecret, MessagePart, isPublicUrl } from '../utils';
import { randomUUID } from 'crypto';

// ═══════════════════════════════════════════════════════════════════════════
// WEBHOOK DELIVERY SERVICE
// Push messages/events to agents via their registered webhook URLs
// Features: in-memory queue, HMAC signing, retry with exponential backoff
// V3: A2A Protocol format for all webhook payloads
// ═══════════════════════════════════════════════════════════════════════════

// ─── Configuration ───────────────────────────────────────────────────────

const CONFIG = {
  maxRetries: 5,
  baseDelayMs: 1000,         // 1s → 2s → 4s → 8s → 16s
  maxDelayMs: 60_000,        // Cap at 60s
  timeoutMs: 10_000,         // 10s HTTP timeout per attempt
  processBatchSize: 20,      // Process up to 20 items per tick
  processIntervalMs: 2_000,  // Check queue every 2s
  deliveryTtlDays: 7,        // Keep delivery logs for 7 days
  maxQueueSize: 10_000,      // Max in-memory queue items (OOM protection)
};

// ─── A2A Protocol Types (v0.3.0 Compliant) ──────────────────────────────

// File content types
export interface A2AFileWithUri {
  uri: string;
  name?: string;
  mimeType?: string;
}

export interface A2AFileWithBytes {
  bytes: string;  // base64 encoded
  name?: string;
  mimeType?: string;
}

// Part types with `kind` discriminator (REQUIRED by A2A spec v0.3.0)
export interface A2ATextPart {
  kind: 'text';
  text: string;
  metadata?: Record<string, unknown>;
}

export interface A2AFilePart {
  kind: 'file';
  file: A2AFileWithUri | A2AFileWithBytes;
  metadata?: Record<string, unknown>;
}

export interface A2ADataPart {
  kind: 'data';
  data: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

// Union type for all parts
export type A2APart = A2ATextPart | A2AFilePart | A2ADataPart;

// A2A TaskState (kebab-case per spec v0.3.0)
export type A2ATaskState = 
  | 'submitted' 
  | 'working' 
  | 'input-required'   // kebab-case!
  | 'completed' 
  | 'canceled' 
  | 'failed' 
  | 'rejected' 
  | 'auth-required';   // kebab-case!

// A2A Message with `kind` discriminator
export interface A2AMessage {
  kind: 'message';     // REQUIRED discriminator
  messageId: string;
  contextId: string;
  taskId?: string;
  role: 'user' | 'agent';
  parts: A2APart[];
  metadata?: Record<string, unknown>;
  referenceTaskIds?: string[];
  extensions?: string[];
}

// A2A Task Status
export interface A2ATaskStatus {
  state: A2ATaskState;
  message?: A2AMessage;
  timestamp?: string;
}

// A2A Artifact
export interface A2AArtifact {
  artifactId: string;
  name?: string;
  description?: string;
  parts: A2APart[];
  metadata?: Record<string, unknown>;
  extensions?: string[];
}

// A2A Task with `kind` discriminator
export interface A2ATask {
  kind: 'task';        // REQUIRED discriminator
  id: string;
  contextId: string;
  status: A2ATaskStatus;
  artifacts?: A2AArtifact[];
  history?: A2AMessage[];
  metadata?: Record<string, unknown>;
}

// A2A TaskStatusUpdateEvent
export interface A2ATaskStatusUpdateEvent {
  kind: 'status-update';  // kebab-case discriminator
  taskId: string;
  contextId: string;
  status: A2ATaskStatus;
  final: boolean;
  metadata?: Record<string, unknown>;
}

// A2A TaskArtifactUpdateEvent
export interface A2ATaskArtifactUpdateEvent {
  kind: 'artifact-update';  // kebab-case discriminator
  taskId: string;
  contextId: string;
  artifact: A2AArtifact;
  append?: boolean;
  lastChunk?: boolean;
  metadata?: Record<string, unknown>;
}

// A2A StreamResponse result type (union of possible results)
export type A2AStreamResult = A2ATask | A2AMessage | A2ATaskStatusUpdateEvent | A2ATaskArtifactUpdateEvent;

// A2A JSON-RPC Response (used for webhook payloads)
export interface A2AStreamResponse {
  jsonrpc: '2.0';
  id?: string | number | null;
  result: A2AStreamResult;
}

// ─── Event Types ─────────────────────────────────────────────────────────

export type WebhookEventType = 
  | 'message.received'
  | 'connection.request'
  | 'connection.accepted'
  | 'connection.rejected';

// Legacy payload type (for internal use)
interface LegacyWebhookData {
  messageId?: string;
  threadId?: string;
  senderId?: string;
  senderDomain?: string;
  body?: string;
  parts?: MessagePart[];
  type?: string;
  taskMeta?: {
    taskId?: string;
    status?: string;
    progress?: number;
    priority?: string;
    timeout?: number;
    artifacts?: Array<{
      artifactId: string;
      name?: string;
      description?: string;
      parts: MessagePart[];
      metadata?: Record<string, unknown>;
    }>;
    result?: unknown;
  };
  metadata?: Record<string, unknown>;
  referenceTaskIds?: string[];
  [key: string]: unknown;
}

// A2A webhook payload (what gets sent to agents)
export type WebhookPayload = A2AStreamResponse;

// ─── A2A Format Converter (v0.3.0 Compliant) ────────────────────────────

/**
 * Convert internal MessagePart to A2A Part format (with kind discriminator)
 */
function convertPartToA2A(part: MessagePart): A2APart {
  const metadata = (part as any).metadata;
  
  if (part.kind === 'text') {
    const textPart: A2ATextPart = {
      kind: 'text',
      text: String(part.content || ''),
    };
    if (metadata) textPart.metadata = metadata;
    return textPart;
  }
  
  if (part.kind === 'data') {
    const dataPart: A2ADataPart = {
      kind: 'data',
      data: (part.content as Record<string, unknown>) || {},
    };
    if (metadata) dataPart.metadata = metadata;
    return dataPart;
  }
  
  if (part.kind === 'file') {
    // FilePart uses nested file object with uri (internal FilePart only has url, no bytes)
    const filePart: A2AFilePart = {
      kind: 'file',
      file: { uri: part.url, name: part.name, mimeType: part.mime },
    };
    if (metadata) filePart.metadata = metadata;
    return filePart;
  }
  
  // Fallback to text part (should not happen with proper typing)
  return {
    kind: 'text',
    text: '',
  };
}

/**
 * Convert internal status to A2A TaskState (kebab-case)
 */
function convertStatusToA2A(status?: string): A2ATaskState {
  switch (status) {
    case 'pending': 
    case 'submitted': 
      return 'submitted';
    case 'working': 
      return 'working';
    case 'completed': 
      return 'completed';
    case 'failed': 
      return 'failed';
    case 'cancelled':
    case 'canceled': 
      return 'canceled';
    case 'input_required':
    case 'input-required': 
      return 'input-required';  // kebab-case!
    case 'rejected': 
      return 'rejected';
    case 'auth_required':
    case 'auth-required': 
      return 'auth-required';   // kebab-case!
    default: 
      return 'submitted';
  }
}

/**
 * Convert internal data to A2A StreamResponse format (v0.3.0 compliant)
 * Uses JSON-RPC 2.0 response format with result containing Task/Message/Event
 */
function convertToA2AFormat(event: WebhookEventType, data: LegacyWebhookData): A2AStreamResponse {
  const timestamp = new Date().toISOString();
  const responseId = data.messageId || randomUUID();
  
  // Convert parts to A2A format (with kind discriminators)
  const a2aParts: A2APart[] = (data.parts || []).map(convertPartToA2A);
  
  // If no parts but has body, create text part
  if (a2aParts.length === 0 && data.body) {
    a2aParts.push({ kind: 'text', text: data.body });
  }
  
  // Build A2A Message with kind discriminator
  const a2aMessage: A2AMessage = {
    kind: 'message',  // REQUIRED discriminator
    messageId: data.messageId || randomUUID(),
    contextId: data.threadId || randomUUID(),
    role: 'user',  // Incoming messages are from "user" (the sending agent)
    parts: a2aParts,
  };
  
  // Add optional fields to message
  if (data.taskMeta?.taskId) {
    a2aMessage.taskId = data.taskMeta.taskId;
  }
  if (data.metadata) {
    a2aMessage.metadata = data.metadata;
  }
  if (data.referenceTaskIds && data.referenceTaskIds.length > 0) {
    a2aMessage.referenceTaskIds = data.referenceTaskIds;
  }
  
  // Handle message.received events
  if (event === 'message.received') {
    // Check if this is a task-related message
    if (data.taskMeta?.taskId || data.type?.includes('task')) {
      // Build task status
      const taskStatus: A2ATaskStatus = {
        state: convertStatusToA2A(data.taskMeta?.status),
        timestamp,
      };
      
      // Build task object with kind discriminator
      const task: A2ATask = {
        kind: 'task',  // REQUIRED discriminator
        id: data.taskMeta?.taskId || data.messageId || randomUUID(),
        contextId: data.threadId || randomUUID(),
        status: taskStatus,
      };
      
      // Add artifacts if present (with proper Part format)
      if (data.taskMeta?.artifacts && data.taskMeta.artifacts.length > 0) {
        task.artifacts = data.taskMeta.artifacts.map(artifact => ({
          artifactId: artifact.artifactId,
          name: artifact.name,
          description: artifact.description,
          parts: (artifact.parts || []).map(convertPartToA2A),
          metadata: artifact.metadata,
        }));
      }
      
      // Add history with the incoming message
      task.history = [a2aMessage];
      
      // Add metadata
      if (data.metadata) {
        task.metadata = data.metadata;
      }
      
      // Return Task as result
      return {
        jsonrpc: '2.0',
        id: responseId,
        result: task,
      };
    }
    
    // Simple message (no task) - return Message as result
    return {
      jsonrpc: '2.0',
      id: responseId,
      result: a2aMessage,
    };
  }
  
  // Connection events - wrap as agent message
  const connectionMessage: A2AMessage = {
    kind: 'message',
    messageId: randomUUID(),
    contextId: randomUUID(),
    role: 'agent',
    parts: [{ 
      kind: 'text', 
      text: `Connection event: ${event}` 
    }],
    metadata: {
      eventType: event,
      originalData: data,
    },
  };
  
  return {
    jsonrpc: '2.0',
    id: responseId,
    result: connectionMessage,
  };
}

/**
 * Get event type string from A2A result for logging purposes
 */
function getResultType(payload: A2AStreamResponse): string {
  const result = payload.result;
  if ('kind' in result) {
    switch (result.kind) {
      case 'task': return 'task';
      case 'message': return 'message';
      case 'status-update': return 'status-update';
      case 'artifact-update': return 'artifact-update';
      default: return 'unknown';
    }
  }
  return 'unknown';
}

// ─── In-Memory Queue ─────────────────────────────────────────────────────

interface QueueItem {
  id: string;
  agentId: string;
  webhookUrl: string;
  webhookSecretEncrypted: string; // V2.1.3: Keep encrypted until delivery
  payload: WebhookPayload;
  attempts: number;
  nextRetryAt: number;   // epoch ms
  createdAt: number;
}

const queue: QueueItem[] = [];
let processorInterval: NodeJS.Timeout | null = null;
let isProcessing = false;

// ─── Public API: Enqueue ─────────────────────────────────────────────────

/**
 * Enqueue a webhook delivery for an agent.
 * Looks up agent's webhook URL + secret, creates delivery record, adds to queue.
 * V3: Automatically converts to A2A format.
 */
export async function enqueueWebhook(
  agentId: string,
  event: WebhookEventType,
  data: Record<string, unknown>
): Promise<void> {
  try {
    // Fetch agent's webhook config
    const [agent] = await db.select({
      id: agents.id,
      webhookUrl: agents.webhookUrl,
      webhookSecret: agents.webhookSecret,
    })
    .from(agents)
    .where(eq(agents.id, agentId))
    .limit(1);

    // Skip if agent has no webhook configured
    if (!agent?.webhookUrl || !agent?.webhookSecret) {
      return;
    }

    const deliveryId = randomUUID();
    
    // V3: Convert to A2A format
    const payload = convertToA2AFormat(event, data as LegacyWebhookData);

    // Persist delivery record
    await db.insert(webhookDeliveries).values({
      id: deliveryId,
      agentId,
      eventType: event,
      payload: payload as any,
      status: 'pending',
      attempts: 0,
      maxRetries: CONFIG.maxRetries,
    });

    // V2.2.2: Queue size limit — prevent OOM under heavy load
    if (queue.length >= CONFIG.maxQueueSize) {
      console.warn(`[Webhook] Queue full (${queue.length}/${CONFIG.maxQueueSize}), dropping delivery ${deliveryId}`);
      await db.update(webhookDeliveries)
        .set({ status: 'failed', lastError: 'Queue full — delivery dropped' })
        .where(eq(webhookDeliveries.id, deliveryId));
      return;
    }

    // V2.1.3: Store encrypted secret in queue — decrypted only at delivery time
    queue.push({
      id: deliveryId,
      agentId,
      webhookUrl: agent.webhookUrl,
      webhookSecretEncrypted: agent.webhookSecret,
      payload,
      attempts: 0,
      nextRetryAt: Date.now(),
      createdAt: Date.now(),
    });

    console.log(`[Webhook] Enqueued ${event} (A2A format) for agent ${agentId} (${deliveryId})`);
  } catch (err) {
    console.error(`[Webhook] Failed to enqueue for agent ${agentId}:`, err);
  }
}

/**
 * Convenience: enqueue webhook for multiple agents at once.
 */
export async function enqueueWebhookBatch(
  agentIds: string[],
  event: WebhookEventType,
  data: Record<string, unknown>
): Promise<void> {
  await Promise.allSettled(
    agentIds.map(id => enqueueWebhook(id, event, data))
  );
}

// ─── Processor: Deliver webhooks ─────────────────────────────────────────

async function processQueue(): Promise<void> {
  if (isProcessing || queue.length === 0) return;
  isProcessing = true;

  try {
    const now = Date.now();

    // Get items ready to process (nextRetryAt <= now)
    const ready = queue
      .filter(item => item.nextRetryAt <= now)
      .slice(0, CONFIG.processBatchSize);

    if (ready.length === 0) {
      isProcessing = false;
      return;
    }

    // Process concurrently
    await Promise.allSettled(
      ready.map(item => deliverWebhook(item))
    );
  } catch (err) {
    console.error('[Webhook] Processor error:', err);
  } finally {
    isProcessing = false;
  }
}

async function deliverWebhook(item: QueueItem): Promise<void> {
  const bodyStr = JSON.stringify(item.payload);
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = randomUUID();

  // V2.1.3: Decrypt webhook secret just-in-time for signing
  // V2.2.6: Handle decryption errors (key change, corrupted data)
  let secret: string;
  try {
    secret = decryptWebhookSecret(item.webhookSecretEncrypted);
  } catch (err) {
    removeFromQueue(item.id);
    await db.update(webhookDeliveries)
      .set({ status: 'failed', lastError: 'Failed to decrypt webhook secret (key may have changed)', lastAttemptAt: new Date() })
      .where(eq(webhookDeliveries.id, item.id));
    console.error(`[Webhook] Decryption failed for ${item.id}:`, err);
    return;
  }
  const signature = generateWebhookSignature(bodyStr, secret, timestamp);

  // V2.2.4: Re-validate URL at delivery time (defense-in-depth against TOCTOU SSRF)
  if (!isPublicUrl(item.webhookUrl)) {
    removeFromQueue(item.id);
    await db.update(webhookDeliveries)
      .set({ status: 'failed', lastError: 'Webhook URL failed SSRF re-validation at delivery time', lastAttemptAt: new Date() })
      .where(eq(webhookDeliveries.id, item.id));
    console.warn(`[Webhook] SSRF blocked at delivery: ${item.webhookUrl} (${item.id})`);
    return;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CONFIG.timeoutMs);
    
    const resultType = getResultType(item.payload);

    const response = await fetch(item.webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-NeuralPost-Signature': `sha256=${signature}`,
        'X-NeuralPost-Timestamp': String(timestamp),
        'X-NeuralPost-Nonce': nonce,
        'X-NeuralPost-ResultType': resultType,  // A2A result type for routing
        'X-NeuralPost-Delivery': item.id,
        'User-Agent': 'NeuralPost-Webhook/3.0.0',
      },
      body: bodyStr,
      signal: controller.signal,
      redirect: 'error',  // SECURITY: Don't follow redirects (SSRF via 302 to internal IPs)
    });

    clearTimeout(timeout);

    if (response.ok) {
      // Success — remove from queue, update DB
      removeFromQueue(item.id);
      await db.update(webhookDeliveries)
        .set({
          status: 'delivered',
          attempts: item.attempts + 1,
          lastAttemptAt: new Date(),
          responseStatus: response.status,
          deliveredAt: new Date(),
        })
        .where(eq(webhookDeliveries.id, item.id));

      console.log(`[Webhook] ✓ Delivered ${resultType} to ${item.webhookUrl} (${item.id})`);
    } else {
      // HTTP error — retry or fail
      await handleFailure(item, `HTTP ${response.status}: ${response.statusText}`);
    }
  } catch (err: any) {
    const errMsg = err.name === 'AbortError' 
      ? `Timeout after ${CONFIG.timeoutMs}ms` 
      : err.message || 'Unknown error';
    await handleFailure(item, errMsg);
  }
}

async function handleFailure(item: QueueItem, errorMsg: string): Promise<void> {
  item.attempts += 1;
  const resultType = getResultType(item.payload);

  if (item.attempts >= CONFIG.maxRetries) {
    // Max retries reached — mark as failed, remove from queue
    removeFromQueue(item.id);
    await db.update(webhookDeliveries)
      .set({
        status: 'failed',
        attempts: item.attempts,
        lastAttemptAt: new Date(),
        lastError: errorMsg,
      })
      .where(eq(webhookDeliveries.id, item.id));

    console.log(`[Webhook] ✗ Failed permanently: ${resultType} → ${item.webhookUrl} (${item.id}) — ${errorMsg}`);
  } else {
    // Schedule retry with exponential backoff
    const delay = Math.min(
      CONFIG.baseDelayMs * Math.pow(2, item.attempts - 1),
      CONFIG.maxDelayMs
    );
    item.nextRetryAt = Date.now() + delay;

    await db.update(webhookDeliveries)
      .set({
        status: 'retrying',
        attempts: item.attempts,
        lastAttemptAt: new Date(),
        lastError: errorMsg,
        nextRetryAt: new Date(item.nextRetryAt),
      })
      .where(eq(webhookDeliveries.id, item.id));

    console.log(`[Webhook] ↻ Retry ${item.attempts}/${CONFIG.maxRetries} in ${delay}ms: ${resultType} → ${item.webhookUrl} (${item.id})`);
  }
}

function removeFromQueue(id: string): void {
  const idx = queue.findIndex(item => item.id === id);
  if (idx !== -1) queue.splice(idx, 1);
}

// ─── Recovery: Load pending deliveries from DB on startup ────────────────

async function recoverPendingDeliveries(): Promise<void> {
  try {
    const pending = await db.select({
      delivery: webhookDeliveries,
      webhookUrl: agents.webhookUrl,
      webhookSecret: agents.webhookSecret,
    })
    .from(webhookDeliveries)
    .innerJoin(agents, eq(webhookDeliveries.agentId, agents.id))
    .where(
      inArray(webhookDeliveries.status, ['pending', 'retrying'])
    );

    for (const row of pending) {
      if (!row.webhookUrl || !row.webhookSecret) continue;

      // V2.1.3: Store encrypted secret — decrypted only at delivery time
      queue.push({
        id: row.delivery.id,
        agentId: row.delivery.agentId,
        webhookUrl: row.webhookUrl,
        webhookSecretEncrypted: row.webhookSecret,
        payload: row.delivery.payload as WebhookPayload,
        attempts: row.delivery.attempts,
        nextRetryAt: row.delivery.nextRetryAt 
          ? new Date(row.delivery.nextRetryAt).getTime() 
          : Date.now(),
        createdAt: row.delivery.createdAt 
          ? new Date(row.delivery.createdAt).getTime()
          : Date.now(),
      });
    }

    if (pending.length > 0) {
      console.log(`[Webhook] Recovered ${pending.length} pending deliveries from DB`);
    }
  } catch (err) {
    console.error('[Webhook] Recovery failed:', err);
  }
}

// ─── Cleanup: Purge old delivery logs ────────────────────────────────────

export async function purgeOldDeliveries(): Promise<number> {
  const cutoff = new Date(Date.now() - CONFIG.deliveryTtlDays * 24 * 60 * 60 * 1000);

  const result = await db.delete(webhookDeliveries)
    .where(and(
      inArray(webhookDeliveries.status, ['delivered', 'failed']),
      lt(webhookDeliveries.createdAt, cutoff)
    ))
    .returning({ id: webhookDeliveries.id });

  return result.length;
}

// ─── Stats ───────────────────────────────────────────────────────────────

export async function getWebhookStats() {
  // V2.2.12: Parallelize independent count queries
  const [[total], [delivered], [failed], [pending]] = await Promise.all([
    db.select({ count: sql<number>`count(*)::int` }).from(webhookDeliveries),
    db.select({ count: sql<number>`count(*)::int` })
      .from(webhookDeliveries).where(eq(webhookDeliveries.status, 'delivered')),
    db.select({ count: sql<number>`count(*)::int` })
      .from(webhookDeliveries).where(eq(webhookDeliveries.status, 'failed')),
    db.select({ count: sql<number>`count(*)::int` })
      .from(webhookDeliveries).where(inArray(webhookDeliveries.status, ['pending', 'retrying'])),
  ]);

  return {
    total: total.count,
    delivered: delivered.count,
    failed: failed.count,
    pending: pending.count,
    queueSize: queue.length,
  };
}

export async function getWebhookLogs(agentId?: string, limit: number = 50) {
  // V2.1.3: Restructured to avoid 'as any' type assertion
  if (agentId) {
    return db.select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.agentId, agentId))
      .orderBy(sql`${webhookDeliveries.createdAt} DESC`)
      .limit(limit);
  }

  return db.select()
    .from(webhookDeliveries)
    .orderBy(sql`${webhookDeliveries.createdAt} DESC`)
    .limit(limit);
}

// ─── Lifecycle: Start / Stop ─────────────────────────────────────────────

export async function startWebhookProcessor(): Promise<void> {
  // Recover any pending deliveries from DB
  await recoverPendingDeliveries();

  // Start processing loop
  processorInterval = setInterval(processQueue, CONFIG.processIntervalMs);
  console.log(`[Webhook] Processor started (interval: ${CONFIG.processIntervalMs}ms)`);
}

export function stopWebhookProcessor(): void {
  if (processorInterval) {
    clearInterval(processorInterval);
    processorInterval = null;
    console.log(`[Webhook] Processor stopped (${queue.length} items remaining in queue)`);
  }
}
