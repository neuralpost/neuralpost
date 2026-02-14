// ═══════════════════════════════════════════════════════════════════════════
// A2A PROTOCOL ROUTES
// Implements A2A Protocol v0.3 for agent interoperability
// https://a2a-protocol.org/latest/
// ═══════════════════════════════════════════════════════════════════════════

import { Hono } from 'hono';
import type { Context } from 'hono';
import { db } from '../db';
import { agents, messages, threads, threadParticipants, connections, messageRecipients } from '../db/schema';
import { eq, and, sql, or, desc, asc, inArray } from 'drizzle-orm';
import { verifyToken, sanitizeHtml, partsHaveFiles, isPublicUrl, verifyApiKey, getApiKeyPrefix, sanitizeParts } from '../utils';
import type { MessagePart } from '../utils';
import { enqueueWebhook } from '../services/webhook';
import {
  A2A_PROTOCOL_VERSION,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type A2ATask,
  type A2APart,
  type MessageSendParams,
  type TasksGetParams,
  type TasksCancelParams,
  JSON_RPC_ERRORS,
} from '../a2a/types';
import {
  agentToAgentCard,
  getPlatformAgentCard,
  a2aPartsToInternal,
  internalPartsToA2A,
  buildTaskResponse,
  extractTextFromA2AParts,
} from '../a2a/converters';

const a2aRoute = new Hono();

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS & LIMITS
// ═══════════════════════════════════════════════════════════════════════════

const LIMITS = {
  MAX_PARTS: 50,              // Maximum parts per message
  MAX_TEXT_LENGTH: 100_000,   // 100KB per text part
  MAX_DATA_SIZE: 1_000_000,   // 1MB per data part
  MAX_HISTORY_LENGTH: 100,    // Maximum history items
  MAX_MESSAGE_ID_LENGTH: 128, // messageId length limit
} as const;

// V2.2.12: Pre-compiled regex for hot-path validation (avoid re-creation per request)
const MESSAGE_ID_RE = /^[a-zA-Z0-9_-]+$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ═══════════════════════════════════════════════════════════════════════════
// LOGGING
// ═══════════════════════════════════════════════════════════════════════════

function logA2A(
  level: 'info' | 'warn' | 'error',
  method: string,
  message: string,
  meta?: Record<string, unknown>
): void {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level,
    component: 'A2A',
    method,
    message,
    ...meta,
  };
  
  if (level === 'error') {
    console.error(JSON.stringify(logEntry));
  } else if (level === 'warn') {
    console.warn(JSON.stringify(logEntry));
  } else {
    console.log(JSON.stringify(logEntry));
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function getBaseUrl(c: Context): string {
  const url = new URL(c.req.url);
  return `${url.protocol}//${url.host}`;
}

function jsonRpcSuccess<T>(c: Context, id: string | number | null, result: T): Response {
  const response: JsonRpcResponse<T> = {
    jsonrpc: '2.0',
    id,
    result,
  };
  return c.json(response);
}

function jsonRpcError(
  c: Context, 
  id: string | number | null, 
  code: number, 
  message: string,
  data?: unknown
): Response {
  const response: JsonRpcResponse = {
    jsonrpc: '2.0',
    id,
    error: { code, message, data },
  };
  
  // Log errors
  logA2A('warn', 'error', message, { code, id, data });
  
  return c.json(response);
}

/**
 * Extract and verify Bearer token (JWT or API key) from Authorization header
 */
async function getAuthenticatedAgent(c: Context): Promise<{ id: string; domain: string } | null> {
  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }

  const token = authHeader.slice(7);
  
  // Try JWT first
  const payload = verifyToken(token);
  if (payload) {
    // Verify agent is still active (JWT doesn't contain status)
    const [agent] = await db.select({ id: agents.id, status: agents.status, tokenInvalidBefore: agents.tokenInvalidBefore })
      .from(agents).where(eq(agents.id, payload.agentId)).limit(1);
    if (!agent || agent.status !== 'active') return null;
    // V2.2.6: Reject JWTs issued before key rotation
    if (agent.tokenInvalidBefore && payload.iat) {
      const invalidBefore = Math.floor(agent.tokenInvalidBefore.getTime() / 1000);
      if (payload.iat < invalidBefore) return null;
    }
    return { id: payload.agentId, domain: payload.domain };
  }

  // Try API key (sk_xxx format)
  if (token.startsWith('sk_')) {
    const prefix = getApiKeyPrefix(token);
    const [agent] = await db.select({
      id: agents.id,
      domain: agents.domain,
      apiKeyHash: agents.apiKeyHash,
      status: agents.status,
    })
    .from(agents)
    .where(eq(agents.apiKeyPrefix, prefix))
    .limit(1);

    if (agent && agent.status === 'active' && verifyApiKey(token, agent.apiKeyHash)) {
      return { id: agent.id, domain: agent.domain };
    }
  }

  return null;
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

interface ValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Validate messageId format (prevent injection attacks)
 */
function isValidMessageId(messageId: unknown): boolean {
  if (typeof messageId !== 'string') return false;
  if (messageId.length === 0 || messageId.length > LIMITS.MAX_MESSAGE_ID_LENGTH) return false;
  // Allow alphanumeric, hyphens, underscores only
  return MESSAGE_ID_RE.test(messageId);
}

/**
 * Validate UUID format
 */
function isValidUUID(id: unknown): boolean {
  if (typeof id !== 'string') return false;
  return UUID_RE.test(id);
}

/**
 * Validate A2A part
 */
function validatePart(part: unknown, index: number): ValidationResult {
  if (!part || typeof part !== 'object') {
    return { valid: false, error: `parts[${index}] must be an object` };
  }

  const p = part as Record<string, unknown>;
  
  if (!p.kind || !['text', 'data', 'file'].includes(p.kind as string)) {
    return { valid: false, error: `parts[${index}].kind must be 'text', 'data', or 'file'` };
  }

  if (p.kind === 'text') {
    if (typeof p.text !== 'string') {
      return { valid: false, error: `parts[${index}].text must be a string` };
    }
    if (p.text.length > LIMITS.MAX_TEXT_LENGTH) {
      return { valid: false, error: `parts[${index}].text exceeds ${LIMITS.MAX_TEXT_LENGTH} characters` };
    }
  }

  if (p.kind === 'data') {
    // V2.2.9: Check data field exists before stringify (prevents TypeError on undefined)
    if (p.data === undefined) {
      return { valid: false, error: `parts[${index}].data is required` };
    }
    const dataStr = JSON.stringify(p.data);
    if (dataStr.length > LIMITS.MAX_DATA_SIZE) {
      return { valid: false, error: `parts[${index}].data exceeds ${LIMITS.MAX_DATA_SIZE} bytes` };
    }
  }

  if (p.kind === 'file') {
    // V2.2.9: Reject arrays (typeof [] === 'object')
    if (!p.file || typeof p.file !== 'object' || Array.isArray(p.file)) {
      return { valid: false, error: `parts[${index}].file must be an object` };
    }
    const file = p.file as Record<string, unknown>;
    // V0.3: File can be FileWithUri (has uri) OR FileWithBytes (has bytes)
    const hasUri = file.uri && typeof file.uri === 'string';
    const hasBytes = file.bytes && typeof file.bytes === 'string';
    if (!hasUri && !hasBytes) {
      return { valid: false, error: `parts[${index}].file must have either 'uri' (string) or 'bytes' (base64 string)` };
    }
  }

  return { valid: true };
}

/**
 * Comprehensive validation for message/send params
 */
function validateMessageParams(params: unknown): ValidationResult {
  if (!params || typeof params !== 'object') {
    return { valid: false, error: 'params must be an object' };
  }

  const p = params as Record<string, unknown>;
  
  if (!p.message || typeof p.message !== 'object') {
    return { valid: false, error: 'params.message is required' };
  }

  const message = p.message as Record<string, unknown>;

  // V0.3: Validate role (incoming messages must be from 'user')
  if (message.role !== undefined && message.role !== 'user') {
    return { valid: false, error: "params.message.role must be 'user' for incoming messages" };
  }
  
  // Validate parts array
  if (!message.parts || !Array.isArray(message.parts)) {
    return { valid: false, error: 'params.message.parts must be an array' };
  }
  
  if (message.parts.length === 0) {
    return { valid: false, error: 'params.message.parts cannot be empty' };
  }
  
  if (message.parts.length > LIMITS.MAX_PARTS) {
    return { valid: false, error: `params.message.parts exceeds limit of ${LIMITS.MAX_PARTS}` };
  }

  // Validate messageId
  if (!isValidMessageId(message.messageId)) {
    return { 
      valid: false, 
      error: 'params.message.messageId must be alphanumeric string (max 128 chars)' 
    };
  }

  // Validate contextId if provided
  if (message.contextId !== undefined && !isValidUUID(message.contextId)) {
    return { valid: false, error: 'params.message.contextId must be a valid UUID' };
  }

  // Validate each part
  for (let i = 0; i < message.parts.length; i++) {
    const partValidation = validatePart(message.parts[i], i);
    if (!partValidation.valid) {
      return partValidation;
    }
  }

  return { valid: true };
}

/**
 * Validate tasks/get params
 */
function validateTasksGetParams(params: unknown): ValidationResult {
  if (!params || typeof params !== 'object') {
    return { valid: false, error: 'params must be an object' };
  }

  const p = params as Record<string, unknown>;
  
  if (!p.id || !isValidUUID(p.id)) {
    return { valid: false, error: 'params.id must be a valid UUID' };
  }

  if (p.historyLength !== undefined) {
    if (typeof p.historyLength !== 'number' || p.historyLength < 0) {
      return { valid: false, error: 'params.historyLength must be a non-negative number' };
    }
    if (p.historyLength > LIMITS.MAX_HISTORY_LENGTH) {
      return { valid: false, error: `params.historyLength exceeds limit of ${LIMITS.MAX_HISTORY_LENGTH}` };
    }
  }

  return { valid: true };
}

/**
 * Validate tasks/cancel params
 */
function validateTasksCancelParams(params: unknown): ValidationResult {
  if (!params || typeof params !== 'object') {
    return { valid: false, error: 'params must be an object' };
  }

  const p = params as Record<string, unknown>;
  
  if (!p.id || !isValidUUID(p.id)) {
    return { valid: false, error: 'params.id must be a valid UUID' };
  }

  return { valid: true };
}

// ═══════════════════════════════════════════════════════════════════════════
// AGENT CARD ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * GET /a2a/.well-known/agent-card.json
 * Platform-level Agent Card (also accessible at root /.well-known/agent-card.json)
 * V0.3: Path changed from agent.json to agent-card.json per RFC 8615
 */
a2aRoute.get('/.well-known/agent-card.json', (c) => {
  const baseUrl = getBaseUrl(c);
  const card = getPlatformAgentCard(baseUrl);
  
  logA2A('info', 'getAgentCard', 'Platform Agent Card requested', { baseUrl });
  
  return c.json(card);
});

/**
 * GET /a2a/:agentId/.well-known/agent-card.json
 * Per-agent Agent Card
 */
a2aRoute.get('/:agentId/.well-known/agent-card.json', async (c) => {
  const agentId = c.req.param('agentId');
  const baseUrl = getBaseUrl(c);

  // Validate agentId format
  if (!isValidUUID(agentId)) {
    return c.json({ error: 'Invalid agent ID format' }, 400);
  }

  try {
    const [agent] = await db.select({
      id: agents.id,
      domain: agents.domain,
      displayName: agents.displayName,
      bio: agents.bio,
      profile: agents.profile,
      webhookUrl: agents.webhookUrl,
      status: agents.status,
      walletAddress: agents.walletAddress,
      x402Enabled: agents.x402Enabled,
      messagePrice: agents.messagePrice,
    })
    .from(agents)
    .where(eq(agents.id, agentId))
    .limit(1);

    if (!agent) {
      logA2A('warn', 'getAgentCard', 'Agent not found', { agentId });
      return c.json({ error: 'Agent not found' }, 404);
    }

    if (agent.status !== 'active') {
      // V2.2.6: Return 404 instead of 403 to avoid revealing agent existence
      logA2A('warn', 'getAgentCard', 'Agent not active', { agentId, status: agent.status });
      return c.json({ error: 'Agent not found' }, 404);
    }

    const card = agentToAgentCard(agent, baseUrl);
    
    logA2A('info', 'getAgentCard', 'Agent Card retrieved', { agentId, domain: agent.domain });
    
    return c.json(card);
  } catch (err) {
    logA2A('error', 'getAgentCard', 'Database error', { agentId, error: String(err) });
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Backward-compatible aliases for old /.well-known/agent.json path
a2aRoute.get('/.well-known/agent.json', (c) => {
  const baseUrl = getBaseUrl(c);
  return c.json(getPlatformAgentCard(baseUrl));
});
a2aRoute.get('/:agentId/.well-known/agent.json', async (c) => {
  // Redirect to new canonical path
  const agentId = c.req.param('agentId');
  const url = new URL(c.req.url);
  return c.redirect(`${url.pathname.replace('/agent.json', '/agent-card.json')}`, 301);
});

// ═══════════════════════════════════════════════════════════════════════════
// JSON-RPC ENDPOINT
// POST /a2a/:agentId — Main A2A communication endpoint
// ═══════════════════════════════════════════════════════════════════════════

a2aRoute.post('/:agentId', async (c) => {
  const targetAgentId = c.req.param('agentId');

  // V2.2.8: Body size limit — reject payloads > 2MB to prevent OOM
  const contentLength = parseInt(c.req.header('Content-Length') || '0', 10);
  if (contentLength > 2 * 1024 * 1024) {
    return c.json({
      jsonrpc: '2.0',
      id: null,
      error: {
        code: JSON_RPC_ERRORS.INVALID_REQUEST,
        message: 'Request body too large (max 2MB)',
      },
    }, 413);
  }
  
  // Validate Content-Type
  const contentType = c.req.header('Content-Type');
  if (!contentType?.includes('application/json')) {
    return c.json({
      jsonrpc: '2.0',
      id: null,
      error: {
        code: JSON_RPC_ERRORS.CONTENT_TYPE_NOT_SUPPORTED,
        message: 'Content-Type must be application/json',
      },
    }, 415);
  }

  // Validate agentId format
  if (!isValidUUID(targetAgentId)) {
    return c.json({
      jsonrpc: '2.0',
      id: null,
      error: {
        code: JSON_RPC_ERRORS.INVALID_REQUEST,
        message: 'Invalid agent ID format',
      },
    }, 400);
  }
  
  // Parse JSON-RPC request
  let rpc: JsonRpcRequest;
  try {
    rpc = await c.req.json();
  } catch {
    return jsonRpcError(c, null, JSON_RPC_ERRORS.PARSE_ERROR, 'Parse error: Invalid JSON');
  }

  // Validate JSON-RPC structure
  if (rpc.jsonrpc !== '2.0') {
    return jsonRpcError(c, rpc?.id ?? null, JSON_RPC_ERRORS.INVALID_REQUEST, 'jsonrpc must be "2.0"');
  }
  
  if (!rpc.method || typeof rpc.method !== 'string') {
    return jsonRpcError(c, rpc?.id ?? null, JSON_RPC_ERRORS.INVALID_REQUEST, 'method is required');
  }

  // V2.2.6: Validate rpc.method length (prevent log/memory abuse)
  if (rpc.method.length > 128) {
    return jsonRpcError(c, null, JSON_RPC_ERRORS.INVALID_REQUEST, 'method name too long (max 128 chars)');
  }
  
  if (rpc.id === undefined) {
    return jsonRpcError(c, null, JSON_RPC_ERRORS.INVALID_REQUEST, 'id is required');
  }

  // V2.2.6: Validate rpc.id type and size (JSON-RPC 2.0: string, number, or null)
  if (typeof rpc.id === 'string' && rpc.id.length > 256) {
    return jsonRpcError(c, null, JSON_RPC_ERRORS.INVALID_REQUEST, 'id too long (max 256 chars)');
  }
  if (typeof rpc.id !== 'string' && typeof rpc.id !== 'number' && rpc.id !== null) {
    return jsonRpcError(c, null, JSON_RPC_ERRORS.INVALID_REQUEST, 'id must be a string, number, or null');
  }

  // Authenticate caller
  const caller = await getAuthenticatedAgent(c);
  if (!caller) {
    // V0.3 §4.4: SHOULD use HTTP 401 with WWW-Authenticate header
    c.header('WWW-Authenticate', 'Bearer');
    return c.json({
      jsonrpc: '2.0',
      id: rpc.id,
      error: {
        code: JSON_RPC_ERRORS.INVALID_REQUEST,
        message: 'Authentication required (Bearer token)',
      },
    }, 401);
  }

  logA2A('info', rpc.method, 'Request received', { 
    callerId: caller.id, 
    targetAgentId,
    rpcId: rpc.id,
  });

  // Verify target agent exists
  let targetAgent: { id: string; domain: string; status: string; webhookUrl: string | null };
  try {
    const [agent] = await db.select({
      id: agents.id,
      domain: agents.domain,
      status: agents.status,
      webhookUrl: agents.webhookUrl,
    })
    .from(agents)
    .where(eq(agents.id, targetAgentId))
    .limit(1);

    if (!agent) {
      return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.TASK_NOT_FOUND, 'Target agent not found');
    }
    
    if (agent.status !== 'active') {
      // V2.2.6: Same error as not-found to avoid revealing agent existence
      return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.TASK_NOT_FOUND, 'Target agent not found');
    }
    
    // At this point, status is guaranteed to be 'active' (not null)
    targetAgent = {
      id: agent.id,
      domain: agent.domain,
      status: agent.status, // guaranteed to be 'active' after check above
      webhookUrl: agent.webhookUrl,
    };
  } catch (err) {
    logA2A('error', rpc.method, 'Database error fetching target agent', { error: String(err) });
    return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error');
  }

  // Prevent self-messaging via A2A
  if (caller.id === targetAgent.id) {
    return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.INVALID_PARAMS, 'Cannot send messages to yourself');
  }

  // Route to method handler
  switch (rpc.method) {
    case 'message/send':
      return handleMessageSend(c, rpc, caller, targetAgent);
    
    case 'tasks/get':
      return handleTasksGet(c, rpc, caller);
    
    case 'tasks/cancel':
      return handleTasksCancel(c, rpc, caller);
    
    case 'tasks/list':
      return handleTasksList(c, rpc, caller, targetAgent);
    
    default:
      return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.METHOD_NOT_FOUND, `Method not found: ${rpc.method}`);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// METHOD HANDLERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Handle message/send — Send a message to target agent
 */
async function handleMessageSend(
  c: Context,
  rpc: JsonRpcRequest,
  caller: { id: string; domain: string },
  target: { id: string; domain: string; webhookUrl: string | null }
): Promise<Response> {
  // Validate params
  const validation = validateMessageParams(rpc.params);
  if (!validation.valid) {
    return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.INVALID_PARAMS, validation.error!);
  }

  const params = rpc.params as MessageSendParams;
  const { message } = params;

  try {
    // V2.2.10: Validate message-level metadata size (matches v1 API 10KB limit)
    if (message.metadata) {
      const metaSize = JSON.stringify(message.metadata).length;
      if (metaSize > 10_000) {
        return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.INVALID_PARAMS, 'message.metadata must be under 10KB when serialized');
      }
    }
    // Check connection status (NeuralPost requires accepted connection)
    const [connection] = await db.select({ status: connections.status })
      .from(connections)
      .where(and(
        eq(connections.status, 'accepted'),
        or(
          and(eq(connections.requesterId, caller.id), eq(connections.targetId, target.id)),
          and(eq(connections.requesterId, target.id), eq(connections.targetId, caller.id))
        )
      ))
      .limit(1);

    if (!connection) {
      return jsonRpcError(
        c, 
        rpc.id, 
        JSON_RPC_ERRORS.INVALID_REQUEST, 
        `Not connected with ${target.domain}. Connection request required first.`
      );
    }

    // Convert A2A parts to internal format
    const internalParts = a2aPartsToInternal(message.parts);

    // V2.2.8: Sanitize parts for XSS defense-in-depth (matches internal message API)
    const sanitizedInternalParts = sanitizeParts(internalParts);

    // Validate file URLs (anti-SSRF) — skip data: URIs (inline base64 from FileWithBytes)
    for (const part of internalParts) {
      if (part.kind === 'file') {
        const filePart = part as { kind: 'file'; url: string };
        if (filePart.url && !filePart.url.startsWith('data:') && !isPublicUrl(filePart.url)) {
          return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.INVALID_PARAMS, 'File URL targets private network');
        }
      }
    }

    // Extract text for body/search
    const textBody = extractTextFromA2AParts(message.parts);
    const sanitizedBody = sanitizeHtml(textBody || '[A2A message]');

    const now = new Date();
    let threadId: string;

    // Use existing context or create new thread
    if (message.contextId) {
      // Verify caller is active participant in this thread (not soft-deleted)
      const [participant] = await db.select({ id: threadParticipants.id })
        .from(threadParticipants)
        .where(and(
          eq(threadParticipants.threadId, message.contextId),
          eq(threadParticipants.agentId, caller.id),
          eq(threadParticipants.isDeleted, false)
        ))
        .limit(1);

      if (!participant) {
        return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.INVALID_PARAMS, 'Invalid contextId or not a participant');
      }

      // V2.2.9: Also verify target hasn't soft-deleted their participation
      const [targetParticipant] = await db.select({ id: threadParticipants.id })
        .from(threadParticipants)
        .where(and(
          eq(threadParticipants.threadId, message.contextId),
          eq(threadParticipants.agentId, target.id),
          eq(threadParticipants.isDeleted, false)
        ))
        .limit(1);

      if (!targetParticipant) {
        return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.INVALID_PARAMS, 'Target agent is no longer a participant in this thread');
      }

      threadId = message.contextId;
      
      // Update thread
      await db.update(threads)
        .set({ 
          messageCount: sql`${threads.messageCount} + 1`,
          updatedAt: now,
        })
        .where(eq(threads.id, threadId));
    } else {
      // V2.2.13: Reuse existing private thread if one exists
      let existingPrivateThread: string | null = null;
      const callerThreads = await db.select({ threadId: threadParticipants.threadId })
        .from(threadParticipants)
        .where(and(
          eq(threadParticipants.agentId, caller.id),
          eq(threadParticipants.isDeleted, false)
        ));
      const callerThreadIds = callerThreads.map(t => t.threadId);
      
      if (callerThreadIds.length > 0) {
        const sharedThreads = await db.select({ threadId: threadParticipants.threadId })
          .from(threadParticipants)
          .where(and(
            eq(threadParticipants.agentId, target.id),
            eq(threadParticipants.isDeleted, false),
            inArray(threadParticipants.threadId, callerThreadIds)
          ));
        
        for (const st of sharedThreads) {
          const [countResult] = await db.select({ count: sql<number>`count(*)::int` })
            .from(threadParticipants)
            .where(and(
              eq(threadParticipants.threadId, st.threadId),
              eq(threadParticipants.isDeleted, false)
            ));
          if (countResult && countResult.count === 2) {
            existingPrivateThread = st.threadId;
            break;
          }
        }
      }

      if (existingPrivateThread) {
        threadId = existingPrivateThread;
        await db.update(threads)
          .set({ messageCount: sql`${threads.messageCount} + 1`, updatedAt: now })
          .where(eq(threads.id, threadId));
      } else {
        // Create new thread
        const [newThread] = await db.insert(threads).values({
          subject: textBody?.slice(0, 100) || 'A2A Conversation',
          messageCount: 1,
          updatedAt: now,
        }).returning();
        threadId = newThread.id;

        // Add both agents as participants
        await db.insert(threadParticipants).values([
          { threadId, agentId: caller.id },
          { threadId, agentId: target.id },
        ]);
      }
    }

    // Create message
    // Only set taskMeta if the incoming message has task-related fields
    const hasTaskContext = message.taskId || (params as any).configuration?.blocking;
    const [newMessage] = await db.insert(messages).values({
      threadId,
      senderId: caller.id,
      type: 'message',
      parts: sanitizedInternalParts,
      body: sanitizedBody,
      bodyHtml: sanitizedBody,
      hasAttachments: partsHaveFiles(sanitizedInternalParts),
      taskMeta: hasTaskContext ? { status: 'submitted' } : null,
      metadata: (message as any).metadata || null,
    }).returning();

    // Create recipient record
    await db.insert(messageRecipients).values({
      messageId: newMessage.id,
      recipientId: target.id,
      status: 'sent',
    });

    // V2.2.13: Sender inbox record
    await db.insert(messageRecipients).values({
      messageId: newMessage.id,
      recipientId: caller.id,
      status: 'sent',
      folder: 'inbox',
      readAt: now,
    }).onConflictDoNothing();

    // Trigger webhook if target has one
    if (target.webhookUrl) {
      enqueueWebhook(target.id, 'message.received', {
        messageId: newMessage.id,
        threadId,
        type: newMessage.type,
        senderId: caller.id,
        senderDomain: caller.domain,
        parts: sanitizedInternalParts,
        body: sanitizedBody,
        taskMeta: newMessage.taskMeta,
        createdAt: newMessage.createdAt,
        a2a: true,
      }).catch(err => logA2A('error', 'message/send', 'Webhook enqueue error', { error: String(err) }));
    }

    logA2A('info', 'message/send', 'Message sent successfully', {
      messageId: newMessage.id,
      threadId,
      callerId: caller.id,
      targetId: target.id,
    });

    // Build A2A Task response
    // V0.3: If configuration.historyLength is set, include thread history in response
    let history: import('../a2a/types').A2AMessage[] = [{
      role: 'user',
      kind: 'message' as const,
      parts: message.parts,
      messageId: message.messageId,
      contextId: threadId,
      taskId: newMessage.id,
    }];

    const requestedHistoryLength = params.configuration?.historyLength;
    if (requestedHistoryLength && requestedHistoryLength > 0 && message.contextId) {
      // Fetch previous messages from thread (up to requested length)
      const historyMessages = await db.select({
        id: messages.id,
        senderId: messages.senderId,
        parts: messages.parts,
        createdAt: messages.createdAt,
      })
      .from(messages)
      .where(eq(messages.threadId, threadId))
      .orderBy(asc(messages.createdAt))
      .limit(Math.min(requestedHistoryLength, LIMITS.MAX_HISTORY_LENGTH));

      history = historyMessages.map(m => ({
        role: m.senderId === caller.id ? 'user' as const : 'agent' as const,
        kind: 'message' as const,
        parts: internalPartsToA2A((m.parts || []) as MessagePart[]),
        messageId: m.id,
        contextId: threadId,
        taskId: m.id,
      }));
    }

    const task = buildTaskResponse(
      newMessage.id,
      threadId,
      [],
      'submitted',
      history
    );

    return jsonRpcSuccess(c, rpc.id, task);
  } catch (err) {
    logA2A('error', 'message/send', 'Database error', { error: String(err) });
    return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error');
  }
}

/**
 * Handle tasks/get — Get task status
 */
async function handleTasksGet(
  c: Context,
  rpc: JsonRpcRequest,
  caller: { id: string; domain: string }
): Promise<Response> {
  // Validate params
  const validation = validateTasksGetParams(rpc.params);
  if (!validation.valid) {
    return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.INVALID_PARAMS, validation.error!);
  }

  const params = rpc.params as TasksGetParams;

  try {
    // In NeuralPost, taskId = messageId
    const [message] = await db.select({
      id: messages.id,
      threadId: messages.threadId,
      senderId: messages.senderId,
      parts: messages.parts,
      body: messages.body,
      type: messages.type,
      taskMeta: messages.taskMeta,
      createdAt: messages.createdAt,
    })
    .from(messages)
    .where(eq(messages.id, params.id))
    .limit(1);

    if (!message) {
      return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.TASK_NOT_FOUND, 'Task not found');
    }

    // Verify caller has access to this thread (and not soft-deleted)
    const [participant] = await db.select({ id: threadParticipants.id })
      .from(threadParticipants)
      .where(and(
        eq(threadParticipants.threadId, message.threadId),
        eq(threadParticipants.agentId, caller.id),
        eq(threadParticipants.isDeleted, false)
      ))
      .limit(1);

    if (!participant) {
      return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.TASK_NOT_FOUND, 'Task not found');
    }

    // Determine task status based on taskMeta (A2A Protocol v0.3 states)
    type TaskStatusType = 'submitted' | 'working' | 'completed' | 'failed' | 'canceled' | 'input-required' | 'rejected' | 'auth-required' | 'unknown';
    let status: TaskStatusType = 'completed';
    
    const taskMeta = message.taskMeta as { status?: string } | null;
    if (taskMeta?.status) {
      switch (taskMeta.status) {
        case 'pending': 
        case 'submitted': status = 'submitted'; break;
        case 'working': status = 'working'; break;
        case 'completed': status = 'completed'; break;
        case 'failed': status = 'failed'; break;
        case 'cancelled': 
        case 'canceled': status = 'canceled'; break;
        case 'input_required':
        case 'input-required': status = 'input-required'; break;
        case 'rejected': status = 'rejected'; break;
        case 'auth_required':
        case 'auth-required': status = 'auth-required'; break;
        case 'unknown': status = 'unknown'; break;
      }
    }

    const messageParts = (message.parts || []) as MessagePart[];
    
    const task: A2ATask = {
      kind: 'task' as const,
      id: message.id,
      contextId: message.threadId,
      status: {
        state: status,
        timestamp: message.createdAt?.toISOString() || new Date().toISOString(),
      },
      artifacts: messageParts.length > 0 ? [{
        artifactId: `${message.id}_artifact`,
        name: 'message',
        parts: internalPartsToA2A(messageParts),
      }] : undefined,
    };

    // Optionally include history (sorted chronologically - oldest first)
    if (params.historyLength && params.historyLength > 0) {
      const historyMessages = await db.select({
        id: messages.id,
        senderId: messages.senderId,
        parts: messages.parts,
        createdAt: messages.createdAt,
      })
      .from(messages)
      .where(eq(messages.threadId, message.threadId))
      .orderBy(asc(messages.createdAt))  // ✅ FIXED: Chronological order (oldest first)
      .limit(params.historyLength);

      task.history = historyMessages.map(m => ({
        role: m.senderId === caller.id ? 'user' as const : 'agent' as const,
        kind: 'message' as const,
        parts: internalPartsToA2A((m.parts || []) as MessagePart[]),
        messageId: m.id,
        contextId: message.threadId,
        taskId: m.id,
      }));
    }

    logA2A('info', 'tasks/get', 'Task retrieved', { taskId: params.id, status });

    return jsonRpcSuccess(c, rpc.id, task);
  } catch (err) {
    logA2A('error', 'tasks/get', 'Database error', { error: String(err) });
    return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error');
  }
}

/**
 * Handle tasks/cancel — Cancel a running task
 */
async function handleTasksCancel(
  c: Context,
  rpc: JsonRpcRequest,
  caller: { id: string; domain: string }
): Promise<Response> {
  // Validate params
  const validation = validateTasksCancelParams(rpc.params);
  if (!validation.valid) {
    return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.INVALID_PARAMS, validation.error!);
  }

  const params = rpc.params as TasksCancelParams;

  try {
    // Find the message/task
    const [message] = await db.select({
      id: messages.id,
      threadId: messages.threadId,
      senderId: messages.senderId,
      taskMeta: messages.taskMeta,
    })
    .from(messages)
    .where(eq(messages.id, params.id))
    .limit(1);

    if (!message) {
      return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.TASK_NOT_FOUND, 'Task not found');
    }

    // Verify caller has access (and not soft-deleted)
    const [participant] = await db.select({ id: threadParticipants.id })
      .from(threadParticipants)
      .where(and(
        eq(threadParticipants.threadId, message.threadId),
        eq(threadParticipants.agentId, caller.id),
        eq(threadParticipants.isDeleted, false)
      ))
      .limit(1);

    if (!participant) {
      return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.TASK_NOT_FOUND, 'Task not found');
    }

    // Check if task is cancelable (terminal states cannot be canceled)
    const taskMeta = (message.taskMeta || {}) as { status?: string };
    const currentStatus = taskMeta.status || 'completed';
    const terminalStates = ['completed', 'failed', 'canceled', 'cancelled', 'rejected', 'unknown'];
    
    if (terminalStates.includes(currentStatus)) {
      return jsonRpcError(
        c, 
        rpc.id, 
        JSON_RPC_ERRORS.TASK_NOT_CANCELABLE, 
        `Task is already ${currentStatus} and cannot be canceled`
      );
    }

    // Update task status to canceled (A2A spec uses 'canceled' with one 'l')
    await db.update(messages)
      .set({
        taskMeta: { ...taskMeta, status: 'canceled' },
      })
      .where(eq(messages.id, params.id));

    logA2A('info', 'tasks/cancel', 'Task canceled', { taskId: params.id });

    // Return updated task
    const task: A2ATask = {
      kind: 'task' as const,
      id: message.id,
      contextId: message.threadId,
      status: {
        state: 'canceled',
        timestamp: new Date().toISOString(),
      },
    };

    return jsonRpcSuccess(c, rpc.id, task);
  } catch (err) {
    logA2A('error', 'tasks/cancel', 'Database error', { error: String(err) });
    return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error');
  }
}

/**
 * Handle tasks/list — List tasks for a context
 */
async function handleTasksList(
  c: Context,
  rpc: JsonRpcRequest,
  caller: { id: string; domain: string },
  _target: { id: string; domain: string; webhookUrl: string | null }
): Promise<Response> {
  const params = rpc.params as { contextId?: string; limit?: number; offset?: number } | undefined;

  // Validate contextId if provided
  if (params?.contextId && !isValidUUID(params.contextId)) {
    return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.INVALID_PARAMS, 'params.contextId must be a valid UUID');
  }

  // Validate limit
  const limit = Math.min(params?.limit || 20, 100);
  const offset = Math.min(Math.max(params?.offset || 0, 0), 10000);

  try {
    // Find threads where caller is active participant (not soft-deleted)
    const participantThreads = await db.select({ threadId: threadParticipants.threadId })
      .from(threadParticipants)
      .where(and(
        eq(threadParticipants.agentId, caller.id),
        eq(threadParticipants.isDeleted, false)
      ));

    const threadIds = participantThreads.map(t => t.threadId);

    if (threadIds.length === 0) {
      return jsonRpcSuccess(c, rpc.id, { tasks: [] });
    }

    // Filter by contextId if provided
    let filteredThreadIds = threadIds;
    if (params?.contextId) {
      if (!threadIds.includes(params.contextId)) {
        return jsonRpcSuccess(c, rpc.id, { tasks: [] });
      }
      filteredThreadIds = [params.contextId];
    }

    // Query messages
    const taskMessages = await db.select({
      id: messages.id,
      threadId: messages.threadId,
      taskMeta: messages.taskMeta,
      createdAt: messages.createdAt,
    })
    .from(messages)
    .where(inArray(messages.threadId, filteredThreadIds))
    .orderBy(desc(messages.createdAt))
    .limit(limit)
    .offset(offset);

    const tasks = taskMessages.map(m => {
      const taskMeta = (m.taskMeta || {}) as { status?: string };
      type TaskStatusType = 'submitted' | 'working' | 'completed' | 'failed' | 'canceled' | 'input-required' | 'rejected' | 'auth-required' | 'unknown';
      let status: TaskStatusType = 'completed';
      
      if (taskMeta.status) {
        switch (taskMeta.status) {
          case 'pending':
          case 'submitted': status = 'submitted'; break;
          case 'working': status = 'working'; break;
          case 'completed': status = 'completed'; break;
          case 'failed': status = 'failed'; break;
          case 'cancelled': 
          case 'canceled': status = 'canceled'; break;
          case 'input_required':
          case 'input-required': status = 'input-required'; break;
          case 'rejected': status = 'rejected'; break;
          case 'auth_required':
          case 'auth-required': status = 'auth-required'; break;
          case 'unknown': status = 'unknown'; break;
        }
      }

      return {
        kind: 'task' as const,
        id: m.id,
        contextId: m.threadId,
        status: {
          state: status,
          timestamp: m.createdAt?.toISOString() || new Date().toISOString(),
        },
      };
    });

    logA2A('info', 'tasks/list', 'Tasks listed', { count: tasks.length, callerId: caller.id });

    return jsonRpcSuccess(c, rpc.id, { tasks });
  } catch (err) {
    logA2A('error', 'tasks/list', 'Database error', { error: String(err) });
    return jsonRpcError(c, rpc.id, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error');
  }
}

export default a2aRoute;
