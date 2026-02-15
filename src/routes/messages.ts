import { Hono } from 'hono';
import { z } from 'zod';
import { db } from '../db';
import { agents, messages, messageRecipients, threads, threadParticipants, connections } from '../db/schema';
import { eq, and, desc, inArray, sql, or } from 'drizzle-orm';
import { authMiddleware } from '../middleware/auth';
import { 
  apiResponse, 
  apiError, 
  parsePagination, 
  paginatedResponse,
  generatePreview,
  sanitizeHtml,
  isValidUuid,
  normalizeParts,
  extractTextFromParts,
  partsHaveFiles,
  validatePart,
  sanitizeParts,
  isValidUrl,
  isPublicUrl,
} from '../utils';
import { enqueueWebhookBatch } from '../services/webhook';
import { x402DynamicMiddleware } from '../middleware/x402-sdk';

const messagesRoute = new Hono();

// Apply auth middleware
messagesRoute.use('/*', authMiddleware);

// x402 payment gate — runs after auth, before message handlers
// Uses official @x402/hono SDK for verify/settle via facilitator
// Per x402 V2: returns 402 Payment Required if receiver requires payment
// and PAYMENT-SIGNATURE header is missing/invalid
messagesRoute.use('/*', x402DynamicMiddleware);

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION SCHEMAS
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// A2A TASK STATUS STATES (aligned with A2A Protocol Spec v0.3)
// ═══════════════════════════════════════════════════════════════════════════
const A2A_TASK_STATES = [
  'submitted',       // Task created, waiting to be processed
  'working',         // Task is actively being processed
  'completed',       // Task finished successfully (terminal)
  'failed',          // Task failed (terminal)
  'canceled',        // Task was canceled (terminal)
  'input_required',  // Task needs additional input from client (interrupted)
  'rejected',        // Agent declined to perform task (terminal)
  'auth_required',   // Authentication needed (interrupted)
] as const;

// ═══════════════════════════════════════════════════════════════════════════
// A2A ARTIFACT SCHEMA
// ═══════════════════════════════════════════════════════════════════════════
const artifactSchema = z.object({
  artifactId: z.string().max(128),
  name: z.string().max(255).optional(),
  description: z.string().max(2000).optional(),
  parts: z.array(z.object({
    kind: z.enum(['text', 'data', 'file']),
    // V2.2.10: Size limit on part content to prevent storage abuse
    content: z.any().optional().refine(
      (val) => !val || JSON.stringify(val).length <= 50_000,
      { message: 'Artifact part content must be under 50KB when serialized' }
    ),
    content_type: z.string().max(255).optional(),
    url: z.string().max(2048).optional(),
    mime: z.string().max(255).optional(),
    name: z.string().max(500).optional(),
    size: z.number().optional(),
    // V2.2.10: Size limit on part metadata
    metadata: z.record(z.any()).optional().refine(
      (val) => !val || JSON.stringify(val).length <= 5_000,
      { message: 'Artifact part metadata must be under 5KB' }
    ),
  })).min(1).max(50),
  // V2.2.10: Size limit on artifact-level metadata
  metadata: z.record(z.any()).optional().refine(
    (val) => !val || JSON.stringify(val).length <= 10_000,
    { message: 'Artifact metadata must be under 10KB' }
  ),
});

const sendMessageSchema = z.object({
  to: z.array(z.string()).min(1).max(50),
  subject: z.string().max(500).optional(),
  
  // V2: Multimodal — accept either body (string) or parts (array)
  body: z.string().min(1).max(50000).optional(),
  parts: z.array(z.object({
    kind: z.enum(['text', 'data', 'file']),
    content: z.any().optional(),
    content_type: z.string().max(255).optional(),
    url: z.string().max(2048).optional(),
    mime: z.string().max(255).optional(),
    name: z.string().max(500).optional(),
    size: z.number().optional(),
    metadata: z.record(z.any()).optional().refine(
      (val) => !val || JSON.stringify(val).length <= 5_000,
      { message: 'Part metadata must be under 5KB' }
    ),
  })).min(1).max(20).optional(),
  
  // V2: Threading (A2A: contextId)
  threadId: z.string().uuid().optional(),
  refId: z.string().uuid().optional(),
  
  // V2: Message type
  type: z.enum(['message', 'task_request', 'task_update', 'task_response', 'presence']).default('message'),
  
  // V3: A2A Task metadata (aligned with A2A Protocol Spec)
  taskMeta: z.object({
    taskId: z.string().optional(),
    status: z.enum(A2A_TASK_STATES).optional(),
    progress: z.number().min(0).max(1).optional(),
    priority: z.enum(['low', 'normal', 'high', 'urgent']).optional(),
    timeout: z.number().optional(),
    // A2A: Artifacts instead of single result
    // V2.2.10: Limit to 20 artifacts to prevent storage abuse
    artifacts: z.array(artifactSchema).max(20).optional(),
    // Legacy: Keep result for backward compatibility
    // V2.2.10: Size limit to prevent storage abuse
    result: z.any().optional().refine(
      (val) => !val || JSON.stringify(val).length <= 50_000,
      { message: 'taskMeta.result must be under 50KB when serialized' }
    ),
  }).optional(),
  
  // V3: A2A Message metadata
  metadata: z.record(z.any()).optional().refine(
    (val) => !val || JSON.stringify(val).length <= 10_000,
    { message: 'metadata must be under 10KB when serialized' }
  ),
  
  // V3: A2A Reference task IDs (for context)
  referenceTaskIds: z.array(z.string().max(128)).max(20).optional(),
}).refine(
  (data) => data.body || data.parts,
  { message: 'Either body (string) or parts (array) is required' }
);

const updateMessageSchema = z.object({
  isStarred: z.boolean().optional(),
  labels: z.array(z.string().max(50)).max(20).optional(),
  folder: z.enum(['inbox', 'archive', 'trash']).optional(),
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /messages
// Send a new message
// ═══════════════════════════════════════════════════════════════════════════
messagesRoute.post('/', async (c) => {
  try {
    const { id: senderId } = c.get('agent');
    const body = await c.req.json();
    const data = sendMessageSchema.parse(body);

    // Find all recipient agents (active only)
    const recipientAgents = await db.select({
      id: agents.id,
      domain: agents.domain,
    })
    .from(agents)
    .where(and(
      inArray(agents.domain, data.to.map(d => d.toLowerCase())),
      eq(agents.status, 'active')
    ));

    if (recipientAgents.length === 0) {
      return c.json(apiError('No valid recipients found', 'INVALID_RECIPIENTS'), 400);
    }

    // Check for invalid recipients
    const foundDomains = new Set(recipientAgents.map(a => a.domain));
    const invalidDomains = data.to.filter(d => !foundDomains.has(d.toLowerCase()));
    
    if (invalidDomains.length > 0) {
      return c.json(apiError(
        `Recipients not found: ${invalidDomains.join(', ')}`,
        'INVALID_RECIPIENTS'
      ), 400);
    }

    // V2: Consent check — must have accepted connection with each recipient
    const recipientIds = recipientAgents.map(a => a.id);

    // Prevent self-messaging
    if (recipientIds.includes(senderId)) {
      return c.json(apiError('Cannot send a message to yourself', 'SELF_MESSAGE'), 400);
    }

    const acceptedConnections = await db.select({
      requesterId: connections.requesterId,
      targetId: connections.targetId,
    })
    .from(connections)
    .where(and(
      eq(connections.status, 'accepted'),
      or(
        and(eq(connections.requesterId, senderId), inArray(connections.targetId, recipientIds)),
        and(inArray(connections.requesterId, recipientIds), eq(connections.targetId, senderId))
      )
    ));

    const connectedIds = new Set<string>();
    acceptedConnections.forEach(c => {
      connectedIds.add(c.requesterId === senderId ? c.targetId : c.requesterId);
    });

    const unconnected = recipientAgents.filter(a => !connectedIds.has(a.id));
    if (unconnected.length > 0) {
      // V2.2.13: Auto-send connection requests with message instead of rejecting
      const autoConnected: string[] = [];
      for (const agent of unconnected) {
        try {
          // Check if connection already exists (either direction)
          const [existing] = await db.select({ id: connections.id, status: connections.status })
            .from(connections)
            .where(or(
              and(eq(connections.requesterId, senderId), eq(connections.targetId, agent.id)),
              and(eq(connections.requesterId, agent.id), eq(connections.targetId, senderId))
            ))
            .limit(1);

          if (existing) {
            // Already have a connection (pending/accepted/rejected) — block duplicate
            if (existing.status === 'pending') {
              return c.json(apiError(
                `Connection request to ${agent.domain} is already pending. Wait for them to accept before sending more messages.`,
                'CONNECTION_PENDING'
              ), 409);
            } else if (existing.status === 'rejected' || existing.status === 'blocked') {
              return c.json(apiError(
                `Cannot send message to ${agent.domain}. Connection was ${existing.status}.`,
                'CONNECTION_REJECTED'
              ), 403);
            }
          } else {
            await db.insert(connections).values({
              requesterId: senderId,
              targetId: agent.id,
              status: 'pending',
              initialMessage: {
                subject: data.subject || null,
                parts: data.parts || [{ kind: 'text', content: data.body }],
                type: data.type || 'message',
              },
            });
            autoConnected.push(agent.domain);
          }
        } catch (err: any) {
          if (err.code !== '23505') throw err; // ignore duplicate key
        }
      }

      // Filter to only connected recipients
      const connectedRecipients = recipientAgents.filter(a => connectedIds.has(a.id));

      if (connectedRecipients.length === 0) {
        // All recipients were unconnected — return success with connection info
        return c.json(apiResponse({
          connectionRequestsSent: autoConnected,
          message: `Connection request${autoConnected.length > 1 ? 's' : ''} sent with your message to: ${autoConnected.join(', ')}`,
        }, 'Connection requests sent with message'), 202);
      }

      // Continue with connected recipients only
      recipientAgents.length = 0;
      recipientAgents.push(...connectedRecipients);
    }

    // V2: Normalize content to parts array (backward compatible)
    let parts: import('../utils').MessagePart[];
    try {
      const raw = data.parts || data.body!;
      parts = normalizeParts(raw as string | import('../utils').MessagePart[]);
    } catch (err: any) {
      return c.json(apiError(err.message, 'INVALID_CONTENT'), 400);
    }

    // V2: Validate each part
    for (let i = 0; i < parts.length; i++) {
      const validation = validatePart(parts[i]);
      if (!validation.valid) {
        return c.json(apiError(`Invalid part[${i}]: ${validation.error}`, 'INVALID_PART'), 400);
      }
      // Validate file URLs are not targeting internal networks
      if (parts[i].kind === 'file') {
        const filePart = parts[i] as { url: string };
        if (!isPublicUrl(filePart.url)) {
          return c.json(apiError(`part[${i}]: URL targets private/internal network`, 'SSRF_BLOCKED'), 400);
        }
      }
    }

    // V2: Extract text body from parts for search/preview/backward compat
    const textBody = extractTextFromParts(parts);
    const sanitizedBody = sanitizeHtml(textBody || `[${data.type || 'message'}]`);
    const hasFiles = partsHaveFiles(parts);

    // V2.1.2: Sanitize parts for XSS defense-in-depth before storage
    const sanitizedParts = sanitizeParts(parts);

    const now = new Date();
    let threadId: string;

    if (!data.threadId) {
      // V2.2.13: For 1-on-1 messages, reuse existing private thread if one exists
      let existingPrivateThread: string | null = null;
      if (recipientAgents.length === 1) {
        const recipientId = recipientAgents[0].id;
        // Find threads where both sender and recipient are participants
        const senderThreads = await db.select({ threadId: threadParticipants.threadId })
          .from(threadParticipants)
          .where(and(
            eq(threadParticipants.agentId, senderId),
            eq(threadParticipants.isDeleted, false)
          ));
        const senderThreadIds = senderThreads.map(t => t.threadId);
        
        if (senderThreadIds.length > 0) {
          // Find threads that also have the recipient
          const sharedThreads = await db.select({ threadId: threadParticipants.threadId })
            .from(threadParticipants)
            .where(and(
              eq(threadParticipants.agentId, recipientId),
              eq(threadParticipants.isDeleted, false),
              inArray(threadParticipants.threadId, senderThreadIds)
            ));
          
          // Check which shared threads have exactly 2 participants (private thread)
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
      }

      if (existingPrivateThread) {
        // Reuse existing private thread
        threadId = existingPrivateThread;
        await db.update(threads)
          .set({ 
            messageCount: sql`${threads.messageCount} + 1`,
            updatedAt: now,
          })
          .where(eq(threads.id, threadId));
      } else {
        // Create new thread
        const [newThread] = await db.insert(threads).values({
          subject: data.subject,
          messageCount: 1,
          updatedAt: now,
        }).returning();
        threadId = newThread.id;

        // Add all participants to thread
        const allParticipantIds = [senderId, ...recipientAgents.map(a => a.id)];
        await db.insert(threadParticipants).values(
          allParticipantIds.map(agentId => ({
            threadId,
            agentId,
          }))
        );
      }
    } else {
      threadId = data.threadId;
      
      // SECURITY: Verify sender is a participant of this thread
      const [senderParticipation] = await db.select({ id: threadParticipants.id })
        .from(threadParticipants)
        .where(and(
          eq(threadParticipants.threadId, threadId),
          eq(threadParticipants.agentId, senderId),
          eq(threadParticipants.isDeleted, false)
        ))
        .limit(1);

      if (!senderParticipation) {
        return c.json(apiError('Thread not found or access denied', 'NOT_FOUND'), 404);
      }

      // Verify thread exists
      const [existingThread] = await db.select({ id: threads.id })
        .from(threads)
        .where(eq(threads.id, threadId))
        .limit(1);

      if (!existingThread) {
        return c.json(apiError('Thread not found', 'NOT_FOUND'), 404);
      }

      // Update existing thread
      await db.update(threads)
        .set({ 
          messageCount: sql`${threads.messageCount} + 1`,
          updatedAt: now,
        })
        .where(eq(threads.id, threadId));

      // Add new participants if any
      for (const agent of recipientAgents) {
        await db.insert(threadParticipants)
          .values({ threadId, agentId: agent.id })
          .onConflictDoNothing();
      }
    }

    // Sanitize HTML body
    // (sanitizedBody already computed above from parts)

    // Create message (V3: with parts, type, refId, taskMeta, metadata, referenceTaskIds)
    const [newMessage] = await db.insert(messages).values({
      threadId,
      senderId,
      type: data.type || 'message',
      parts: sanitizedParts,
      body: sanitizedBody,
      bodyHtml: sanitizedBody,
      refId: data.refId || null,
      hasAttachments: hasFiles,
      taskMeta: data.taskMeta || null,
      metadata: data.metadata || null,
      referenceTaskIds: data.referenceTaskIds || null,
    }).returning();

    // Create recipient records
    await db.insert(messageRecipients).values(
      recipientAgents.map(agent => ({
        messageId: newMessage.id,
        recipientId: agent.id,
        status: 'sent',
      }))
    );

    // V2.2.13: Also create a recipient record for the sender so the thread appears in their inbox
    await db.insert(messageRecipients).values({
      messageId: newMessage.id,
      recipientId: senderId,
      status: 'sent',
      folder: 'inbox',
      readAt: now,
    }).onConflictDoNothing();

    // V2.1: Enqueue webhook delivery for recipients with webhook URLs
    enqueueWebhookBatch(
      recipientAgents.map(a => a.id),
      'message.received',
      {
        messageId: newMessage.id,
        threadId: newMessage.threadId,
        type: newMessage.type,
        sender: { id: senderId },
        parts: newMessage.parts,
        body: newMessage.body,
        refId: newMessage.refId,
        taskMeta: newMessage.taskMeta,
        createdAt: newMessage.createdAt,
      }
    ).catch(err => console.error('[Webhook] Enqueue error:', err));

    // Get sender info for response
    const [sender] = await db.select({
      id: agents.id,
      domain: agents.domain,
      displayName: agents.displayName,
      avatarEmoji: agents.avatarEmoji,
    })
    .from(agents)
    .where(eq(agents.id, senderId))
    .limit(1);

    return c.json(apiResponse({
      id: newMessage.id,
      threadId: newMessage.threadId,
      type: newMessage.type,
      sender: sender,
      recipients: recipientAgents.map(a => ({
        id: a.id,
        domain: a.domain,
      })),
      parts: newMessage.parts,
      body: newMessage.body,
      refId: newMessage.refId,
      taskMeta: newMessage.taskMeta,
      hasAttachments: newMessage.hasAttachments,
      createdAt: newMessage.createdAt,
    }, 'Message sent'), 201);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation error: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('Send message error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /messages
// List messages in inbox/folder
// ═══════════════════════════════════════════════════════════════════════════
messagesRoute.get('/', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const folder = c.req.query('folder') || 'inbox';
    const starred = c.req.query('starred') === 'true';
    const pagination = parsePagination(c.req.query());

    // ═══════════════════════════════════════════════════════════════
    // SENT VIEW: Query messages where I'm the sender
    // ═══════════════════════════════════════════════════════════════
    if (folder === 'sent') {
      const sentMessages = await db
        .select({
          id: messages.id,
          threadId: messages.threadId,
          type: messages.type,
          parts: messages.parts,
          body: messages.body,
          refId: messages.refId,
          hasAttachments: messages.hasAttachments,
          taskMeta: messages.taskMeta,
          createdAt: messages.createdAt,
          senderId: messages.senderId,
          senderDomain: agents.domain,
          senderDisplayName: agents.displayName,
          senderAvatarEmoji: agents.avatarEmoji,
        })
        .from(messages)
        .innerJoin(agents, eq(messages.senderId, agents.id))
        .where(eq(messages.senderId, agentId))
        .orderBy(desc(messages.createdAt))
        .limit(pagination.limit)
        .offset(pagination.offset);

      // Get thread subjects
      const threadIds = [...new Set(sentMessages.map(m => m.threadId))];
      const threadSubjects = new Map();
      if (threadIds.length > 0) {
        const threadData = await db.select({ id: threads.id, subject: threads.subject })
          .from(threads).where(inArray(threads.id, threadIds));
        threadData.forEach(t => threadSubjects.set(t.id, t.subject));
      }

      // Get first recipient for each sent message (for display)
      const messageIds = sentMessages.map(m => m.id);
      const recipientsByMsg = new Map<string, { domain: string; displayName: string | null; avatarEmoji: string | null }>();
      if (messageIds.length > 0) {
        const recipients = await db.select({
          messageId: messageRecipients.messageId,
          domain: agents.domain,
          displayName: agents.displayName,
          avatarEmoji: agents.avatarEmoji,
        })
        .from(messageRecipients)
        .innerJoin(agents, eq(messageRecipients.recipientId, agents.id))
        .where(inArray(messageRecipients.messageId, messageIds));
        recipients.forEach(r => {
          if (!recipientsByMsg.has(r.messageId)) {
            recipientsByMsg.set(r.messageId, r);
          }
        });
      }

      // Get thread participant counts for group detection
      const sentParticipantCount = new Map<string, number>();
      if (threadIds.length > 0) {
        const tpCounts = await db.select({
          threadId: threadParticipants.threadId,
          agentId: threadParticipants.agentId,
        }).from(threadParticipants).where(and(
          inArray(threadParticipants.threadId, threadIds),
          eq(threadParticipants.isDeleted, false),
        ));
        tpCounts.forEach(tp => sentParticipantCount.set(tp.threadId, (sentParticipantCount.get(tp.threadId) || 0) + 1));
      }

      const formattedSent = sentMessages.map(msg => ({
        id: msg.id,
        threadId: msg.threadId,
        type: msg.type,
        subject: threadSubjects.get(msg.threadId),
        preview: generatePreview(msg.body),
        parts: msg.parts,
        refId: msg.refId,
        hasAttachments: msg.hasAttachments,
        taskMeta: msg.taskMeta,
        sender: {
          id: msg.senderId,
          domain: msg.senderDomain,
          displayName: msg.senderDisplayName,
          avatarEmoji: msg.senderAvatarEmoji,
        },
        recipient: recipientsByMsg.get(msg.id) || null,
        participantCount: sentParticipantCount.get(msg.threadId) || 2,
        status: 'sent',
        readAt: null,
        isStarred: false,
        labels: [],
        folder: 'sent',
        isUnread: false,
        createdAt: msg.createdAt,
      }));

      return c.json(apiResponse({
        ...paginatedResponse(formattedSent, pagination),
        folder: 'sent',
      }));
    }

    // ═══════════════════════════════════════════════════════════════
    // INBOX / ARCHIVE / TRASH / STARRED: Query as recipient
    // ═══════════════════════════════════════════════════════════════

    // Build where conditions
    const conditions = [
      eq(messageRecipients.recipientId, agentId),
      eq(messageRecipients.isDeleted, false),
    ];

    if (starred) {
      // Starred: filter by isStarred across all folders
      conditions.push(eq(messageRecipients.isStarred, true));
    } else {
      // Normal folder filter
      conditions.push(eq(messageRecipients.folder, folder));
    }

    const myMessages = await db
      .select({
        // Message fields
        id: messages.id,
        threadId: messages.threadId,
        type: messages.type,
        parts: messages.parts,
        body: messages.body,
        refId: messages.refId,
        hasAttachments: messages.hasAttachments,
        taskMeta: messages.taskMeta,
        createdAt: messages.createdAt,
        // Sender info
        senderId: messages.senderId,
        senderDomain: agents.domain,
        senderDisplayName: agents.displayName,
        senderAvatarEmoji: agents.avatarEmoji,
        // Recipient state
        recipientRecordId: messageRecipients.id,
        status: messageRecipients.status,
        readAt: messageRecipients.readAt,
        isStarred: messageRecipients.isStarred,
        labels: messageRecipients.labels,
        folder: messageRecipients.folder,
      })
      .from(messageRecipients)
      .innerJoin(messages, eq(messageRecipients.messageId, messages.id))
      .innerJoin(agents, eq(messages.senderId, agents.id))
      .where(and(...conditions))
      .orderBy(desc(messages.createdAt))
      .limit(pagination.limit)
      .offset(pagination.offset);

    // Get thread subjects
    const threadIds = [...new Set(myMessages.map(m => m.threadId))];
    const threadSubjects = new Map();
    
    if (threadIds.length > 0) {
      const threadData = await db.select({
        id: threads.id,
        subject: threads.subject,
      })
      .from(threads)
      .where(inArray(threads.id, threadIds));
      
      threadData.forEach(t => threadSubjects.set(t.id, t.subject));
    }

    // V2.2.13: Get thread participants to identify "other party" for self-sent messages
    const threadParticipantMap = new Map<string, { id: string; domain: string; displayName: string | null; avatarEmoji: string | null }>();
    const threadParticipantCount = new Map<string, number>();
    if (threadIds.length > 0) {
      const tpData = await db.select({
        threadId: threadParticipants.threadId,
        agentId: threadParticipants.agentId,
        domain: agents.domain,
        displayName: agents.displayName,
        avatarEmoji: agents.avatarEmoji,
      })
      .from(threadParticipants)
      .innerJoin(agents, eq(threadParticipants.agentId, agents.id))
      .where(and(
        inArray(threadParticipants.threadId, threadIds),
        eq(threadParticipants.isDeleted, false),
      ));
      // For each thread, store the first "other" participant + count all
      tpData.forEach(tp => {
        threadParticipantCount.set(tp.threadId, (threadParticipantCount.get(tp.threadId) || 0) + 1);
        if (tp.agentId !== agentId && !threadParticipantMap.has(tp.threadId)) {
          threadParticipantMap.set(tp.threadId, {
            id: tp.agentId,
            domain: tp.domain,
            displayName: tp.displayName,
            avatarEmoji: tp.avatarEmoji,
          });
        }
      });
    }

    // Format response - standard API format
    const formattedMessages = myMessages.map(msg => ({
      id: msg.id,
      threadId: msg.threadId,
      type: msg.type,
      subject: threadSubjects.get(msg.threadId),
      preview: generatePreview(msg.body),
      parts: msg.parts,
      refId: msg.refId,
      hasAttachments: msg.hasAttachments,
      taskMeta: msg.taskMeta,
      sender: {
        id: msg.senderId,
        domain: msg.senderDomain,
        displayName: msg.senderDisplayName,
        avatarEmoji: msg.senderAvatarEmoji,
      },
      recipient: threadParticipantMap.get(msg.threadId) || null,
      participantCount: threadParticipantCount.get(msg.threadId) || 2,
      status: msg.status,
      readAt: msg.readAt,
      isStarred: msg.isStarred,
      labels: msg.labels,
      folder: msg.folder,
      isUnread: !msg.readAt,
      createdAt: msg.createdAt,
    }));

    return c.json(apiResponse({
      ...paginatedResponse(formattedMessages, pagination),
      folder: starred ? 'starred' : folder,
    }));

  } catch (error) {
    console.error('List messages error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /messages/:id
// Get single message with full details
// ═══════════════════════════════════════════════════════════════════════════
messagesRoute.get('/:id', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const messageId = c.req.param('id');

    if (!isValidUuid(messageId)) {
      return c.json(apiError('Invalid message ID format', 'INVALID_ID'), 400);
    }

    // Get message with recipient info
    const [result] = await db
      .select({
        // Message fields
        id: messages.id,
        threadId: messages.threadId,
        type: messages.type,
        parts: messages.parts,
        body: messages.body,
        bodyHtml: messages.bodyHtml,
        refId: messages.refId,
        hasAttachments: messages.hasAttachments,
        taskMeta: messages.taskMeta,
        createdAt: messages.createdAt,
        // Sender info
        senderId: messages.senderId,
        senderDomain: agents.domain,
        senderDisplayName: agents.displayName,
        senderAvatarEmoji: agents.avatarEmoji,
        // Recipient state (may be null if sender viewing)
        recipientRecordId: messageRecipients.id,
        status: messageRecipients.status,
        readAt: messageRecipients.readAt,
        isStarred: messageRecipients.isStarred,
        labels: messageRecipients.labels,
      })
      .from(messages)
      .innerJoin(agents, eq(messages.senderId, agents.id))
      .leftJoin(messageRecipients, and(
        eq(messageRecipients.messageId, messages.id),
        eq(messageRecipients.recipientId, agentId),
        eq(messageRecipients.isDeleted, false)
      ))
      .where(eq(messages.id, messageId))
      .limit(1);

    if (!result) {
      return c.json(apiError('Message not found', 'NOT_FOUND'), 404);
    }

    // Check access: must be sender or recipient
    const isSender = result.senderId === agentId;
    const isRecipient = !!result.recipientRecordId;
    
    if (!isSender && !isRecipient) {
      return c.json(apiError('Access denied', 'FORBIDDEN'), 403);
    }

    // Mark as read if recipient and unread
    if (isRecipient && !result.readAt) {
      await db.update(messageRecipients)
        .set({ readAt: new Date(), status: 'read' })
        .where(eq(messageRecipients.id, result.recipientRecordId!));
    }

    // Get thread info
    const [thread] = await db.select()
      .from(threads)
      .where(eq(threads.id, result.threadId))
      .limit(1);

    // Get all recipients for this message
    const recipients = await db
      .select({
        id: agents.id,
        domain: agents.domain,
        displayName: agents.displayName,
        avatarEmoji: agents.avatarEmoji,
      })
      .from(messageRecipients)
      .innerJoin(agents, eq(messageRecipients.recipientId, agents.id))
      .where(eq(messageRecipients.messageId, messageId));

    return c.json(apiResponse({
      id: result.id,
      threadId: result.threadId,
      type: result.type,
      thread: thread ? {
        id: thread.id,
        subject: thread.subject,
        messageCount: thread.messageCount,
        createdAt: thread.createdAt,
        updatedAt: thread.updatedAt,
      } : null,
      sender: {
        id: result.senderId,
        domain: result.senderDomain,
        displayName: result.senderDisplayName,
        avatarEmoji: result.senderAvatarEmoji,
      },
      recipients,
      parts: result.parts,
      body: result.body,
      bodyHtml: result.bodyHtml,
      refId: result.refId,
      hasAttachments: result.hasAttachments,
      taskMeta: result.taskMeta,
      isStarred: result.isStarred,
      labels: result.labels,
      status: result.status,
      readAt: result.readAt,
      createdAt: result.createdAt,
    }));

  } catch (error) {
    console.error('Get message error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// PATCH /messages/:id
// Update message (star, labels, folder)
// ═══════════════════════════════════════════════════════════════════════════
messagesRoute.patch('/:id', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const messageId = c.req.param('id');

    if (!isValidUuid(messageId)) {
      return c.json(apiError('Invalid message ID format', 'INVALID_ID'), 400);
    }

    const body = await c.req.json();
    const data = updateMessageSchema.parse(body);

    // Find recipient record
    const [recipientRecord] = await db.select()
      .from(messageRecipients)
      .where(and(
        eq(messageRecipients.messageId, messageId),
        eq(messageRecipients.recipientId, agentId)
      ))
      .limit(1);

    if (!recipientRecord) {
      return c.json(apiError('Message not found', 'NOT_FOUND'), 404);
    }

    // Update
    // V2.2.6: Track folder change time for accurate retention
    const updateData: Record<string, unknown> = { ...data };
    if (data.folder) {
      updateData.folderChangedAt = new Date();
    }
    const [updated] = await db.update(messageRecipients)
      .set(updateData)
      .where(eq(messageRecipients.id, recipientRecord.id))
      .returning();

    return c.json(apiResponse({
      id: messageId,
      isStarred: updated.isStarred,
      labels: updated.labels,
      folder: updated.folder,
    }, 'Message updated'));

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation error: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('Update message error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// DELETE /messages/:id
// Delete message (soft delete - move to trash, then permanent)
// ═══════════════════════════════════════════════════════════════════════════
messagesRoute.delete('/:id', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const messageId = c.req.param('id');

    if (!isValidUuid(messageId)) {
      return c.json(apiError('Invalid message ID format', 'INVALID_ID'), 400);
    }

    const permanent = c.req.query('permanent') === 'true';

    // Find recipient record
    const [recipientRecord] = await db.select()
      .from(messageRecipients)
      .where(and(
        eq(messageRecipients.messageId, messageId),
        eq(messageRecipients.recipientId, agentId)
      ))
      .limit(1);

    if (!recipientRecord) {
      return c.json(apiError('Message not found', 'NOT_FOUND'), 404);
    }

    if (permanent || recipientRecord.folder === 'trash') {
      // Permanent delete
      await db.delete(messageRecipients)
        .where(eq(messageRecipients.id, recipientRecord.id));
      
      return c.json(apiResponse({ 
        deleted: true,
        permanent: true,
      }, 'Message permanently deleted'));
    } else {
      // Move to trash (keep isDeleted=false so message is visible in trash folder)
      await db.update(messageRecipients)
        .set({ folder: 'trash', folderChangedAt: new Date() })
        .where(eq(messageRecipients.id, recipientRecord.id));
      
      return c.json(apiResponse({ 
        deleted: false,
        movedToTrash: true,
      }, 'Message moved to trash'));
    }

  } catch (error) {
    console.error('Delete message error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /messages/:id/read
// Mark message as read
// ═══════════════════════════════════════════════════════════════════════════
messagesRoute.post('/:id/read', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const messageId = c.req.param('id');

    if (!isValidUuid(messageId)) {
      return c.json(apiError('Invalid message ID format', 'INVALID_ID'), 400);
    }

    const [updated] = await db.update(messageRecipients)
      .set({ readAt: new Date(), status: 'read' })
      .where(and(
        eq(messageRecipients.messageId, messageId),
        eq(messageRecipients.recipientId, agentId)
      ))
      .returning();

    if (!updated) {
      return c.json(apiError('Message not found', 'NOT_FOUND'), 404);
    }

    return c.json(apiResponse({ 
      id: messageId,
      readAt: updated.readAt,
    }, 'Marked as read'));

  } catch (error) {
    console.error('Mark read error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /messages/:id/unread
// Mark message as unread
// ═══════════════════════════════════════════════════════════════════════════
messagesRoute.post('/:id/unread', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const messageId = c.req.param('id');

    if (!isValidUuid(messageId)) {
      return c.json(apiError('Invalid message ID format', 'INVALID_ID'), 400);
    }

    const [updated] = await db.update(messageRecipients)
      .set({ readAt: null, status: 'delivered' })
      .where(and(
        eq(messageRecipients.messageId, messageId),
        eq(messageRecipients.recipientId, agentId)
      ))
      .returning();

    if (!updated) {
      return c.json(apiError('Message not found', 'NOT_FOUND'), 404);
    }

    return c.json(apiResponse({ 
      id: messageId,
      readAt: null,
    }, 'Marked as unread'));

  } catch (error) {
    console.error('Mark unread error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

export default messagesRoute;
