import { Hono } from 'hono';
import { z } from 'zod';
import { db } from '../db';
import { agents, messages, messageRecipients, threads, threadParticipants, connections } from '../db/schema';
import { eq, and, desc, inArray, sql, ne, or } from 'drizzle-orm';
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
  isPublicUrl,
} from '../utils';
import { enqueueWebhookBatch } from '../services/webhook';

const threadsRoute = new Hono();

// Apply auth middleware
threadsRoute.use('/*', authMiddleware);

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION SCHEMAS
// ═══════════════════════════════════════════════════════════════════════════

const replySchema = z.object({
  // V2: Accept either body (string) or parts (array)
  body: z.string().min(1).max(50000).optional(),
  parts: z.array(z.object({
    kind: z.enum(['text', 'data', 'file']),
    content: z.any().optional(),
    content_type: z.string().max(255).optional(),
    url: z.string().max(2048).optional(),
    mime: z.string().max(255).optional(),
    name: z.string().max(500).optional(),
    size: z.number().optional(),
    // V2.2.9: Part metadata size limit (matches sendMessageSchema)
    metadata: z.record(z.any()).optional().refine(
      (val) => !val || JSON.stringify(val).length <= 5_000,
      { message: 'Part metadata must be under 5KB' }
    ),
  })).min(1).max(20).optional(),
  refId: z.string().uuid().optional(),
  type: z.enum(['message', 'task_request', 'task_update', 'task_response', 'presence']).default('message'),
  taskMeta: z.object({
    taskId: z.string().optional(),
    // V3: A2A task states (including legacy aliases)
    status: z.enum([
      'submitted', 'pending',  // pending = submitted (legacy)
      'working', 
      'completed', 
      'failed', 
      'canceled', 'cancelled',  // cancelled = canceled (legacy)
      'input-required', 'input_required',
      'rejected',
      'auth-required', 'auth_required'
    ]).optional(),
    progress: z.number().min(0).max(1).optional(),
    priority: z.enum(['low', 'normal', 'high', 'urgent']).optional(),
    timeout: z.number().optional(),
    // V2.2.10: Size limit to prevent storage abuse
    result: z.any().optional().refine(
      (val) => !val || JSON.stringify(val).length <= 50_000,
      { message: 'taskMeta.result must be under 50KB when serialized' }
    ),
  }).optional(),
}).refine(
  (data) => data.body || data.parts,
  { message: 'Either body (string) or parts (array) is required' }
);

const updateThreadSchema = z.object({
  isArchived: z.boolean().optional(),
  subject: z.string().max(200).optional(),
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /threads
// List threads the agent is part of
// ═══════════════════════════════════════════════════════════════════════════
threadsRoute.get('/', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const pagination = parsePagination(c.req.query());

    // Get threads where agent is a participant (bounded to prevent OOM)
    // We fetch more than pagination.limit to allow for proper thread sorting
    const MAX_THREAD_FETCH = 1000;
    const myParticipations = await db
      .select({
        threadId: threadParticipants.threadId,
        isArchived: threadParticipants.isArchived,
        lastReadAt: threadParticipants.lastReadAt,
      })
      .from(threadParticipants)
      .where(and(
        eq(threadParticipants.agentId, agentId),
        eq(threadParticipants.isDeleted, false)
      ))
      .limit(MAX_THREAD_FETCH);

    if (myParticipations.length === 0) {
      return c.json(apiResponse(paginatedResponse([], pagination)));
    }

    const threadIds = myParticipations.map(p => p.threadId);
    const participationMap = new Map(myParticipations.map(p => [p.threadId, p]));

    // Get thread details
    const threadsList = await db.select()
      .from(threads)
      .where(inArray(threads.id, threadIds))
      .orderBy(desc(threads.updatedAt))
      .limit(pagination.limit)
      .offset(pagination.offset);

    // Get last message for each thread (V2.1.3: use DISTINCT ON for efficiency)
    const lastMessages = threadIds.length > 0 ? await db.execute(sql`
      SELECT DISTINCT ON (thread_id)
        thread_id AS "threadId",
        id,
        body,
        sender_id AS "senderId",
        created_at AS "createdAt"
      FROM messages
      WHERE thread_id = ANY(${threadIds})
      ORDER BY thread_id, created_at DESC
    `) : [];

    // Build map of thread → last message
    const lastMessageByThread = new Map<string, { threadId: string; id: string; body: string; senderId: string; createdAt: Date }>();
    (lastMessages as any[]).forEach((msg: any) => {
      lastMessageByThread.set(msg.threadId, msg);
    });

    // Get sender info for last messages
    const senderIds = [...new Set([...lastMessageByThread.values()].map(m => m.senderId))];
    const senders = senderIds.length > 0 ? await db.select({
      id: agents.id,
      domain: agents.domain,
      displayName: agents.displayName,
      avatarEmoji: agents.avatarEmoji,
    })
    .from(agents)
    .where(inArray(agents.id, senderIds)) : [];
    
    const senderMap = new Map(senders.map(s => [s.id, s]));

    // Get unread count per thread
    const unreadCounts = await db
      .select({
        threadId: messages.threadId,
        count: sql<number>`count(*)::int`,
      })
      .from(messages)
      .innerJoin(messageRecipients, eq(messages.id, messageRecipients.messageId))
      .where(and(
        inArray(messages.threadId, threadIds),
        eq(messageRecipients.recipientId, agentId),
        sql`${messageRecipients.readAt} IS NULL`
      ))
      .groupBy(messages.threadId);

    const unreadMap = new Map(unreadCounts.map(u => [u.threadId, u.count]));

    // Get participant count per thread (V2.2.10: exclude soft-deleted participants)
    const participantCounts = await db
      .select({
        threadId: threadParticipants.threadId,
        count: sql<number>`count(*)::int`,
      })
      .from(threadParticipants)
      .where(and(
        inArray(threadParticipants.threadId, threadIds),
        eq(threadParticipants.isDeleted, false)
      ))
      .groupBy(threadParticipants.threadId);

    const participantCountMap = new Map(participantCounts.map(p => [p.threadId, p.count]));

    // V2.2.13: Get participant details for each thread (needed for DM identification)
    const allParticipants = threadIds.length > 0 ? await db.select({
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
      eq(threadParticipants.isDeleted, false)
    )) : [];

    const participantsByThread = new Map<string, Array<{ id: string; domain: string; displayName: string | null; avatarEmoji: string | null }>>();
    allParticipants.forEach(p => {
      if (!participantsByThread.has(p.threadId)) participantsByThread.set(p.threadId, []);
      participantsByThread.get(p.threadId)!.push({
        id: p.agentId,
        domain: p.domain,
        displayName: p.displayName,
        avatarEmoji: p.avatarEmoji,
      });
    });

    // Format response
    const formattedThreads = threadsList.map(thread => {
      const lastMsg = lastMessageByThread.get(thread.id);
      const participation = participationMap.get(thread.id);
      const sender = lastMsg ? senderMap.get(lastMsg.senderId) : null;

      return {
        id: thread.id,
        subject: thread.subject,
        messageCount: thread.messageCount,
        participantCount: participantCountMap.get(thread.id) || 0,
        participants: participantsByThread.get(thread.id) || [],
        unreadCount: unreadMap.get(thread.id) || 0,
        isArchived: participation?.isArchived || false,
        lastMessage: lastMsg ? {
          id: lastMsg.id,
          preview: generatePreview(lastMsg.body),
          sender: sender,
          createdAt: lastMsg.createdAt,
        } : null,
        createdAt: thread.createdAt,
        updatedAt: thread.updatedAt,
      };
    });

    return c.json(apiResponse(paginatedResponse(formattedThreads, pagination)));

  } catch (error) {
    console.error('List threads error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /threads/dm/:domain
// Find existing DM (2-person) thread with a specific agent by domain
// V2.2.13: Must be BEFORE /:id route so Hono matches /dm/ first
// ═══════════════════════════════════════════════════════════════════════════
threadsRoute.get('/dm/:domain', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const targetDomain = c.req.param('domain');

    // Find the target agent
    const [targetAgent] = await db.select({ id: agents.id, domain: agents.domain })
      .from(agents)
      .where(eq(agents.domain, targetDomain))
      .limit(1);

    if (!targetAgent) {
      return c.json(apiResponse({ threadId: null }, 'Agent not found'));
    }

    // Find threads where BOTH agents are participants
    const myThreads = await db.select({ threadId: threadParticipants.threadId })
      .from(threadParticipants)
      .where(and(eq(threadParticipants.agentId, agentId), eq(threadParticipants.isDeleted, false)));

    const targetThreads = await db.select({ threadId: threadParticipants.threadId })
      .from(threadParticipants)
      .where(and(eq(threadParticipants.agentId, targetAgent.id), eq(threadParticipants.isDeleted, false)));

    const mySet = new Set(myThreads.map(t => t.threadId));
    const sharedThreadIds = targetThreads.map(t => t.threadId).filter(id => mySet.has(id));

    if (sharedThreadIds.length === 0) {
      return c.json(apiResponse({ threadId: null }, 'No shared thread'));
    }

    // Find the 2-person thread with the most messages
    let bestThreadId: string | null = null;
    let bestMessageCount = -1;

    for (const tid of sharedThreadIds) {
      const [countResult] = await db.select({ count: sql<number>`count(*)::int` })
        .from(threadParticipants)
        .where(and(eq(threadParticipants.threadId, tid), eq(threadParticipants.isDeleted, false)));

      if (countResult && countResult.count === 2) {
        const [msgCount] = await db.select({ count: sql<number>`count(*)::int` })
          .from(messages)
          .where(eq(messages.threadId, tid));

        const mc = msgCount?.count || 0;
        if (mc > bestMessageCount) {
          bestMessageCount = mc;
          bestThreadId = tid;
        }
      }
    }

    return c.json(apiResponse({ threadId: bestThreadId }));
  } catch (error) {
    console.error('DM lookup error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /threads/:id
// Get thread with all messages
// ═══════════════════════════════════════════════════════════════════════════
threadsRoute.get('/:id', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const threadId = c.req.param('id');

    if (!isValidUuid(threadId)) {
      return c.json(apiError('Invalid thread ID format', 'INVALID_ID'), 400);
    }

    const pagination = parsePagination(c.req.query(), { defaultLimit: 100 });

    // Check if agent is active participant (not soft-deleted)
    const [participation] = await db.select()
      .from(threadParticipants)
      .where(and(
        eq(threadParticipants.threadId, threadId),
        eq(threadParticipants.agentId, agentId),
        eq(threadParticipants.isDeleted, false)
      ))
      .limit(1);

    if (!participation) {
      return c.json(apiError('Thread not found or access denied', 'NOT_FOUND'), 404);
    }

    // Get thread
    const [thread] = await db.select()
      .from(threads)
      .where(eq(threads.id, threadId))
      .limit(1);

    if (!thread) {
      return c.json(apiError('Thread not found', 'NOT_FOUND'), 404);
    }

    // Get all messages in thread
    const threadMessages = await db
      .select({
        id: messages.id,
        type: messages.type,
        parts: messages.parts,
        body: messages.body,
        bodyHtml: messages.bodyHtml,
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
      .where(eq(messages.threadId, threadId))
      .orderBy(messages.createdAt)
      .limit(pagination.limit)
      .offset(pagination.offset);

    // Get recipients for each message
    const messageIds = threadMessages.map(m => m.id);
    const allRecipients = messageIds.length > 0 ? await db
      .select({
        messageId: messageRecipients.messageId,
        recipientId: agents.id,
        recipientDomain: agents.domain,
        recipientDisplayName: agents.displayName,
        recipientAvatarEmoji: agents.avatarEmoji,
        status: messageRecipients.status,
        readAt: messageRecipients.readAt,
      })
      .from(messageRecipients)
      .innerJoin(agents, eq(messageRecipients.recipientId, agents.id))
      .where(inArray(messageRecipients.messageId, messageIds)) : [];

    // Group recipients by message
    const recipientsByMessage = new Map<string, typeof allRecipients>();
    allRecipients.forEach(r => {
      const existing = recipientsByMessage.get(r.messageId) || [];
      existing.push(r);
      recipientsByMessage.set(r.messageId, existing);
    });

    // Get all active participants (exclude soft-deleted)
    const participants = await db
      .select({
        id: agents.id,
        domain: agents.domain,
        displayName: agents.displayName,
        avatarEmoji: agents.avatarEmoji,
        isOnline: agents.isOnline,
      })
      .from(threadParticipants)
      .innerJoin(agents, eq(threadParticipants.agentId, agents.id))
      .where(and(
        eq(threadParticipants.threadId, threadId),
        eq(threadParticipants.isDeleted, false)
      ));

    // Format messages
    const formattedMessages = threadMessages.map(msg => ({
      id: msg.id,
      type: msg.type,
      sender: {
        id: msg.senderId,
        domain: msg.senderDomain,
        displayName: msg.senderDisplayName,
        avatarEmoji: msg.senderAvatarEmoji,
      },
      recipients: (recipientsByMessage.get(msg.id) || []).map(r => ({
        id: r.recipientId,
        domain: r.recipientDomain,
        displayName: r.recipientDisplayName,
        avatarEmoji: r.recipientAvatarEmoji,
        status: r.status,
        readAt: r.readAt,
      })),
      parts: msg.parts,
      body: msg.body,
      bodyHtml: msg.bodyHtml,
      refId: msg.refId,
      hasAttachments: msg.hasAttachments,
      taskMeta: msg.taskMeta,
      createdAt: msg.createdAt,
    }));

    // Update last read time (only for active participants)
    await db.update(threadParticipants)
      .set({ lastReadAt: new Date() })
      .where(and(
        eq(threadParticipants.threadId, threadId),
        eq(threadParticipants.agentId, agentId),
        eq(threadParticipants.isDeleted, false)
      ));

    return c.json(apiResponse({
      thread: {
        id: thread.id,
        subject: thread.subject,
        messageCount: thread.messageCount,
        createdAt: thread.createdAt,
        updatedAt: thread.updatedAt,
      },
      participants,
      messages: paginatedResponse(formattedMessages, pagination),
    }));

  } catch (error) {
    console.error('Get thread error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /threads/:id/messages
// Reply to a thread (add new message)
// ═══════════════════════════════════════════════════════════════════════════
threadsRoute.post('/:id/messages', async (c) => {
  try {
    const { id: senderId } = c.get('agent');
    const threadId = c.req.param('id');

    if (!isValidUuid(threadId)) {
      return c.json(apiError('Invalid thread ID format', 'INVALID_ID'), 400);
    }

    const body = await c.req.json();
    const data = replySchema.parse(body);

    // Check if sender is active participant (not soft-deleted)
    const [participation] = await db.select()
      .from(threadParticipants)
      .where(and(
        eq(threadParticipants.threadId, threadId),
        eq(threadParticipants.agentId, senderId),
        eq(threadParticipants.isDeleted, false)
      ))
      .limit(1);

    if (!participation) {
      return c.json(apiError('Thread not found or access denied', 'NOT_FOUND'), 404);
    }

    // Get all other active participants to set as recipients (exclude soft-deleted)
    const otherParticipants = await db.select({ agentId: threadParticipants.agentId })
      .from(threadParticipants)
      .where(and(
        eq(threadParticipants.threadId, threadId),
        ne(threadParticipants.agentId, senderId),
        eq(threadParticipants.isDeleted, false)
      ));

    // V2.1.3: Filter out participants who have blocked the sender (or vice versa)
    // Blocked agents should not receive messages in shared threads
    let eligibleRecipients = otherParticipants;
    if (otherParticipants.length > 0) {
      const otherIds = otherParticipants.map(p => p.agentId);
      const blockedConnections = await db.select({
        requesterId: connections.requesterId,
        targetId: connections.targetId,
      })
      .from(connections)
      .where(and(
        eq(connections.status, 'blocked'),
        or(
          and(eq(connections.requesterId, senderId), inArray(connections.targetId, otherIds)),
          and(inArray(connections.requesterId, otherIds), eq(connections.targetId, senderId))
        )
      ));

      const blockedIds = new Set<string>();
      blockedConnections.forEach(c => {
        blockedIds.add(c.requesterId === senderId ? c.targetId : c.requesterId);
      });

      if (blockedIds.size > 0) {
        eligibleRecipients = otherParticipants.filter(p => !blockedIds.has(p.agentId));
      }
    }

    // V2.2.6: Reject reply if ALL recipients are blocked (prevents ghost messages)
    if (otherParticipants.length > 0 && eligibleRecipients.length === 0) {
      return c.json(apiError(
        'Cannot send reply — no eligible recipients in this thread',
        'NO_ELIGIBLE_RECIPIENTS'
      ), 403);
    }

    const now = new Date();

    // V2: Normalize content to parts array
    let parts: import('../utils').MessagePart[];
    try {
      const raw = data.parts || data.body!;
      parts = normalizeParts(raw as string | import('../utils').MessagePart[]);
    } catch (err: any) {
      return c.json(apiError(err.message, 'INVALID_CONTENT'), 400);
    }

    // V2: Validate parts
    for (let i = 0; i < parts.length; i++) {
      const validation = validatePart(parts[i]);
      if (!validation.valid) {
        return c.json(apiError(`Invalid part[${i}]: ${validation.error}`, 'INVALID_PART'), 400);
      }
      if (parts[i].kind === 'file') {
        const filePart = parts[i] as { url: string };
        if (!isPublicUrl(filePart.url)) {
          return c.json(apiError(`part[${i}]: URL targets private/internal network`, 'SSRF_BLOCKED'), 400);
        }
      }
    }

    const textBody = extractTextFromParts(parts);
    const sanitizedBody = sanitizeHtml(textBody || `[${data.type || 'message'}]`);

    // V2.1.2: Sanitize parts for XSS defense-in-depth before storage
    const sanitizedParts = sanitizeParts(parts);

    // Create message (V2: with parts, type, refId, taskMeta)
    const [newMessage] = await db.insert(messages).values({
      threadId,
      senderId,
      type: data.type || 'message',
      parts: sanitizedParts,
      body: sanitizedBody,
      bodyHtml: sanitizedBody,
      refId: data.refId || null,
      hasAttachments: partsHaveFiles(parts),
      taskMeta: data.taskMeta || null,
    }).returning();

    // Create recipient records for eligible participants (not blocked)
    if (eligibleRecipients.length > 0) {
      await db.insert(messageRecipients).values(
        eligibleRecipients.map(p => ({
          messageId: newMessage.id,
          recipientId: p.agentId,
          status: 'sent',
        }))
      );

      // V2.1: Enqueue webhook delivery for recipients with webhook URLs
      enqueueWebhookBatch(
        eligibleRecipients.map(p => p.agentId),
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
    }

    // V2.2.13: Add sender's own inbox record so thread stays in their inbox
    await db.insert(messageRecipients).values({
      messageId: newMessage.id,
      recipientId: senderId,
      status: 'sent',
      folder: 'inbox',
      readAt: now,
    }).onConflictDoNothing();

    // Update thread
    await db.update(threads)
      .set({ 
        messageCount: sql`${threads.messageCount} + 1`,
        updatedAt: now,
      })
      .where(eq(threads.id, threadId));

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
      sender,
      parts: newMessage.parts,
      body: newMessage.body,
      refId: newMessage.refId,
      taskMeta: newMessage.taskMeta,
      createdAt: newMessage.createdAt,
    }, 'Message sent'), 201);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation error: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('Reply error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// PATCH /threads/:id
// Update thread (archive, rename, etc.)
// ═══════════════════════════════════════════════════════════════════════════
threadsRoute.patch('/:id', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const threadId = c.req.param('id');

    if (!isValidUuid(threadId)) {
      return c.json(apiError('Invalid thread ID format', 'INVALID_ID'), 400);
    }

    const body = await c.req.json();
    const data = updateThreadSchema.parse(body);

    // Verify participation
    const [participation] = await db.select()
      .from(threadParticipants)
      .where(and(
        eq(threadParticipants.threadId, threadId),
        eq(threadParticipants.agentId, agentId),
        eq(threadParticipants.isDeleted, false)
      ))
      .limit(1);

    if (!participation) {
      return c.json(apiError('Thread not found', 'NOT_FOUND'), 404);
    }

    // Update participant record if isArchived changed
    if (data.isArchived !== undefined) {
      await db.update(threadParticipants)
        .set({ isArchived: data.isArchived })
        .where(eq(threadParticipants.id, participation.id));
    }

    // Update thread subject if provided
    let subjectUpdated = false;
    if (data.subject !== undefined) {
      await db.update(threads)
        .set({ subject: data.subject })
        .where(eq(threads.id, threadId));
      subjectUpdated = true;

      // Get agent info for system message
      const [agent] = await db.select({ displayName: agents.displayName, domain: agents.domain })
        .from(agents).where(eq(agents.id, agentId)).limit(1);
      const agentName = agent?.displayName || agent?.domain || 'Someone';

      // Insert system message
      const systemParts = [{ kind: 'text' as const, content: `${agentName} renamed the conversation to "${data.subject}"` }];
      await db.insert(messages).values({
        threadId,
        senderId: agentId,
        type: 'system',
        parts: systemParts,
        body: systemParts[0].content,
      });
    }

    return c.json(apiResponse({
      threadId,
      isArchived: data.isArchived !== undefined ? data.isArchived : participation.isArchived,
      subject: data.subject,
      subjectUpdated,
    }, 'Thread updated'));

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation error: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('Update thread error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// DELETE /threads/:id
// Delete thread (soft delete for user)
// ═══════════════════════════════════════════════════════════════════════════
threadsRoute.delete('/:id', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const threadId = c.req.param('id');

    if (!isValidUuid(threadId)) {
      return c.json(apiError('Invalid thread ID format', 'INVALID_ID'), 400);
    }

    // Soft delete - mark as deleted for this participant (only if not already deleted)
    const [updated] = await db.update(threadParticipants)
      .set({ isDeleted: true, deletedAt: new Date() })
      .where(and(
        eq(threadParticipants.threadId, threadId),
        eq(threadParticipants.agentId, agentId),
        eq(threadParticipants.isDeleted, false)
      ))
      .returning();

    if (!updated) {
      return c.json(apiError('Thread not found', 'NOT_FOUND'), 404);
    }

    return c.json(apiResponse({
      threadId,
      deleted: true,
    }, 'Thread deleted'));

  } catch (error) {
    console.error('Delete thread error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /threads/:id/read
// Mark all messages in thread as read
// ═══════════════════════════════════════════════════════════════════════════
threadsRoute.post('/:id/read', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const threadId = c.req.param('id');

    if (!isValidUuid(threadId)) {
      return c.json(apiError('Invalid thread ID format', 'INVALID_ID'), 400);
    }

    // Verify agent is a participant of this thread
    const [participation] = await db.select({ id: threadParticipants.id })
      .from(threadParticipants)
      .where(and(
        eq(threadParticipants.threadId, threadId),
        eq(threadParticipants.agentId, agentId),
        eq(threadParticipants.isDeleted, false)
      ))
      .limit(1);

    if (!participation) {
      return c.json(apiError('Thread not found or access denied', 'NOT_FOUND'), 404);
    }

    // Get all message IDs in thread
    const threadMessageIds = await db.select({ id: messages.id })
      .from(messages)
      .where(eq(messages.threadId, threadId));

    if (threadMessageIds.length === 0) {
      return c.json(apiError('Thread not found', 'NOT_FOUND'), 404);
    }

    const messageIds = threadMessageIds.map(m => m.id);

    // Mark all as read
    await db.update(messageRecipients)
      .set({ readAt: new Date(), status: 'read' })
      .where(and(
        inArray(messageRecipients.messageId, messageIds),
        eq(messageRecipients.recipientId, agentId),
        sql`${messageRecipients.readAt} IS NULL`
      ));

    // Update last read time (only for active participants)
    await db.update(threadParticipants)
      .set({ lastReadAt: new Date() })
      .where(and(
        eq(threadParticipants.threadId, threadId),
        eq(threadParticipants.agentId, agentId),
        eq(threadParticipants.isDeleted, false)
      ));

    return c.json(apiResponse({
      threadId,
      markedAsRead: true,
    }, 'Thread marked as read'));

  } catch (error) {
    console.error('Mark thread read error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// PATCH /threads/:id/folder
// Move all messages in a thread to a folder (inbox/archive/trash) for current user
// ═══════════════════════════════════════════════════════════════════════════
threadsRoute.patch('/:id/folder', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const threadId = c.req.param('id');
    const body = await c.req.json();
    const folder = body.folder;

    if (!folder || !['inbox', 'archive', 'trash'].includes(folder)) {
      return c.json(apiError('Invalid folder', 'INVALID_FOLDER'), 400);
    }

    if (!isValidUuid(threadId)) {
      return c.json(apiError('Invalid thread ID format', 'INVALID_ID'), 400);
    }

    // Verify agent is participant
    const [participation] = await db.select({ id: threadParticipants.id })
      .from(threadParticipants)
      .where(and(
        eq(threadParticipants.threadId, threadId),
        eq(threadParticipants.agentId, agentId),
        eq(threadParticipants.isDeleted, false)
      ))
      .limit(1);

    if (!participation) {
      return c.json(apiError('Thread not found', 'NOT_FOUND'), 404);
    }

    // Get all message IDs in thread
    const threadMessages = await db.select({ id: messages.id })
      .from(messages)
      .where(eq(messages.threadId, threadId));

    if (threadMessages.length === 0) {
      return c.json(apiResponse({ threadId, folder, moved: 0 }, 'No messages to move'));
    }

    const messageIds = threadMessages.map(m => m.id);

    // Move all messageRecipients for this user to the target folder
    const result = await db.update(messageRecipients)
      .set({ folder, folderChangedAt: new Date() })
      .where(and(
        inArray(messageRecipients.messageId, messageIds),
        eq(messageRecipients.recipientId, agentId),
        eq(messageRecipients.isDeleted, false)
      ));

    return c.json(apiResponse({
      threadId,
      folder,
      moved: threadMessages.length,
    }, `Thread moved to ${folder}`));

  } catch (error) {
    console.error('Move thread folder error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

export default threadsRoute;
