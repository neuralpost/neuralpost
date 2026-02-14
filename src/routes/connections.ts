import { Hono } from 'hono';
import { z } from 'zod';
import { db } from '../db';
import { agents, connections, threads, messages, threadParticipants, messageRecipients } from '../db/schema';
import { eq, and, or, desc, inArray, sql } from 'drizzle-orm';
import { authMiddleware } from '../middleware/auth';
import { 
  apiResponse, 
  apiError, 
  parsePagination, 
  paginatedResponse,
  isValidDomain,
  isValidUuid,
  sanitizeHtml,
} from '../utils';
import { enqueueWebhook, enqueueWebhookBatch } from '../services/webhook';

const connectionsRoute = new Hono();

// Apply auth middleware
connectionsRoute.use('/*', authMiddleware);

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION SCHEMAS
// ═══════════════════════════════════════════════════════════════════════════

const createConnectionSchema = z.object({
  targetDomain: z.string().min(3).max(255),
});

const updateConnectionSchema = z.object({
  status: z.enum(['accepted', 'rejected', 'blocked']),
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /connections
// List all connections (accepted, pending, etc.)
// ═══════════════════════════════════════════════════════════════════════════
connectionsRoute.get('/', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const status = c.req.query('status'); // filter by status
    const type = c.req.query('type'); // 'sent' | 'received' | 'all'
    const pagination = parsePagination(c.req.query());

    let query = db
      .select({
        id: connections.id,
        requesterId: connections.requesterId,
        targetId: connections.targetId,
        status: connections.status,
        initialMessage: connections.initialMessage,
        createdAt: connections.createdAt,
        respondedAt: connections.respondedAt,
      })
      .from(connections);

    // Build where conditions
    const conditions = [];
    
    if (type === 'sent') {
      conditions.push(eq(connections.requesterId, agentId));
    } else if (type === 'received') {
      conditions.push(eq(connections.targetId, agentId));
    } else {
      conditions.push(or(
        eq(connections.requesterId, agentId),
        eq(connections.targetId, agentId)
      ));
    }

    if (status) {
      conditions.push(eq(connections.status, status));
    }

    const connectionsList = await query
      .where(and(...conditions))
      .orderBy(desc(connections.createdAt))
      .limit(pagination.limit)
      .offset(pagination.offset);

    // Get all agent IDs to fetch details
    const agentIds = new Set<string>();
    connectionsList.forEach(conn => {
      agentIds.add(conn.requesterId);
      agentIds.add(conn.targetId);
    });

    const agentDetails = agentIds.size > 0 ? await db.select({
      id: agents.id,
      domain: agents.domain,
      displayName: agents.displayName,
      avatarEmoji: agents.avatarEmoji,
      isOnline: agents.isOnline,
      bio: agents.bio,
      capabilities: agents.capabilities,
      profile: agents.profile,
    })
    .from(agents)
    .where(inArray(agents.id, [...agentIds])) : [];

    const agentMap = new Map(agentDetails.map(a => [a.id, a]));

    // Format response
    const formattedConnections = connectionsList.map(conn => ({
      id: conn.id,
      requester: agentMap.get(conn.requesterId) || null,
      target: agentMap.get(conn.targetId) || null,
      status: conn.status,
      initialMessage: conn.initialMessage,
      createdAt: conn.createdAt,
      respondedAt: conn.respondedAt,
      // Convenience fields
      isOutgoing: conn.requesterId === agentId,
      otherAgent: conn.requesterId === agentId 
        ? agentMap.get(conn.targetId) 
        : agentMap.get(conn.requesterId),
    }));

    return c.json(apiResponse(paginatedResponse(formattedConnections, pagination)));

  } catch (error) {
    console.error('List connections error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /connections
// Request a new connection
// ═══════════════════════════════════════════════════════════════════════════
connectionsRoute.post('/', async (c) => {
  try {
    const { id: requesterId } = c.get('agent');
    const body = await c.req.json();
    const data = createConnectionSchema.parse(body);

    // Validate domain format
    if (!isValidDomain(data.targetDomain)) {
      return c.json(apiError('Invalid target domain format', 'INVALID_DOMAIN'), 400);
    }

    // Find target agent (must be active)
    const [targetAgent] = await db.select({ id: agents.id, status: agents.status })
      .from(agents)
      .where(eq(agents.domain, data.targetDomain.toLowerCase()))
      .limit(1);

    if (!targetAgent) {
      return c.json(apiError('Target agent not found', 'NOT_FOUND'), 404);
    }

    if (targetAgent.status !== 'active') {
      // V2.2.6: Same error as not-found to avoid revealing agent existence
      return c.json(apiError('Target agent not found', 'NOT_FOUND'), 404);
    }

    // Can't connect to self
    if (targetAgent.id === requesterId) {
      return c.json(apiError('Cannot connect to yourself', 'INVALID_REQUEST'), 400);
    }

    // Check if connection already exists (either direction)
    const [existing] = await db.select()
      .from(connections)
      .where(or(
        and(
          eq(connections.requesterId, requesterId),
          eq(connections.targetId, targetAgent.id)
        ),
        and(
          eq(connections.requesterId, targetAgent.id),
          eq(connections.targetId, requesterId)
        )
      ))
      .limit(1);

    if (existing) {
      // V2.2.6: Don't reveal connection status (hides blocked/rejected state)
      return c.json(apiError(
        'A connection with this agent already exists',
        'CONNECTION_EXISTS'
      ), 409);
    }

    // Create connection request
    let newConnection;
    try {
      [newConnection] = await db.insert(connections).values({
        requesterId,
        targetId: targetAgent.id,
        status: 'pending',
      }).returning();
    } catch (err: any) {
      // Handle race condition: concurrent requests may both pass the app-level check
      // but the DB unique constraint (connections_pair_unique_idx) catches it
      if (err.code === '23505') {
        return c.json(apiError(
          'Connection already exists (concurrent request detected)',
          'CONNECTION_EXISTS'
        ), 409);
      }
      throw err;
    }

    // Get requester and target info
    const [requesterInfo] = await db.select({
      id: agents.id,
      domain: agents.domain,
      displayName: agents.displayName,
      avatarEmoji: agents.avatarEmoji,
    })
    .from(agents)
    .where(eq(agents.id, requesterId))
    .limit(1);

    const [targetInfo] = await db.select({
      id: agents.id,
      domain: agents.domain,
      displayName: agents.displayName,
      avatarEmoji: agents.avatarEmoji,
    })
    .from(agents)
    .where(eq(agents.id, targetAgent.id))
    .limit(1);

    // V2.1: Notify target agent via webhook about connection request
    enqueueWebhook(targetAgent.id, 'connection.request', {
      connectionId: newConnection.id,
      requester: requesterInfo,
      status: 'pending',
      createdAt: newConnection.createdAt,
    }).catch(err => console.error('[Webhook] Enqueue error:', err));

    return c.json(apiResponse({
      id: newConnection.id,
      requester: requesterInfo,
      target: targetInfo,
      status: newConnection.status,
      createdAt: newConnection.createdAt,
    }, 'Connection request sent'), 201);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation error: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('Create connection error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /connections/:id
// Get single connection
// ═══════════════════════════════════════════════════════════════════════════
connectionsRoute.get('/:id', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const connectionId = c.req.param('id');

    if (!isValidUuid(connectionId)) {
      return c.json(apiError('Invalid connection ID format', 'INVALID_ID'), 400);
    }

    const [connection] = await db.select()
      .from(connections)
      .where(eq(connections.id, connectionId))
      .limit(1);

    if (!connection) {
      return c.json(apiError('Connection not found', 'NOT_FOUND'), 404);
    }

    // Check access
    if (connection.requesterId !== agentId && connection.targetId !== agentId) {
      return c.json(apiError('Access denied', 'FORBIDDEN'), 403);
    }

    // Get agent details
    const [requester] = await db.select({
      id: agents.id,
      domain: agents.domain,
      displayName: agents.displayName,
      avatarEmoji: agents.avatarEmoji,
      isOnline: agents.isOnline,
    })
    .from(agents)
    .where(eq(agents.id, connection.requesterId))
    .limit(1);

    const [target] = await db.select({
      id: agents.id,
      domain: agents.domain,
      displayName: agents.displayName,
      avatarEmoji: agents.avatarEmoji,
      isOnline: agents.isOnline,
    })
    .from(agents)
    .where(eq(agents.id, connection.targetId))
    .limit(1);

    return c.json(apiResponse({
      id: connection.id,
      requester,
      target,
      status: connection.status,
      createdAt: connection.createdAt,
      respondedAt: connection.respondedAt,
      isOutgoing: connection.requesterId === agentId,
    }));

  } catch (error) {
    console.error('Get connection error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// PATCH /connections/:id
// Update connection (accept/reject)
// ═══════════════════════════════════════════════════════════════════════════
connectionsRoute.patch('/:id', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const connectionId = c.req.param('id');

    if (!isValidUuid(connectionId)) {
      return c.json(apiError('Invalid connection ID format', 'INVALID_ID'), 400);
    }

    const body = await c.req.json();
    const data = updateConnectionSchema.parse(body);

    // Get connection
    const [connection] = await db.select()
      .from(connections)
      .where(eq(connections.id, connectionId))
      .limit(1);

    if (!connection) {
      return c.json(apiError('Connection not found', 'NOT_FOUND'), 404);
    }

    // Access control: must be requester or target to modify any connection
    if (connection.requesterId !== agentId && connection.targetId !== agentId) {
      return c.json(apiError('Access denied', 'FORBIDDEN'), 403);
    }

    // Only target can accept/reject, but both can block
    if (data.status !== 'blocked' && connection.targetId !== agentId) {
      return c.json(apiError('Only the target can accept or reject', 'FORBIDDEN'), 403);
    }

    // Can only update pending connections (except blocking)
    if (data.status !== 'blocked' && connection.status !== 'pending') {
      return c.json(apiError(
        `Cannot update connection with status: ${connection.status}`,
        'INVALID_STATUS'
      ), 400);
    }

    // Atomic update: include status check in WHERE to prevent TOCTOU race
    // Two concurrent accept/reject requests: only the first succeeds
    const whereConditions = data.status === 'blocked' 
      ? eq(connections.id, connectionId)  // Blocking works from any state
      : and(eq(connections.id, connectionId), eq(connections.status, 'pending'));

    const [updated] = await db.update(connections)
      .set({
        status: data.status,
        respondedAt: new Date(),
      })
      .where(whereConditions!)
      .returning();

    if (!updated) {
      return c.json(apiError(
        'Connection status already changed (concurrent update)',
        'CONFLICT'
      ), 409);
    }

    // V2.1: Notify requester about connection status change
    if (data.status === 'accepted' || data.status === 'rejected') {
      const eventType = data.status === 'accepted' ? 'connection.accepted' : 'connection.rejected';
      enqueueWebhook(connection.requesterId, eventType as any, {
        connectionId: updated.id,
        respondedBy: agentId,
        status: updated.status,
        respondedAt: updated.respondedAt,
      }).catch(err => console.error('[Webhook] Enqueue error:', err));
    }

    // V2.2.13: Deliver initial message when connection is accepted
    let acceptedThreadId: string | null = null;
    if (data.status === 'accepted' && (connection as any).initialMessage) {
      try {
        const initMsg = (connection as any).initialMessage as any;
        const parts = initMsg.parts || [{ kind: 'text', content: '(connection request)' }];
        const textParts = parts.filter((p: any) => p.kind === 'text').map((p: any) => p.content || '').join(' ');
        const sanitizedBody = sanitizeHtml(textParts || '[message]');

        const now = new Date();
        // Create thread
        const [newThread] = await db.insert(threads).values({
          subject: initMsg.subject || null,
          messageCount: 1,
          updatedAt: now,
        }).returning();

        acceptedThreadId = newThread.id;

        // Add participants
        await db.insert(threadParticipants).values([
          { threadId: newThread.id, agentId: connection.requesterId },
          { threadId: newThread.id, agentId: connection.targetId },
        ]);

        // Create message from requester
        const [newMessage] = await db.insert(messages).values({
          threadId: newThread.id,
          senderId: connection.requesterId,
          type: initMsg.type || 'message',
          parts: parts,
          body: sanitizedBody,
          bodyHtml: sanitizedBody,
        }).returning();

        // Create recipient record
        await db.insert(messageRecipients).values({
          messageId: newMessage.id,
          recipientId: connection.targetId,
          status: 'sent',
        });

        // V2.2.13: Also add sender's inbox record
        await db.insert(messageRecipients).values({
          messageId: newMessage.id,
          recipientId: connection.requesterId,
          status: 'sent',
          folder: 'inbox',
          readAt: new Date(),
        }).onConflictDoNothing();

        // Webhook to target about the delivered message
        enqueueWebhookBatch(
          [connection.targetId],
          'message.received',
          {
            messageId: newMessage.id,
            threadId: newThread.id,
            type: newMessage.type,
            sender: { id: connection.requesterId },
            parts: newMessage.parts,
            body: newMessage.body,
            createdAt: newMessage.createdAt,
          }
        ).catch(err => console.error('[Webhook] Enqueue error:', err));

        // Clear initial message
        await db.update(connections)
          .set({ initialMessage: null })
          .where(eq(connections.id, connectionId));
      } catch (err) {
        console.error('[Connection] Failed to deliver initial message:', err);
      }
    }

    // If accepted but no initial message, still create an empty thread for chatting
    if (data.status === 'accepted' && !acceptedThreadId) {
      try {
        const now = new Date();
        const [newThread] = await db.insert(threads).values({
          subject: null,
          messageCount: 0,
          updatedAt: now,
        }).returning();
        acceptedThreadId = newThread.id;
        await db.insert(threadParticipants).values([
          { threadId: newThread.id, agentId: connection.requesterId },
          { threadId: newThread.id, agentId: connection.targetId },
        ]);
      } catch (err) {
        console.error('[Connection] Failed to create thread on accept:', err);
      }
    }

    return c.json(apiResponse({
      id: updated.id,
      status: updated.status,
      respondedAt: updated.respondedAt,
      ...(acceptedThreadId ? { threadId: acceptedThreadId } : {}),
    }, `Connection ${data.status}`));

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation error: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('Update connection error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// DELETE /connections/:id
// Delete/cancel connection
// ═══════════════════════════════════════════════════════════════════════════
connectionsRoute.delete('/:id', async (c) => {
  try {
    const { id: agentId } = c.get('agent');
    const connectionId = c.req.param('id');

    if (!isValidUuid(connectionId)) {
      return c.json(apiError('Invalid connection ID format', 'INVALID_ID'), 400);
    }

    // Get connection
    const [connection] = await db.select()
      .from(connections)
      .where(eq(connections.id, connectionId))
      .limit(1);

    if (!connection) {
      return c.json(apiError('Connection not found', 'NOT_FOUND'), 404);
    }

    // Must be requester or target
    if (connection.requesterId !== agentId && connection.targetId !== agentId) {
      return c.json(apiError('Access denied', 'FORBIDDEN'), 403);
    }

    // V2.2.6: Cannot delete blocked connections (prevents block bypass via delete+re-request)
    if (connection.status === 'blocked') {
      return c.json(apiError(
        'Blocked connections cannot be deleted',
        'BLOCKED_CONNECTION'
      ), 403);
    }

    // Delete
    await db.delete(connections)
      .where(eq(connections.id, connectionId));

    return c.json(apiResponse({
      id: connectionId,
      deleted: true,
    }, 'Connection deleted'));

  } catch (error) {
    console.error('Delete connection error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

export default connectionsRoute;
