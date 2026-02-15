import { Hono } from 'hono';
import { z } from 'zod';
import { db } from '../db';
import { agents, connections } from '../db/schema';
import { eq, like, or, and, sql, inArray } from 'drizzle-orm';
import { authMiddleware } from '../middleware/auth';
import { apiResponse, apiError, parsePagination, paginatedResponse, isPublicUrl, generateWebhookSecret, encryptWebhookSecret, isValidUuid } from '../utils';

const agentsRoute = new Hono();

// Apply auth middleware to all routes
agentsRoute.use('/*', authMiddleware);

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION SCHEMAS
// ═══════════════════════════════════════════════════════════════════════════

const updateProfileSchema = z.object({
  displayName: z.string().min(1).max(255).nullable().optional(),
  avatarEmoji: z.string().max(10).regex(/^[\p{Emoji_Presentation}\p{Extended_Pictographic}\u200d\uFE0F\u20E3]*$/u, 'Must be emoji characters only').nullable().optional(),
  avatarUrl: z.string().url().max(500).nullable().optional(),
  bio: z.string().max(1000).nullable().optional(),
  capabilities: z.array(z.string().max(100)).max(50).nullable().optional(),
  // V2: Rich profile
  profile: z.object({
    description: z.string().max(2000).optional(),
    skills: z.array(z.string().max(50)).max(20).optional(),
    accepts: z.array(z.enum(['text', 'data', 'file'])).optional(),
    language: z.array(z.string().max(10)).max(10).optional(),
    metadata: z.record(z.unknown()).optional().refine(
      (val) => !val || JSON.stringify(val).length <= 10_000,
      { message: 'metadata must be under 10KB when serialized' }
    ),
  }).nullable().optional(),
  // V2: Webhook URL
  webhookUrl: z.string().url().max(2048).nullable().optional(),
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /agents/me
// Get current agent's profile
// ═══════════════════════════════════════════════════════════════════════════
agentsRoute.get('/me', async (c) => {
  try {
    const { id } = c.get('agent');

    const [agent] = await db.select({
      id: agents.id,
      domain: agents.domain,
      serverDomain: agents.serverDomain,
      displayName: agents.displayName,
      avatarEmoji: agents.avatarEmoji,
      bio: agents.bio,
      capabilities: agents.capabilities,
      profile: agents.profile,
      webhookUrl: agents.webhookUrl,
      walletAddress: agents.walletAddress,
      walletCustodyType: agents.walletCustodyType,
      walletCustody: agents.walletCustodyType,
      chainId: agents.chainId,
      onChainAgentId: agents.onChainAgentId,
      registrationTxHash: agents.registrationTxHash,
      x402Enabled: agents.x402Enabled,
      messagePrice: agents.messagePrice,
      status: agents.status,
      isOnline: agents.isOnline,
      createdAt: agents.createdAt,
      lastSeenAt: agents.lastSeenAt,
    })
    .from(agents)
    .where(eq(agents.id, id))
    .limit(1);

    if (!agent) {
      return c.json(apiError('Agent not found', 'NOT_FOUND'), 404);
    }

    return c.json(apiResponse(agent));

  } catch (error) {
    console.error('Get me error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// PATCH /agents/me
// Update current agent's profile
// ═══════════════════════════════════════════════════════════════════════════
agentsRoute.patch('/me', async (c) => {
  try {
    const { id } = c.get('agent');
    const body = await c.req.json();
    const data = updateProfileSchema.parse(body);

    // V2: Validate webhook URL (anti-SSRF) when updating
    if (data.webhookUrl && !isPublicUrl(data.webhookUrl)) {
      return c.json(apiError(
        'Webhook URL must be a public HTTPS URL (no localhost/private IPs)',
        'INVALID_WEBHOOK_URL'
      ), 400);
    }

    // V2.1.2: Manage webhook secret when webhookUrl changes
    let newWebhookSecret: string | null = null;
    const updateData: Record<string, unknown> = { ...data };

    if (data.webhookUrl) {
      // Check if agent already has a webhook secret
      const [current] = await db.select({ webhookSecret: agents.webhookSecret })
        .from(agents).where(eq(agents.id, id)).limit(1);
      
      if (!current?.webhookSecret) {
        // Generate new secret, encrypt for storage, return once to user
        newWebhookSecret = generateWebhookSecret();
        updateData.webhookSecret = encryptWebhookSecret(newWebhookSecret);
      }
    } else if (data.webhookUrl === null) {
      // Clearing webhookUrl — also clear the secret
      updateData.webhookSecret = null;
    }

    const [updated] = await db.update(agents)
      .set(updateData)
      .where(eq(agents.id, id))
      .returning({
        id: agents.id,
        domain: agents.domain,
        serverDomain: agents.serverDomain,
        displayName: agents.displayName,
        avatarEmoji: agents.avatarEmoji,
        avatarUrl: agents.avatarUrl,
        bio: agents.bio,
        capabilities: agents.capabilities,
        profile: agents.profile,
        webhookUrl: agents.webhookUrl,
        status: agents.status,
        isOnline: agents.isOnline,
        createdAt: agents.createdAt,
        lastSeenAt: agents.lastSeenAt,
      });

    return c.json(apiResponse({
      ...updated,
      // Include webhook secret ONLY when newly generated (returned once!)
      ...(newWebhookSecret && { webhookSecret: newWebhookSecret }),
    }, newWebhookSecret 
      ? 'Profile updated. Save your webhook secret — it will not be shown again!'
      : 'Profile updated'
    ));

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation error: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('Update me error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /agents/search
// Search for agents by domain or display name
// ═══════════════════════════════════════════════════════════════════════════
agentsRoute.get('/search', async (c) => {
  try {
    const query = c.req.query('q') || '';
    const skill = c.req.query('skill');
    const online = c.req.query('online');
    const pagination = parsePagination(c.req.query());

    // Need at least a text query or a skill filter
    if (query.length < 2 && !skill) {
      return c.json(apiError('Search query (min 2 chars) or skill filter required', 'INVALID_QUERY'), 400);
    }

    // Build conditions
    const conditions: any[] = [eq(agents.status, 'active')]; // Only show active agents

    // Text search on domain/name
    if (query.length >= 2) {
      const escapedQuery = query.toLowerCase().replace(/[%_\\]/g, '\\$&');
      const searchPattern = `%${escapedQuery}%`;
      conditions.push(
        or(
          like(agents.domain, searchPattern),
          sql`lower(${agents.displayName}) LIKE ${searchPattern}`
        )
      );
    }

    // V2: Skill filter — search in profile JSONB skills array
    if (skill) {
      conditions.push(
        sql`${agents.profile}::jsonb->'skills' ? ${skill.toLowerCase()}`
      );
    }

    // V2: Online filter
    if (online === 'true') {
      conditions.push(eq(agents.isOnline, true));
    }

    const results = await db.select({
      id: agents.id,
      domain: agents.domain,
      serverDomain: agents.serverDomain,
      displayName: agents.displayName,
      avatarEmoji: agents.avatarEmoji,
      bio: agents.bio,
      capabilities: agents.capabilities,
      profile: agents.profile,
      isOnline: agents.isOnline,
    })
    .from(agents)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .limit(pagination.limit)
    .offset(pagination.offset);

    return c.json(apiResponse(paginatedResponse(results, pagination)));

  } catch (error) {
    console.error('Search error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /agents/:id
// Get agent by ID or domain
// ═══════════════════════════════════════════════════════════════════════════
agentsRoute.get('/:identifier', async (c) => {
  try {
    const identifier = c.req.param('identifier');

    // Check if it's a UUID or domain
    const isUuid = isValidUuid(identifier);

    const [agent] = await db.select({
      id: agents.id,
      domain: agents.domain,
      displayName: agents.displayName,
      avatarEmoji: agents.avatarEmoji,
      avatarUrl: agents.avatarUrl,
      bio: agents.bio,
      capabilities: agents.capabilities,
      profile: agents.profile,
      isOnline: agents.isOnline,
      lastSeenAt: agents.lastSeenAt,
      chainId: agents.chainId,
      onChainAgentId: agents.onChainAgentId,
      walletAddress: agents.walletAddress,
      createdAt: agents.createdAt,
    })
    .from(agents)
    .where(and(
      isUuid ? eq(agents.id, identifier) : eq(agents.domain, identifier.toLowerCase()),
      eq(agents.status, 'active')
    ))
    .limit(1);

    if (!agent) {
      return c.json(apiError('Agent not found', 'NOT_FOUND'), 404);
    }

    return c.json(apiResponse(agent));

  } catch (error) {
    console.error('Get agent error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /agents/:id/connections
// Get agent's connections
// ═══════════════════════════════════════════════════════════════════════════
agentsRoute.get('/:id/connections', async (c) => {
  try {
    const { id: myId } = c.get('agent');
    const agentId = c.req.param('id');
    const status = c.req.query('status') || 'accepted';

    // Can only view own connections
    if (agentId !== myId) {
      return c.json(apiError('Cannot view other agent\'s connections', 'FORBIDDEN'), 403);
    }

    const pagination = parsePagination(c.req.query());

    // Get connections where agent is requester or target
    const connectionsList = await db.select({
      id: connections.id,
      status: connections.status,
      createdAt: connections.createdAt,
      respondedAt: connections.respondedAt,
      // Connected agent info
      connectedAgentId: sql<string>`
        CASE 
          WHEN ${connections.requesterId} = ${myId} THEN ${connections.targetId}
          ELSE ${connections.requesterId}
        END
      `,
    })
    .from(connections)
    .where(
      and(
        or(
          eq(connections.requesterId, myId),
          eq(connections.targetId, myId)
        ),
        eq(connections.status, status)
      )
    )
    .limit(pagination.limit)
    .offset(pagination.offset);

    // Fetch connected agent details
    const agentIds = connectionsList.map(c => c.connectedAgentId);
    const agentsMap = new Map();
    
    if (agentIds.length > 0) {
      const agentDetails = await db.select({
        id: agents.id,
        domain: agents.domain,
        displayName: agents.displayName,
        avatarEmoji: agents.avatarEmoji,
        isOnline: agents.isOnline,
      })
      .from(agents)
      .where(inArray(agents.id, agentIds));

      agentDetails.forEach(a => agentsMap.set(a.id, a));
    }

    const result = connectionsList.map(conn => ({
      id: conn.id,
      status: conn.status,
      createdAt: conn.createdAt,
      respondedAt: conn.respondedAt,
      agent: agentsMap.get(conn.connectedAgentId) || null,
    }));

    return c.json(apiResponse(paginatedResponse(result, pagination)));

  } catch (error) {
    console.error('Get connections error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// PATCH /agents/me/x402
// Configure x402 payment settings (per x402 V2 protocol)
// ═══════════════════════════════════════════════════════════════════════════
agentsRoute.patch('/me/x402', async (c) => {
  try {
    const { id } = c.get('agent');
    const body = await c.req.json();

    const schema = z.object({
      x402Enabled: z.boolean().optional(),
      messagePrice: z.string()
        .regex(/^\$?\d+(\.\d{1,6})?$/, 'Price must be a valid USD amount (e.g., "$0.001")')
        .optional()
        .nullable(),
    });

    const data = schema.parse(body);

    // Validate: if enabling x402, agent must have a wallet address
    if (data.x402Enabled === true) {
      const [agent] = await db.select({ walletAddress: agents.walletAddress })
        .from(agents).where(eq(agents.id, id)).limit(1);

      if (!agent?.walletAddress) {
        return c.json(apiError(
          'Wallet address required to enable x402. Register a wallet first via /v1/wallet/register',
          'WALLET_REQUIRED'
        ), 400);
      }
    }

    // Normalize price to $-prefixed format
    const updateData: Record<string, unknown> = {};
    if (data.x402Enabled !== undefined) updateData.x402Enabled = data.x402Enabled;
    if (data.messagePrice !== undefined) {
      if (data.messagePrice === null) {
        updateData.messagePrice = null;
      } else {
        const price = data.messagePrice.replace(/^\$/, '');
        updateData.messagePrice = `$${price}`;
      }
    }

    const [updated] = await db.update(agents)
      .set(updateData)
      .where(eq(agents.id, id))
      .returning({
        x402Enabled: agents.x402Enabled,
        messagePrice: agents.messagePrice,
        walletAddress: agents.walletAddress,
      });

    // Return x402 payment info in standard format
    const paymentInfo = getAgentPaymentInfo(updated);

    return c.json(apiResponse({
      x402Enabled: updated.x402Enabled,
      messagePrice: updated.messagePrice,
      walletAddress: updated.walletAddress,
      paymentRequirements: paymentInfo,
    }, 'x402 payment settings updated'));

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation error: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('Update x402 error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /agents/me/x402
// Get current x402 payment settings and payment requirements
// ═══════════════════════════════════════════════════════════════════════════
agentsRoute.get('/me/x402', async (c) => {
  try {
    const { id } = c.get('agent');

    const [agent] = await db.select({
      x402Enabled: agents.x402Enabled,
      messagePrice: agents.messagePrice,
      walletAddress: agents.walletAddress,
    })
    .from(agents)
    .where(eq(agents.id, id))
    .limit(1);

    if (!agent) {
      return c.json(apiError('Agent not found', 'NOT_FOUND'), 404);
    }

    const paymentInfo = getAgentPaymentInfo(agent);

    return c.json(apiResponse({
      x402Enabled: agent.x402Enabled,
      messagePrice: agent.messagePrice,
      walletAddress: agent.walletAddress,
      paymentRequirements: paymentInfo,
    }));

  } catch (error) {
    console.error('Get x402 error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

import { getAgentPaymentInfo } from '../middleware/x402-sdk';

export default agentsRoute;
