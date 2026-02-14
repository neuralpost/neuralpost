import { Context, Next } from 'hono';
import { db } from '../db';
import { agents } from '../db/schema';
import { eq } from 'drizzle-orm';
import { verifyToken, verifyApiKey, getApiKeyPrefix, apiError } from '../utils';

// ═══════════════════════════════════════════════════════════════════════════
// CONTEXT TYPES
// ═══════════════════════════════════════════════════════════════════════════

declare module 'hono' {
  interface ContextVariableMap {
    agent: {
      id: string;
      domain: string;
      displayName: string | null;
      avatarEmoji: string | null;
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// API KEY CACHE
// Simple in-memory cache for API key lookups
// ═══════════════════════════════════════════════════════════════════════════

interface CachedAgent {
  id: string;
  domain: string;
  displayName: string | null;
  avatarEmoji: string | null;
  apiKeyHash: string;
  status: string | null;
  cachedAt: number;
}

const apiKeyCache = new Map<string, CachedAgent>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function getCachedAgent(prefix: string): CachedAgent | null {
  const cached = apiKeyCache.get(prefix);
  if (!cached) return null;
  
  if (Date.now() - cached.cachedAt > CACHE_TTL) {
    apiKeyCache.delete(prefix);
    return null;
  }
  
  return cached;
}

function cacheAgent(prefix: string, agent: CachedAgent): void {
  // Limit cache size
  if (apiKeyCache.size > 10000) {
    const firstKey = apiKeyCache.keys().next().value;
    if (firstKey) apiKeyCache.delete(firstKey);
  }
  
  apiKeyCache.set(prefix, { ...agent, cachedAt: Date.now() });
}

/**
 * Invalidate cached agent by API key prefix.
 * Called after key rotation or status changes to prevent stale cache.
 */
export function invalidateAuthCache(prefix: string): void {
  apiKeyCache.delete(prefix);
}

/**
 * V2.2.4: Invalidate cached auth entries by agent ID
 * Used by cleanup service when marking agents inactive/suspended
 */
export function invalidateAuthCacheByAgentId(agentId: string): void {
  for (const [prefix, cached] of apiKeyCache) {
    if (cached.id === agentId) {
      apiKeyCache.delete(prefix);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// LAST SEEN THROTTLE
// Only update lastSeenAt every 5 minutes to reduce DB writes
// ═══════════════════════════════════════════════════════════════════════════

const lastSeenUpdates = new Map<string, number>();
const LAST_SEEN_THROTTLE = 5 * 60 * 1000; // 5 minutes

// Periodic cleanup: remove stale entries every 10 minutes
setInterval(() => {
  const cutoff = Date.now() - LAST_SEEN_THROTTLE * 2;
  for (const [key, ts] of lastSeenUpdates) {
    if (ts < cutoff) lastSeenUpdates.delete(key);
  }
}, 10 * 60 * 1000).unref();

function shouldUpdateLastSeen(agentId: string): boolean {
  const now = Date.now();
  const lastUpdate = lastSeenUpdates.get(agentId) || 0;
  if (now - lastUpdate > LAST_SEEN_THROTTLE) {
    lastSeenUpdates.set(agentId, now);
    return true;
  }
  return false;
}

// ═══════════════════════════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// Supports both API Key and JWT authentication
// ═══════════════════════════════════════════════════════════════════════════

export async function authMiddleware(c: Context, next: Next) {
  const authHeader = c.req.header('Authorization');
  
  if (!authHeader) {
    return c.json(apiError('Authorization header required', 'UNAUTHORIZED'), 401);
  }

  // Must be Bearer token
  if (!authHeader.startsWith('Bearer ')) {
    return c.json(apiError('Invalid authorization format', 'UNAUTHORIZED'), 401);
  }

  const token = authHeader.slice(7);

  // Try JWT first (faster validation)
  const jwtPayload = verifyToken(token);
  if (jwtPayload) {
    // Fetch minimal agent info for context
    const [agent] = await db.select({
      id: agents.id,
      domain: agents.domain,
      displayName: agents.displayName,
      avatarEmoji: agents.avatarEmoji,
      status: agents.status,
      tokenInvalidBefore: agents.tokenInvalidBefore,
    })
    .from(agents)
    .where(eq(agents.id, jwtPayload.agentId))
    .limit(1);

    if (agent) {
      // Verify agent is active
      if (agent.status !== 'active') {
        return c.json(apiError('Account is suspended or deactivated', 'ACCOUNT_INACTIVE'), 403);
      }
      // V2.2.6: Reject JWTs issued before key rotation (token revocation)
      if (agent.tokenInvalidBefore && jwtPayload.iat) {
        const invalidBefore = Math.floor(agent.tokenInvalidBefore.getTime() / 1000);
        if (jwtPayload.iat < invalidBefore) {
          return c.json(apiError('Token has been revoked (key rotation)', 'TOKEN_REVOKED'), 401);
        }
      }
      c.set('agent', {
        id: agent.id,
        domain: agent.domain,
        displayName: agent.displayName,
        avatarEmoji: agent.avatarEmoji,
      });

      // V2.2.8: Update lastSeenAt for JWT users too (throttled)
      if (shouldUpdateLastSeen(agent.id)) {
        db.update(agents)
          .set({ lastSeenAt: new Date(), isOnline: true })
          .where(eq(agents.id, agent.id))
          .catch(() => {}); // fire-and-forget
      }

      return next();
    }
  }

  // Try API Key (sk_xxx format)
  if (token.startsWith('sk_')) {
    const prefix = getApiKeyPrefix(token);
    
    // Check cache first
    let cachedAgent = getCachedAgent(prefix);
    
    if (!cachedAgent) {
      // Find by prefix for faster lookup
      const [agent] = await db.select({
        id: agents.id,
        domain: agents.domain,
        displayName: agents.displayName,
        avatarEmoji: agents.avatarEmoji,
        apiKeyHash: agents.apiKeyHash,
        status: agents.status,
      })
      .from(agents)
      .where(eq(agents.apiKeyPrefix, prefix))
      .limit(1);

      if (agent) {
        cachedAgent = {
          id: agent.id,
          domain: agent.domain,
          displayName: agent.displayName,
          avatarEmoji: agent.avatarEmoji,
          apiKeyHash: agent.apiKeyHash,
          status: agent.status,
          cachedAt: Date.now(),
        };
        cacheAgent(prefix, cachedAgent);
      }
    }

    if (cachedAgent && verifyApiKey(token, cachedAgent.apiKeyHash)) {
      // Verify agent is active
      if (cachedAgent.status !== 'active') {
        return c.json(apiError('Account is suspended or deactivated', 'ACCOUNT_INACTIVE'), 403);
      }

      // Update last seen (throttled — every 5 min max)
      if (shouldUpdateLastSeen(cachedAgent.id)) {
        db.update(agents)
          .set({ lastSeenAt: new Date(), isOnline: true })
          .where(eq(agents.id, cachedAgent.id))
          .catch(() => {}); // fire-and-forget, don't block request
      }

      c.set('agent', {
        id: cachedAgent.id,
        domain: cachedAgent.domain,
        displayName: cachedAgent.displayName,
        avatarEmoji: cachedAgent.avatarEmoji,
      });
      
      return next();
    }
  }

  return c.json(apiError('Invalid or expired token', 'UNAUTHORIZED'), 401);
}

// ═══════════════════════════════════════════════════════════════════════════
// OPTIONAL AUTH MIDDLEWARE
// Sets agent context if authenticated, but doesn't require it
// ═══════════════════════════════════════════════════════════════════════════

export async function optionalAuthMiddleware(c: Context, next: Next) {
  const authHeader = c.req.header('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next();
  }

  const token = authHeader.slice(7);

  // Try JWT
  const jwtPayload = verifyToken(token);
  if (jwtPayload) {
    const [agent] = await db.select({
      id: agents.id,
      domain: agents.domain,
      displayName: agents.displayName,
      avatarEmoji: agents.avatarEmoji,
      status: agents.status,
      tokenInvalidBefore: agents.tokenInvalidBefore,
    })
    .from(agents)
    .where(eq(agents.id, jwtPayload.agentId))
    .limit(1);

    if (agent) {
      // V2.2.9: Silently skip suspended/inactive agents in optional auth
      if (agent.status !== 'active') {
        return next(); // Treat as unauthenticated
      }
      // V2.2.6: Skip revoked tokens silently in optional auth
      if (agent.tokenInvalidBefore && jwtPayload.iat) {
        const invalidBefore = Math.floor(agent.tokenInvalidBefore.getTime() / 1000);
        if (jwtPayload.iat < invalidBefore) {
          return next(); // Silently treat as unauthenticated
        }
      }
      c.set('agent', agent);
    }
  }

  // Try API Key
  if (token.startsWith('sk_')) {
    const prefix = getApiKeyPrefix(token);
    let cachedAgent = getCachedAgent(prefix);
    
    // DB fallback for uncached API keys
    if (!cachedAgent) {
      const [agent] = await db.select({
        id: agents.id,
        domain: agents.domain,
        displayName: agents.displayName,
        avatarEmoji: agents.avatarEmoji,
        apiKeyHash: agents.apiKeyHash,
        status: agents.status,
      })
      .from(agents)
      .where(eq(agents.apiKeyPrefix, prefix))
      .limit(1);

      if (agent) {
        cachedAgent = {
          id: agent.id,
          domain: agent.domain,
          displayName: agent.displayName,
          avatarEmoji: agent.avatarEmoji,
          apiKeyHash: agent.apiKeyHash,
          status: agent.status,
          cachedAt: Date.now(),
        };
        cacheAgent(prefix, cachedAgent);
      }
    }

    if (cachedAgent && cachedAgent.status === 'active' && verifyApiKey(token, cachedAgent.apiKeyHash)) {
      c.set('agent', {
        id: cachedAgent.id,
        domain: cachedAgent.domain,
        displayName: cachedAgent.displayName,
        avatarEmoji: cachedAgent.avatarEmoji,
      });
    }
  }

  return next();
}
