import { Context, Next } from 'hono';
import { createHash } from 'crypto';
import { apiError } from '../utils';

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const rateLimitStore = new Map<string, RateLimitEntry>();
const MAX_RATE_LIMIT_ENTRIES = 50_000; // Cap to prevent memory exhaustion

const RATE_LIMITS: Record<string, { limit: number; window: number }> = {
  '/v1/auth/register': { limit: 25, window: 60_000 },
  '/v1/auth/token': { limit: 50, window: 60_000 },
  '/v1/messages': { limit: 300, window: 60_000 },
  '/v1/agents/search': { limit: 150, window: 60_000 },
  'default': { limit: 500, window: 60_000 },
};

export function rateLimiter(customLimit?: number, customWindow?: number) {
  return async (c: Context, next: Next) => {
    const token = c.req.header('Authorization')?.slice(7) || '';
    
    // IP extraction: X-Forwarded-For is only trusted if TRUST_PROXY is set
    // Without this, attackers can spoof X-Forwarded-For to bypass rate limits
    let ip = 'unknown';
    if (process.env.TRUST_PROXY === 'true') {
      // Behind trusted proxy: use rightmost client IP (last proxy-appended)
      const xff = c.req.header('x-forwarded-for');
      if (xff) {
        const ips = xff.split(',').map(s => s.trim()).filter(Boolean);
        ip = ips[ips.length - 1] || 'unknown';  // rightmost = most trustworthy
      } else {
        ip = c.req.header('x-real-ip') || 'unknown';
      }
    } else {
      // Direct connection or untrusted proxy: use x-real-ip as hint only
      ip = c.req.header('x-real-ip') || 'direct';
    }
    
    // Differentiate clients: API keys by prefix, JWTs by hash, fallback to IP
    let clientId: string;
    if (token.startsWith('sk_')) {
      clientId = `key:${token.slice(0, 15)}`;
    } else if (token.startsWith('ey')) {
      // JWT tokens all start with 'ey' — hash to get unique per-user key
      clientId = `jwt:${createHash('sha256').update(token).digest('hex').slice(0, 16)}`;
    } else {
      clientId = `ip:${ip}`;
    }
    
    const path = c.req.path;
    const config = RATE_LIMITS[path] || RATE_LIMITS['default'];
    const limit = customLimit || config.limit;
    const window = customWindow || config.window;
    
    const key = `${clientId}:${path}`;
    const now = Date.now();
    
    let entry = rateLimitStore.get(key);
    
    if (!entry || entry.resetAt < now) {
      // Evict expired entries if store is getting large
      if (rateLimitStore.size >= MAX_RATE_LIMIT_ENTRIES) {
        for (const [k, v] of rateLimitStore) {
          if (v.resetAt < now) rateLimitStore.delete(k);
        }
        // If still over limit after cleanup, drop oldest entries
        if (rateLimitStore.size >= MAX_RATE_LIMIT_ENTRIES) {
          const toDelete = rateLimitStore.size - MAX_RATE_LIMIT_ENTRIES + 1000;
          let deleted = 0;
          for (const k of rateLimitStore.keys()) {
            if (deleted >= toDelete) break;
            rateLimitStore.delete(k);
            deleted++;
          }
        }
      }
      entry = { count: 0, resetAt: now + window };
      rateLimitStore.set(key, entry);
    }
    
    if (entry.count >= limit) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      c.header('X-RateLimit-Limit', limit.toString());
      c.header('X-RateLimit-Remaining', '0');
      c.header('Retry-After', retryAfter.toString());
      return c.json(apiError(`Rate limit exceeded. Try again in ${retryAfter} seconds.`, 'RATE_LIMIT_EXCEEDED'), 429);
    }
    
    entry.count++;
    c.header('X-RateLimit-Limit', limit.toString());
    c.header('X-RateLimit-Remaining', (limit - entry.count).toString());
    
    return next();
  };
}

// V2.1.3: Track interval for graceful shutdown
export const rateLimitCleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore.entries()) {
    if (entry.resetAt < now) rateLimitStore.delete(key);
  }
}, 60_000);
