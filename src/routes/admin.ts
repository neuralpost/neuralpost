import { Hono } from 'hono';
import { timingSafeEqual } from 'crypto';
import { runCleanup, getDbStats } from '../services/cleanup';
import { getWebhookStats, getWebhookLogs } from '../services/webhook';
import { apiResponse, apiError, isValidUuid } from '../utils';

const adminRoute = new Hono();

// Anti-brute-force: track failed admin auth attempts per IP
const adminAuthFailures = new Map<string, { count: number; blockedUntil: number }>();
const ADMIN_MAX_FAILURES = 5;
const ADMIN_BLOCK_DURATION = 15 * 60 * 1000; // 15 minutes

// V2.2.5: Periodic cleanup to prevent memory leak from accumulated failure entries
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of adminAuthFailures) {
    if (entry.blockedUntil > 0 && entry.blockedUntil < now) {
      adminAuthFailures.delete(ip);
    } else if (entry.count > 0 && entry.blockedUntil === 0) {
      // Stale non-blocked entries older than block duration
      adminAuthFailures.delete(ip);
    }
  }
}, 5 * 60 * 1000).unref(); // Every 5 minutes

// ═══════════════════════════════════════════════════════════════════════════
// Simple admin auth - check ADMIN_KEY from env
// ═══════════════════════════════════════════════════════════════════════════

const ADMIN_KEY = process.env.ADMIN_KEY;

if (!ADMIN_KEY && process.env.NODE_ENV === 'production') {
  console.error('FATAL: ADMIN_KEY environment variable is required in production');
  process.exit(1);
}

// V2.2.5: Validate admin key strength
if (ADMIN_KEY && ADMIN_KEY.length < 20 && process.env.NODE_ENV === 'production') {
  console.error('FATAL: ADMIN_KEY must be at least 20 characters in production');
  process.exit(1);
}

if (!ADMIN_KEY) {
  console.warn('⚠️  ADMIN_KEY not set — using insecure default. Do NOT use in production.');
}

const effectiveAdminKey = ADMIN_KEY || 'admin-dev-key';

adminRoute.use('/*', async (c, next) => {
  // V2.2.10: Only trust proxy headers when TRUST_PROXY is set (matches rateLimit.ts)
  // Without this, attackers can spoof X-Forwarded-For to bypass brute-force lockout
  let ip = 'unknown';
  if (process.env.TRUST_PROXY === 'true') {
    const xff = c.req.header('x-forwarded-for');
    if (xff) {
      const ips = xff.split(',').map(s => s.trim()).filter(Boolean);
      ip = ips[ips.length - 1] || 'unknown';
    } else {
      ip = c.req.header('x-real-ip') || 'unknown';
    }
  } else {
    ip = c.req.header('x-real-ip') || 'direct';
  }

  // Check if IP is blocked from too many failed attempts
  const failure = adminAuthFailures.get(ip);
  if (failure && failure.blockedUntil > Date.now()) {
    return c.json(apiError('Too many failed attempts. Try again later.', 'RATE_LIMITED'), 429);
  }

  const authHeader = c.req.header('Authorization');

  if (!authHeader) {
    return c.json(apiError('Admin access required', 'FORBIDDEN'), 403);
  }

  // Timing-safe comparison to prevent brute-force via response timing
  const expected = `Bearer ${effectiveAdminKey}`;
  try {
    const match = authHeader.length === expected.length &&
      timingSafeEqual(Buffer.from(authHeader), Buffer.from(expected));
    if (!match) {
      // Track failure
      const existing = adminAuthFailures.get(ip) || { count: 0, blockedUntil: 0 };
      existing.count += 1;
      if (existing.count >= ADMIN_MAX_FAILURES) {
        existing.blockedUntil = Date.now() + ADMIN_BLOCK_DURATION;
        console.warn(`[Admin] IP ${ip} blocked for ${ADMIN_BLOCK_DURATION / 60000}min after ${existing.count} failed attempts`);
      }
      adminAuthFailures.set(ip, existing);
      return c.json(apiError('Admin access required', 'FORBIDDEN'), 403);
    }
  } catch {
    return c.json(apiError('Admin access required', 'FORBIDDEN'), 403);
  }

  // Success — clear failures for this IP
  adminAuthFailures.delete(ip);
  return next();
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /admin/stats
// Database stats overview
// ═══════════════════════════════════════════════════════════════════════════

adminRoute.get('/stats', async (c) => {
  try {
    const stats = await getDbStats();
    return c.json(apiResponse(stats));
  } catch (error) {
    console.error('Stats error:', error);
    return c.json(apiError('Failed to get stats', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /admin/cleanup
// Trigger manual cleanup
// ═══════════════════════════════════════════════════════════════════════════

adminRoute.post('/cleanup', async (c) => {
  try {
    const result = await runCleanup();
    return c.json(apiResponse(result, 'Cleanup completed'));
  } catch (error) {
    console.error('Cleanup error:', error);
    return c.json(apiError('Cleanup failed', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /admin/webhook-stats
// V2.1: Webhook delivery statistics
// ═══════════════════════════════════════════════════════════════════════════

adminRoute.get('/webhook-stats', async (c) => {
  try {
    const stats = await getWebhookStats();
    return c.json(apiResponse(stats));
  } catch (error) {
    console.error('Webhook stats error:', error);
    return c.json(apiError('Failed to get webhook stats', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /admin/webhook-logs
// V2.1: Webhook delivery logs (optional ?agentId= filter, ?limit=)
// ═══════════════════════════════════════════════════════════════════════════

adminRoute.get('/webhook-logs', async (c) => {
  try {
    const agentId = c.req.query('agentId');
    // Validate agentId is a valid UUID if provided
    if (agentId && !isValidUuid(agentId)) {
      return c.json(apiError('Invalid agentId format', 'INVALID_PARAMS'), 400);
    }
    const limit = Math.min(Math.max(parseInt(c.req.query('limit') || '50', 10) || 50, 1), 200);
    const logs = await getWebhookLogs(agentId, limit);
    return c.json(apiResponse(logs));
  } catch (error) {
    console.error('Webhook logs error:', error);
    return c.json(apiError('Failed to get webhook logs', 'SERVER_ERROR'), 500);
  }
});

export default adminRoute;
