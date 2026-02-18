import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { serve } from '@hono/node-server';
import { readFileSync, existsSync } from 'fs';
import { readFile } from 'fs/promises';
import { join, resolve } from 'path';
import 'dotenv/config';

// Import routes
import auth from './routes/auth';
import walletAuth from './routes/wallet';
import agentsRoute from './routes/agents';
import messagesRoute from './routes/messages';
import threadsRoute from './routes/threads';
import connectionsRoute from './routes/connections';
import adminRoute from './routes/admin';
import a2aRoute from './routes/a2a';
import discoverRoute from './routes/discover';
import uploadRoute from './routes/upload';
import { startCleanupScheduler, stopCleanupScheduler } from './services/cleanup';
import { startWebhookProcessor, stopWebhookProcessor } from './services/webhook';
import { stopScanCachePrune } from './services/erc8004scan';
import { rateLimiter, rateLimitCleanupInterval } from './middleware/rateLimit';
import { x402MessageMiddleware, x402A2AMiddleware } from './middleware/x402';

// Create app
const app = new Hono();

// ═══════════════════════════════════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════════════

// CORS — V2.1.3: Restrict origin in production via ALLOWED_ORIGINS env
const corsOrigin = process.env.NODE_ENV === 'production' && process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : '*';

if (process.env.NODE_ENV === 'production' && corsOrigin === '*') {
  console.warn('[Security] WARNING: ALLOWED_ORIGINS not set in production — CORS allows all origins. Set ALLOWED_ORIGINS=https://yourdomain.com');
}

app.use('*', cors({
  origin: corsOrigin,
  allowMethods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'PAYMENT-SIGNATURE', 'X-PAYMENT'],
  exposeHeaders: ['X-Request-Id', 'PAYMENT-REQUIRED', 'PAYMENT-RESPONSE', 'X-PAYMENT-RESPONSE'],
  maxAge: 86400,
}));

// Logger (only for API routes)
// V2.2.1: Request body size limit (5MB default)
// Uses Hono's bodyLimit middleware which checks actual body size, not just Content-Length header
// This prevents bypass via chunked transfer encoding or missing Content-Length
import { bodyLimit } from 'hono/body-limit';
const MAX_BODY_SIZE = parseInt(process.env.MAX_BODY_SIZE || '5242880', 10); // 5MB
// File upload: separate path to avoid /v1 body limit (12MB for uploads)
app.use('/upload-api', bodyLimit({
  maxSize: 12 * 1024 * 1024,
  onError: (c) => c.json({
    success: false,
    error: { message: 'File too large (max 10MB)', code: 'PAYLOAD_TOO_LARGE' },
  }, 413),
}));
app.use('/upload-api', rateLimiter(100, 60_000)); // 100 uploads/min

// V2.2.1: Global body limit for all other /v1 routes (5MB)
app.use('/v1/*', bodyLimit({
  maxSize: MAX_BODY_SIZE,
  onError: (c) => c.json({
    success: false,
    error: { message: `Request body too large (max ${MAX_BODY_SIZE} bytes)`, code: 'PAYLOAD_TOO_LARGE' },
  }, 413),
}));

// Security headers
app.use('*', async (c, next) => {
  await next();
  c.res.headers.set('X-Content-Type-Options', 'nosniff');
  c.res.headers.set('X-Frame-Options', 'DENY');
  c.res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.res.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (process.env.NODE_ENV === 'production') {
    c.res.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
});

// Logging
app.use('/v1/*', logger());

// Request ID
app.use('/v1/*', async (c, next) => {
  const requestId = crypto.randomUUID();
  c.res.headers.set('X-Request-Id', requestId);
  await next();
});

// V2: Rate limiting (enabled)
app.use('/v1/auth/register', rateLimiter(25, 60_000));  // 25 registrations/min
app.use('/v1/auth/token', rateLimiter(50, 60_000));     // 50 token exchanges/min
app.use('/v1/auth/rotate-key', rateLimiter(15, 60_000)); // 15 key rotations/min
app.use('/v1/auth/refresh', rateLimiter(50, 60_000));   // 50 token refreshes/min
app.use('/v1/messages', rateLimiter(300, 60_000));        // 300 messages/min
app.use('/v1/agents/search', rateLimiter(150, 60_000));   // 150 searches/min
app.use('/v1/connections', rateLimiter(150, 60_000));     // 150 connection ops/min
app.use('/v1/discover', rateLimiter(150, 60_000));        // 150 discovery searches/min
app.use('/v1/threads/*/messages', rateLimiter(300, 60_000)); // 300 replies/min

// ═══════════════════════════════════════════════════════════════════════════
// API ROUTES (v1)
// ═══════════════════════════════════════════════════════════════════════════

const api = new Hono();

api.route('/auth', auth);
api.route('/wallet', walletAuth);
api.route('/agents', agentsRoute);
api.route('/messages', messagesRoute);
api.route('/threads', threadsRoute);
api.route('/connections', connectionsRoute);
api.route('/discover', discoverRoute);
api.route('/admin', adminRoute);

// Health check
api.get('/health', (c) => {
  return c.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// x402 payment gate for message routes (after rate limit, before handlers)
app.use('/v1/messages', x402MessageMiddleware);

// Mount API under /v1
app.route('/v1', api);

// Upload route (outside /v1 to avoid 5MB body limit)
app.route('/upload-api', uploadRoute);

// ═══════════════════════════════════════════════════════════════════════════
// A2A PROTOCOL ROUTES
// Agent-to-Agent Protocol endpoints for external agent interoperability
// ═══════════════════════════════════════════════════════════════════════════

// A2A Rate limiting
// V2.2.9: Body size limit for A2A routes (2MB) — prevents OOM via chunked transfer encoding bypass
app.use('/a2a/*', bodyLimit({
  maxSize: 2 * 1024 * 1024, // 2MB for A2A payloads
  onError: (c) => c.json({
    jsonrpc: '2.0',
    id: null,
    error: { code: -32600, message: 'Request body too large (max 2MB)' },
  }, 413),
}));
app.use('/a2a/*', rateLimiter(500, 60_000));  // 500 A2A requests/min

// x402 payment gate for A2A routes (after rate limit, before handlers)
// Uses official @x402/hono SDK for verify/settle via facilitator
app.use('/a2a/:agentId', x402A2AMiddleware);

// Root-level Agent Card (A2A spec v0.3 requirement)
// External clients discover platform at /.well-known/agent-card.json
import { getPlatformAgentCard } from './a2a/converters';

app.get('/.well-known/agent-card.json', (c) => {
  const url = new URL(c.req.url);
  const baseUrl = `${url.protocol}//${url.host}`;
  return c.json(getPlatformAgentCard(baseUrl));
});

// Backward-compatible old path
app.get('/.well-known/agent.json', (c) => {
  const url = new URL(c.req.url);
  const baseUrl = `${url.protocol}//${url.host}`;
  return c.json(getPlatformAgentCard(baseUrl));
});

// A2A routes
app.route('/a2a', a2aRoute);

// Start services
startCleanupScheduler();
startWebhookProcessor().catch(err => console.error('[Webhook] Failed to start processor:', err));

// ═══════════════════════════════════════════════════════════════════════════
// GRACEFUL SHUTDOWN (V2.1)
// Stop webhook processor + cleanup scheduler before exit
// ═══════════════════════════════════════════════════════════════════════════

function gracefulShutdown(signal: string) {
  console.log(`\n[Server] ${signal} received — shutting down gracefully...`);
  stopWebhookProcessor();
  stopCleanupScheduler();
  stopScanCachePrune();
  clearInterval(rateLimitCleanupInterval); // V2.1.3: Clean up rate limiter interval
  console.log('[Server] All services stopped. Exiting.');
  process.exit(0);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ═══════════════════════════════════════════════════════════════════════════
// UPLOADED FILES SERVING
// ═══════════════════════════════════════════════════════════════════════════

const UPLOAD_DIR = join(process.cwd(), 'uploads');

app.get('/uploads/:filename', async (c) => {
  const filename = c.req.param('filename');
  // Sanitize: no path traversal
  if (!filename || filename.includes('/') || filename.includes('\\') || filename.includes('..')) {
    return c.notFound();
  }
  const filePath = join(UPLOAD_DIR, filename);
  const resolved = resolve(filePath);
  if (!resolved.startsWith(resolve(UPLOAD_DIR))) {
    return c.notFound();
  }
  if (!existsSync(resolved)) {
    return c.notFound();
  }
  const ext = resolved.substring(resolved.lastIndexOf('.'));
  const mimeType = MIME_TYPES[ext] || 'application/octet-stream';
  const content = await readFile(resolved);
  return new Response(content, {
    headers: {
      'Content-Type': mimeType,
      'Cache-Control': 'public, max-age=604800',
      'Content-Disposition': `inline; filename="${filename}"`,
    },
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// STATIC FRONTEND SERVING
// ═══════════════════════════════════════════════════════════════════════════

const STATIC_DIR = join(process.cwd(), 'public');

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.pdf': 'application/pdf',
  '.zip': 'application/zip',
  '.md': 'text/markdown; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.gz': 'application/gzip',
  '.xml': 'application/xml',
  '.csv': 'text/csv',
  '.txt': 'text/plain',
  '.md': 'text/markdown',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.webp': 'image/webp',
  '.bmp': 'image/bmp',
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};

// ═══════════════════════════════════════════════════════════════════════════
// FILE CACHE — Pre-load HTML pages at startup, async read for assets
// Prevents readFileSync from blocking the event loop during requests
// ═══════════════════════════════════════════════════════════════════════════

const htmlCache = new Map<string, string>();

// Pre-cache known HTML pages at startup
const HTML_PAGES = ['index.html', 'app.html', 'login.html', 'register.html', 'docs.html', 'discover.html', 'architecture.html', 'architecture-full.html'];
for (const page of HTML_PAGES) {
  const filePath = join(STATIC_DIR, page);
  if (existsSync(filePath)) {
    htmlCache.set(page, readFileSync(filePath, 'utf-8'));
  }
}

// Serve static files from /public (async read, not blocking)
app.get('/assets/*', async (c) => {
  const filePath = join(STATIC_DIR, c.req.path);
  // V2.2.3: Prevent path traversal — resolved path MUST stay inside STATIC_DIR
  const resolved = resolve(filePath);
  if (!resolved.startsWith(resolve(STATIC_DIR))) {
    return c.notFound();
  }
  if (existsSync(resolved)) {
    const ext = resolved.substring(resolved.lastIndexOf('.'));
    const mimeType = MIME_TYPES[ext] || 'application/octet-stream';
    const content = await readFile(resolved);
    return new Response(content, {
      headers: { 'Content-Type': mimeType, 'Cache-Control': 'public, max-age=86400' },
    });
  }
  return c.notFound();
});

// Serve root-level static files (logo.png, favicon.ico, etc.)
app.get('/:file{.+\\.[a-z0-9]+$}', async (c) => {
  const fileName = c.req.param('file');
  if (!fileName || fileName.includes('/') || fileName.includes('..')) return c.notFound();
  const filePath = join(STATIC_DIR, fileName);
  const resolved = resolve(filePath);
  if (!resolved.startsWith(resolve(STATIC_DIR))) return c.notFound();
  if (existsSync(resolved)) {
    const ext = resolved.substring(resolved.lastIndexOf('.'));
    const mimeType = MIME_TYPES[ext] || 'application/octet-stream';
    const content = await readFile(resolved);
    return new Response(content, {
      headers: { 'Content-Type': mimeType, 'Cache-Control': 'public, max-age=86400' },
    });
  }
  return c.notFound();
});

// SPA Routing: All non-API routes serve the right page (from cache)
app.get('*', (c) => {
  // Skip API routes
  if (c.req.path.startsWith('/v1/')) return c.notFound();
  
  const path = c.req.path;
  let file = 'index.html';
  
  if (path === '/register') file = 'register.html';
  else if (path === '/login') file = 'login.html';
  else if (path === '/app') file = 'app.html';
  else if (path === '/discover') file = 'discover.html';
  else if (path === '/docs') file = 'docs.html';
  
  // Serve from cache (loaded at startup)
  const cached = htmlCache.get(file);
  if (cached) return c.html(cached, 200, { 'Cache-Control': 'no-cache, no-store, must-revalidate' });

  // Fallback to index.html
  const indexCached = htmlCache.get('index.html');
  if (indexCached) return c.html(indexCached, 200, { 'Cache-Control': 'no-cache, no-store, must-revalidate' });

  return c.json({
    name: 'NeuralPost',
    version: '2.3.0',
    api: '/v1',
    health: '/v1/health',
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// ERROR HANDLERS
// ═══════════════════════════════════════════════════════════════════════════

// 404 handler
app.notFound((c) => {
  return c.json({
    success: false,
    error: {
      message: 'Endpoint not found',
      code: 'NOT_FOUND',
    },
  }, 404);
});

// Global error handler
app.onError((err, c) => {
  console.error('Unhandled error:', err);
  return c.json({
    success: false,
    error: {
      message: process.env.NODE_ENV === 'production' 
        ? 'Internal server error' 
        : err.message,
      code: 'SERVER_ERROR',
    },
  }, 500);
});

// ═══════════════════════════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════════════════════════

const port = parseInt(process.env.PORT || '3000', 10);

console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     █████╗  ██████╗ ███████╗███╗   ██╗████████╗              ║
║    ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝              ║
║    ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║                 ║
║    ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║                 ║
║    ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║                 ║
║    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝                 ║
║                                                               ║
║    ██████╗ ███████╗██╗      █████╗ ██╗   ██╗                 ║
║    ██╔══██╗██╔════╝██║     ██╔══██╗╚██╗ ██╔╝                 ║
║    ██████╔╝█████╗  ██║     ███████║ ╚████╔╝                  ║
║    ██╔══██╗██╔══╝  ██║     ██╔══██║  ╚██╔╝                   ║
║    ██║  ██║███████╗███████╗██║  ██║   ██║                    ║
║    ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝                    ║
║                                                               ║
║    Email for AI Agents                                        ║
║    v2.3.0 — x402 Payment Protocol (V2 middleware)          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

Server:    http://localhost:${port}
📡 API:       http://localhost:${port}/v1
🔗 A2A:       http://localhost:${port}/a2a
🔍 Discover:  http://localhost:${port}/v1/discover
💚 Health:    http://localhost:${port}/v1/health
💰 x402:      enabled on /v1/messages + /a2a/:agentId
📨 Webhooks:  Processor running (auto-delivery)
🌐 Frontend:  http://localhost:${port}
`);

serve({
  fetch: app.fetch,
  port,
});

export default app;
