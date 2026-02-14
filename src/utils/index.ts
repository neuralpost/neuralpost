import { randomBytes, createHash, createHmac, timingSafeEqual, createCipheriv, createDecipheriv } from 'crypto';
import jwt from 'jsonwebtoken';

// ═══════════════════════════════════════════════════════════════════════════
// API KEY UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

const API_KEY_PREFIX = 'sk_';
const API_KEY_LENGTH = 32;

/**
 * Generate a new API key
 * Format: sk_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
 */
export function generateApiKey(): string {
  const randomPart = randomBytes(API_KEY_LENGTH).toString('base64url');
  return `${API_KEY_PREFIX}${randomPart}`;
}

/**
 * Get the prefix of an API key for quick lookups
 * Returns first 12 characters after sk_
 */
export function getApiKeyPrefix(apiKey: string): string {
  return apiKey.slice(API_KEY_PREFIX.length, API_KEY_PREFIX.length + 12);
}

/**
 * Hash an API key for storage
 * Uses SHA-256 for fast comparison (API keys are already high-entropy)
 */
export function hashApiKey(apiKey: string): string {
  return createHash('sha256').update(apiKey).digest('hex');
}

/**
 * Verify an API key against a stored hash
 * Uses timing-safe comparison to prevent timing attacks
 */
export function verifyApiKey(apiKey: string, storedHash: string): boolean {
  const hash = hashApiKey(apiKey);
  try {
    const a = Buffer.from(hash, 'hex');
    const b = Buffer.from(storedHash, 'hex');
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// JWT UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  console.error('FATAL: JWT_SECRET environment variable is required in production (min 32 chars)');
  process.exit(1);
}

// V2.2.5: Validate JWT secret strength in production
if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32 && process.env.NODE_ENV === 'production') {
  console.error('FATAL: JWT_SECRET must be at least 32 characters in production');
  process.exit(1);
}

if (!process.env.JWT_SECRET && process.env.NODE_ENV !== 'development') {
  console.warn('[Security] WARNING: JWT_SECRET not set and NODE_ENV is not "development". Using insecure default. Set JWT_SECRET or NODE_ENV=development.');
}

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-do-not-use-in-production';
const JWT_EXPIRES_IN = '7d';

interface TokenPayload {
  agentId: string;
  domain: string;
  iat?: number;  // V2.2.6: issued-at timestamp (set by jsonwebtoken)
  exp?: number;
}

/**
 * Generate a JWT token for an agent
 */
export function generateToken(agentId: string, domain: string): string {
  return jwt.sign(
    { agentId, domain } as TokenPayload,
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN, algorithm: 'HS256' }
  );
}

/**
 * Verify and decode a JWT token
 */
export function verifyToken(token: string): TokenPayload | null {
  try {
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }) as TokenPayload;
  } catch {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

// V2.2.12: Pre-compiled regex for hot-path validation
const DOMAIN_RE = /^[a-z0-9][a-z0-9._-]*@[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/i;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Validate agent domain format
 * Format: name@platform.domain
 */
export function isValidDomain(domain: string): boolean {
  // V2.2.6: Additional validation for RFC compliance
  if (domain.includes('..') || domain.includes('.-') || domain.includes('-.')) return false;
  return DOMAIN_RE.test(domain) && domain.length <= 255;
}

/**
 * Validate UUID format
 */
export function isValidUuid(id: string): boolean {
  return UUID_RE.test(id);
}

// ═══════════════════════════════════════════════════════════════════════════
// API RESPONSE HELPERS
// ═══════════════════════════════════════════════════════════════════════════

interface ApiResponse<T> {
  success: boolean;
  data?: T;
  message?: string;
  error?: {
    message: string;
    code: string;
  };
}

/**
 * Create a success response
 */
export function apiResponse<T>(data: T, message?: string): ApiResponse<T> {
  return {
    success: true,
    data,
    ...(message && { message }),
  };
}

/**
 * Create an error response
 */
export function apiError(message: string, code: string): ApiResponse<never> {
  return {
    success: false,
    error: { message, code },
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// PAGINATION HELPERS
// ═══════════════════════════════════════════════════════════════════════════

interface PaginationParams {
  limit: number;
  offset: number;
  cursor?: string;
}

interface PaginatedResponse<T> {
  items: T[];
  pagination: {
    total?: number;
    limit: number;
    offset: number;
    hasMore: boolean;
    nextCursor?: string;
  };
}

/**
 * Parse pagination params from query string
 */
export function parsePagination(
  query: { limit?: string; offset?: string; cursor?: string },
  defaults: { maxLimit?: number; defaultLimit?: number } = {}
): PaginationParams {
  const { maxLimit = 100, defaultLimit = 50 } = defaults;
  
  const parsedLimit = parseInt(query.limit || String(defaultLimit), 10);
  const parsedOffset = parseInt(query.offset || '0', 10);

  return {
    limit: Math.min(
      Math.max(Number.isNaN(parsedLimit) ? defaultLimit : parsedLimit, 1),
      maxLimit
    ),
    // V2.2.6: Cap offset to prevent expensive sequential scans
    offset: Math.min(Math.max(Number.isNaN(parsedOffset) ? 0 : parsedOffset, 0), 10_000),
    cursor: query.cursor,
  };
}

/**
 * Create a paginated response
 */
export function paginatedResponse<T>(
  items: T[],
  pagination: PaginationParams,
  total?: number
): PaginatedResponse<T> {
  return {
    items,
    pagination: {
      ...(total !== undefined && { total }),
      limit: pagination.limit,
      offset: pagination.offset,
      hasMore: items.length === pagination.limit,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// TEXT UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Sanitize HTML content
 * Strips dangerous tags and attributes for XSS prevention.
 * For user-generated content stored as body/bodyHtml.
 */
export function sanitizeHtml(html: string): string {
  return html
    // ── PHASE 1: Strip dangerous tags WITH their content ──
    // Match both closed AND unclosed (no closing tag) variants
    // Unclosed: <script ...> followed by anything to end-of-string
    .replace(/<script\b[^]*?<\/script\s*>/gi, '')
    .replace(/<script\b[^]*$/gi, '')  // unclosed <script> to end
    .replace(/<style\b[^]*?<\/style\s*>/gi, '')
    .replace(/<style\b[^]*$/gi, '')
    .replace(/<iframe\b[^]*?<\/iframe\s*>/gi, '')
    .replace(/<iframe\b[^]*$/gi, '')
    .replace(/<object\b[^]*?<\/object\s*>/gi, '')
    .replace(/<object\b[^]*$/gi, '')
    .replace(/<embed\b[^>]*\/?>/gi, '')
    .replace(/<noscript\b[^]*?<\/noscript\s*>/gi, '')

    // ── PHASE 2: Strip additional dangerous tags (open + close) ──
    .replace(/<\/?(?:svg|math|link|base|meta|form|applet|marquee)\b[^>]*>/gi, '')

    // ── PHASE 3: Event handlers — match / or whitespace before on ──
    // HTML5 treats / as attribute separator: <img/onerror=...> is valid
    // V2.2.8: Use single-char separator (no +) to prevent ReDoS on repeated /'s
    .replace(/[\s\/]on\w+\s*=\s*("[^"]*"|'[^']*'|`[^`]*`|[^\s>]*)/gi, '')

    // ── PHASE 4: Dangerous URL protocols ──
    // Handle whitespace within protocol (java\tscript:, java\nscript:)
    // Block: javascript, data, vbscript, blob
    .replace(/\b(href|src|action|data|xlink:href|formaction|poster|background)\s*=\s*["']?\s*(?:j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t|d\s*a\s*t\s*a|v\s*b\s*s\s*c\s*r\s*i\s*p\s*t|b\s*l\s*o\s*b)\s*:/gi, '$1="blocked:')

    // ── PHASE 5: HTML entity-encoded event handlers ──
    // Match on + word + &#61; or &#x3d; (encoded =)
    // V2.2.8: Use single-char separator to prevent ReDoS
    .replace(/[\s\/]on\w+\s*(?:&#(?:61|x3d);|&#(?:0*61|x0*3d);)\s*[^\s>]*/gi, '');
}

/**
 * Strip HTML tags from text
 */
export function stripHtml(html: string): string {
  return html.replace(/<[^>]*>/g, '');
}

/**
 * Generate preview text from body
 */
export function generatePreview(body: string, maxLength: number = 150): string {
  const text = stripHtml(body).trim();
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength).trim() + '...';
}

// ═══════════════════════════════════════════════════════════════════════════
// V2: MULTIMODAL MESSAGE UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

export interface TextPart { kind: 'text'; content: string }
export interface DataPart { kind: 'data'; content_type: string; content: unknown }
export interface FilePart { kind: 'file'; url: string; mime: string; name?: string; size?: number }
export type MessagePart = TextPart | DataPart | FilePart;

/**
 * Normalize message content to parts array
 * Backward compatible: plain string → [{kind: "text", content: "..."}]
 */
export function normalizeParts(input: string | MessagePart[]): MessagePart[] {
  if (typeof input === 'string') {
    if (input.length === 0) {
      throw new Error('Message must have non-empty content');
    }
    return [{ kind: 'text', content: input }];
  }
  if (Array.isArray(input) && input.length > 0) {
    return input;
  }
  throw new Error('Message must have content (string) or parts (array)');
}

/**
 * Extract plain text body from parts array (for search, preview, backward compat)
 */
export function extractTextFromParts(parts: MessagePart[]): string {
  return parts
    .filter((p): p is TextPart => p.kind === 'text')
    .map(p => p.content)
    .join('\n');
}

/**
 * Check if parts contain file references
 */
export function partsHaveFiles(parts: MessagePart[]): boolean {
  return parts.some(p => p.kind === 'file');
}

/**
 * Validate a single message part
 */
export function validatePart(part: unknown): { valid: boolean; error?: string } {
  if (!part || typeof part !== 'object') {
    return { valid: false, error: 'Part must be an object' };
  }
  
  const p = part as Record<string, unknown>;
  
  if (!p.kind || !['text', 'data', 'file'].includes(p.kind as string)) {
    return { valid: false, error: 'Part kind must be "text", "data", or "file"' };
  }
  
  switch (p.kind) {
    case 'text':
      if (typeof p.content !== 'string' || p.content.length === 0) {
        return { valid: false, error: 'Text part requires non-empty content string' };
      }
      if (p.content.length > 50000) {
        return { valid: false, error: 'Text part content exceeds 50000 characters' };
      }
      break;
      
    case 'data':
      if (typeof p.content_type !== 'string') {
        return { valid: false, error: 'Data part requires content_type string' };
      }
      if (p.content === undefined || p.content === null) {
        return { valid: false, error: 'Data part requires content' };
      }
      // V2.2.8: Limit data part size to prevent storage abuse
      {
        const dataStr = typeof p.content === 'string' ? p.content : JSON.stringify(p.content);
        if (dataStr.length > 1_000_000) {
          return { valid: false, error: 'Data part content exceeds 1MB limit' };
        }
      }
      break;
      
    case 'file':
      if (typeof p.url !== 'string' || !isValidUrl(p.url)) {
        return { valid: false, error: 'File part requires valid url' };
      }
      if (typeof p.mime !== 'string') {
        return { valid: false, error: 'File part requires mime string' };
      }
      break;
  }
  
  return { valid: true };
}

/**
 * Escape HTML entities (for text stored/displayed as HTML)
 */
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * Sanitize message parts before storage.
 * Defense-in-depth: escape HTML in text parts, sanitize file names/URLs.
 * Prevents stored XSS when frontend renders parts via innerHTML.
 */
export function sanitizeParts(parts: MessagePart[]): MessagePart[] {
  return parts.map(p => {
    switch (p.kind) {
      case 'text':
        return { ...p, content: sanitizeHtml(p.content) };
      case 'file':
        return {
          ...p,
          name: p.name ? escapeHtml(stripHtml(p.name)) : p.name,
          mime: p.mime ? escapeHtml(p.mime) : p.mime,
        };
      case 'data':
        return {
          ...p,
          content_type: escapeHtml(p.content_type),
        };
      default:
        return p;
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// V2: URL & WEBHOOK SECURITY UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Validate URL format (basic check)
 */
export function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

/**
 * Anti-SSRF: Validate webhook URL is not targeting internal/private networks
 * V2.1.3: Added IPv6, decimal IP, octal IP, and additional hostname checks
 */
export function isPublicUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    
    // MUST be http or https — blocks javascript:, data:, ftp:, file:, etc.
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }
    
    const hostname = parsed.hostname.toLowerCase();
    
    // Block localhost variants
    if (['localhost', '127.0.0.1', '::1', '0.0.0.0'].includes(hostname)) {
      return false;
    }
    
    // Block .localhost TLD (e.g., anything.localhost)
    if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
      return false;
    }

    // Block IPv6 addresses entirely in webhook URLs (too many bypass vectors)
    // IPv6 in URLs looks like [::1] or [::ffff:127.0.0.1]
    if (hostname.startsWith('[') || hostname.includes(':')) {
      return false;
    }

    // Block decimal / octal / hex IP representations
    // Decimal: 2130706433 = 127.0.0.1; Octal: 0177.0.0.1; Hex: 0x7f000001
    if (/^(0x[0-9a-f]+|\d{8,}|0\d+\.\d+\.\d+\.\d+)$/i.test(hostname)) {
      return false;
    }
    
    // Block private IPv4 ranges
    const ipMatch = hostname.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (ipMatch) {
      const [, a, b] = ipMatch.map(Number);
      if (a === 10) return false;                          // 10.0.0.0/8
      if (a === 172 && b >= 16 && b <= 31) return false;   // 172.16.0.0/12
      if (a === 192 && b === 168) return false;             // 192.168.0.0/16
      if (a === 169 && b === 254) return false;             // 169.254.0.0/16 (link-local / cloud metadata)
      if (a === 0) return false;                            // 0.0.0.0/8
      if (a === 100 && b >= 64 && b <= 127) return false;  // 100.64.0.0/10 (carrier-grade NAT)
      if (a === 127) return false;                          // 127.0.0.0/8 (full loopback range)
    }
    
    // Block internal TLDs
    if (hostname.endsWith('.local') || hostname.endsWith('.internal') || hostname.endsWith('.corp') || hostname.endsWith('.home') || hostname.endsWith('.lan')) {
      return false;
    }

    // Block AWS/GCP/Azure metadata endpoints by hostname
    if (hostname === 'metadata.google.internal' || hostname === 'metadata.google.com') {
      return false;
    }
    
    // Must be HTTPS in production
    if (process.env.NODE_ENV === 'production' && parsed.protocol !== 'https:') {
      return false;
    }
    
    return true;
  } catch {
    return false;
  }
}

/**
 * Generate HMAC signature for webhook delivery
 */
export function generateWebhookSignature(
  body: string,
  secret: string,
  timestamp: number
): string {
  const payload = `${timestamp}.${body}`;
  return createHmac('sha256', secret).update(payload).digest('hex');
}

/**
 * Generate a webhook secret for an agent
 */
export function generateWebhookSecret(): string {
  return `whsec_${randomBytes(32).toString('base64url')}`;
}

// ═══════════════════════════════════════════════════════════════════════════
// V2.1.2: WEBHOOK SECRET ENCRYPTION AT REST (AES-256-GCM)
// DB stores encrypted ciphertext. Server decrypts on-the-fly when signing.
// ═══════════════════════════════════════════════════════════════════════════

const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;      // GCM standard nonce length
const AUTH_TAG_LENGTH = 16; // GCM standard auth tag length

/**
 * Derive a 32-byte encryption key from env variable or fallback.
 * In production, WEBHOOK_ENCRYPTION_KEY must be set (64-char hex or 32+ char string).
 */
function getEncryptionKey(): Buffer {
  const envKey = process.env.WEBHOOK_ENCRYPTION_KEY;
  if (envKey && envKey.length >= 64 && /^[0-9a-f]+$/i.test(envKey)) {
    return Buffer.from(envKey.slice(0, 64), 'hex');
  }
  if (envKey && envKey.length >= 32) {
    return createHash('sha256').update(envKey).digest();
  }
  if (process.env.NODE_ENV === 'production') {
    // V2.2.5: CRITICAL — refuse to use hardcoded key in production
    throw new Error(
      '[Security] WEBHOOK_ENCRYPTION_KEY not set in production! ' +
      'Set a 64-char hex string or 32+ char secret. ' +
      'Webhook secrets cannot be safely encrypted without this.'
    );
  }
  return createHash('sha256').update('neuralpost-dev-encryption-key-change-me').digest();
}

/**
 * Encrypt a webhook secret for storage.
 * Format: base64url(iv + authTag + ciphertext) prefixed with "enc_"
 */
export function encryptWebhookSecret(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ENCRYPTION_ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH } as any);
  
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  
  const packed = Buffer.concat([iv, authTag, encrypted]);
  return `enc_${packed.toString('base64url')}`;
}

/**
 * Decrypt a webhook secret from storage.
 * Handles both encrypted ("enc_...") and legacy plain text secrets.
 */
export function decryptWebhookSecret(stored: string): string {
  if (!stored.startsWith('enc_')) {
    return stored; // Legacy plain text
  }
  
  const key = getEncryptionKey();
  const packed = Buffer.from(stored.slice(4), 'base64url');
  
  const iv = packed.subarray(0, IV_LENGTH);
  const authTag = packed.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = packed.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  
  const decipher = createDecipheriv(ENCRYPTION_ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH } as any);
  decipher.setAuthTag(authTag);
  
  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  
  return decrypted.toString('utf8');
}

// ═══════════════════════════════════════════════════════════════════════════
// DATE UTILITIES (Return ISO strings - frontend formats)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Get current timestamp as ISO string
 */
export function now(): string {
  return new Date().toISOString();
}

/**
 * Check if a date is within the last N minutes
 */
export function isWithinMinutes(date: Date | string, minutes: number): boolean {
  const d = typeof date === 'string' ? new Date(date) : date;
  const diff = Date.now() - d.getTime();
  return diff < minutes * 60 * 1000;
}
