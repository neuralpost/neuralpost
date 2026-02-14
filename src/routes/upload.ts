import { Hono } from 'hono';
import { db } from '../db';
import { agents } from '../db/schema';
import { eq } from 'drizzle-orm';
import { verifyToken, apiResponse, apiError } from '../utils';
import { randomBytes } from 'crypto';
import { join, extname } from 'path';
import { writeFile, mkdir, stat } from 'fs/promises';
import { existsSync } from 'fs';

const upload = new Hono();

// ═══════════════════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════════════════

const UPLOAD_DIR = join(process.cwd(), 'uploads');
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const ALLOWED_MIME_PREFIXES = [
  'image/', 'text/', 'application/json', 'application/pdf',
  'application/xml', 'application/zip', 'application/gzip',
  'application/octet-stream', 'audio/', 'video/',
  'application/vnd.', 'application/x-',
];

// Ensure upload dir exists
async function ensureUploadDir() {
  if (!existsSync(UPLOAD_DIR)) {
    await mkdir(UPLOAD_DIR, { recursive: true });
  }
}

// Generate unique filename
function generateFilename(originalName: string): string {
  const ext = extname(originalName) || '';
  const id = randomBytes(12).toString('hex');
  const timestamp = Date.now().toString(36);
  // Sanitize: keep only safe chars
  const safeName = originalName
    .replace(ext, '')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .slice(0, 60);
  return `${timestamp}_${id}_${safeName}${ext}`;
}

// ═══════════════════════════════════════════════════════════════════════════
// POST /upload — Upload a file (multipart/form-data)
// Returns URL that can be used in message parts
// ═══════════════════════════════════════════════════════════════════════════

upload.post('/', async (c) => {
  try {
    // Auth check
    const authHeader = c.req.header('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json(apiError('Authentication required', 'UNAUTHORIZED'), 401);
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload) {
      return c.json(apiError('Invalid token', 'UNAUTHORIZED'), 401);
    }

    // Parse multipart form
    const formData = await c.req.formData();
    const file = formData.get('file');

    if (!file || !(file instanceof File)) {
      return c.json(apiError('No file provided. Send as multipart/form-data with field "file"', 'VALIDATION_ERROR'), 400);
    }

    // Size check
    if (file.size > MAX_FILE_SIZE) {
      return c.json(apiError(`File too large. Max ${MAX_FILE_SIZE / 1024 / 1024}MB`, 'FILE_TOO_LARGE'), 413);
    }

    if (file.size === 0) {
      return c.json(apiError('Empty file', 'VALIDATION_ERROR'), 400);
    }

    // MIME check
    const mime = file.type || 'application/octet-stream';
    const allowed = ALLOWED_MIME_PREFIXES.some(prefix => mime.startsWith(prefix));
    if (!allowed) {
      return c.json(apiError(`File type "${mime}" not allowed`, 'INVALID_FILE_TYPE'), 400);
    }

    // Save file
    await ensureUploadDir();
    const filename = generateFilename(file.name || 'upload');
    const filepath = join(UPLOAD_DIR, filename);

    const buffer = Buffer.from(await file.arrayBuffer());
    await writeFile(filepath, buffer);

    // Build public URL
    const protocol = c.req.header('x-forwarded-proto') || 'https';
    const host = c.req.header('host') || 'neuralpost.net';
    const url = `${protocol}://${host}/uploads/${filename}`;

    return c.json(apiResponse({
      url,
      filename,
      originalName: file.name || 'upload',
      mime,
      size: file.size,
    }, 'File uploaded'));

  } catch (error) {
    console.error('[Upload] Error:', error);
    return c.json(apiError('Upload failed', 'SERVER_ERROR'), 500);
  }
});

export default upload;
