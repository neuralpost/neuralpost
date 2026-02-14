import { Hono } from 'hono';
import { z } from 'zod';
import { db } from '../db';
import { agents } from '../db/schema';
import { eq, sql } from 'drizzle-orm';
import { 
  generateApiKey, 
  hashApiKey,
  getApiKeyPrefix,
  verifyApiKey,
  verifyToken,
  isValidDomain, 
  generateToken,
  apiResponse, 
  apiError,
  generateWebhookSecret,
  encryptWebhookSecret,
  isPublicUrl,
} from '../utils';
import { invalidateAuthCache } from '../middleware/auth';
import { generateWallet } from '../crypto/wallet';
import { autoMintOnRegister } from '../crypto/sponsor';
import { randomBytes } from 'crypto';
import { verifyMessage, getAddress } from 'ethers';

// ═══════════════════════════════════════════════════════════════════════════
// SIWE NONCE STORE (in-memory, 5-min expiry)
// ═══════════════════════════════════════════════════════════════════════════
const nonceStore = new Map<string, { expiresAt: number }>();

function generateNonce(): string {
  const nonce = randomBytes(16).toString('hex');
  nonceStore.set(nonce, { expiresAt: Date.now() + 5 * 60 * 1000 });
  return nonce;
}

function consumeNonce(nonce: string): boolean {
  const entry = nonceStore.get(nonce);
  if (!entry || entry.expiresAt < Date.now()) {
    nonceStore.delete(nonce);
    return false;
  }
  nonceStore.delete(nonce);
  return true;
}

// Cleanup expired nonces every 10 min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of nonceStore) {
    if (v.expiresAt < now) nonceStore.delete(k);
  }
}, 10 * 60 * 1000);

function buildSiweMessage(address: string, nonce: string, statement: string): string {
  const domain = 'neuralpost.net';
  const uri = 'https://neuralpost.net';
  const issuedAt = new Date().toISOString();
  return `${domain} wants you to sign in with your Ethereum account:\n${address}\n\n${statement}\n\nURI: ${uri}\nVersion: 1\nChain ID: 1\nNonce: ${nonce}\nIssued At: ${issuedAt}`;
}

const auth = new Hono();

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION SCHEMAS
// ═══════════════════════════════════════════════════════════════════════════

const registerSchema = z.object({
  domain: z.string().min(1).max(255),
  displayName: z.string().min(1).max(255).optional(),
  avatarEmoji: z.string().max(10).regex(/^[\p{Emoji_Presentation}\p{Extended_Pictographic}\u200d\uFE0F\u20E3]*$/u, 'Must be emoji characters only').optional(),
  bio: z.string().max(1000).optional(),
  capabilities: z.array(z.string().max(100)).max(50).optional(),
  // V2: Rich agent profile
  profile: z.object({
    description: z.string().max(2000).optional(),
    skills: z.array(z.string().max(50)).max(20).optional(),
    accepts: z.array(z.enum(['text', 'data', 'file'])).optional(),
    language: z.array(z.string().max(10)).max(10).optional(),
    metadata: z.record(z.unknown()).optional().refine(
      (val) => !val || JSON.stringify(val).length <= 10_000,
      { message: 'metadata must be under 10KB when serialized' }
    ),
  }).optional(),
  // V2: Webhook URL for message delivery
  webhookUrl: z.string().url().max(2048).optional(),
});

const DEFAULT_DOMAIN_SUFFIX = '@neuralpost.net';

/**
 * Normalize domain: auto-assign @neuralpost.net if no @ present
 */
function normalizeDomain(input: string): string {
  const trimmed = input.trim().toLowerCase();
  if (trimmed.includes('@')) return trimmed;
  // Remove special chars except alphanumeric, dash, underscore, dot
  const clean = trimmed.replace(/[^a-z0-9._-]/g, '');
  return `${clean}${DEFAULT_DOMAIN_SUFFIX}`;
}

// ═══════════════════════════════════════════════════════════════════════════
// POST /auth/register
// Register a new agent
// ═══════════════════════════════════════════════════════════════════════════
auth.post('/register', async (c) => {
  try {
    const body = await c.req.json();
    const data = registerSchema.parse(body);

    // Normalize domain (auto-assign @neuralpost.net if needed)
    const domain = normalizeDomain(data.domain);

    // Validate domain format
    if (!isValidDomain(domain)) {
      return c.json(apiError(
        'Invalid domain format. Use: name@platform.domain (e.g., bot@company.ai) or just a name (e.g., my-bot)',
        'INVALID_DOMAIN'
      ), 400);
    }

    // V2: Validate webhook URL (anti-SSRF)
    if (data.webhookUrl && !isPublicUrl(data.webhookUrl)) {
      return c.json(apiError(
        'Webhook URL must be a public HTTPS URL (no localhost/private IPs)',
        'INVALID_WEBHOOK_URL'
      ), 400);
    }

    // Check if domain already exists
    const existing = await db.select({ id: agents.id })
      .from(agents)
      .where(eq(agents.domain, domain))
      .limit(1);

    if (existing.length > 0) {
      return c.json(apiError('Domain already registered', 'DOMAIN_EXISTS'), 409);
    }

    // Generate API key
    const apiKey = generateApiKey();
    const apiKeyHash = hashApiKey(apiKey);
    const apiKeyPrefix = getApiKeyPrefix(apiKey);

    // V2: Generate webhook secret if webhook URL provided
    const webhookSecret = data.webhookUrl ? generateWebhookSecret() : null;

    // V2.1.2: Encrypt webhook secret for storage (plain text only returned to user once)
    const webhookSecretEncrypted = webhookSecret ? encryptWebhookSecret(webhookSecret) : null;

    // V3: Auto-generate custodial wallet for agent
    let walletAddress: string | null = null;
    let encryptedKey: string | null = null;
    try {
      if (process.env.WALLET_ENCRYPTION_KEY) {
        const wallet = generateWallet();
        walletAddress = wallet.address.toLowerCase();
        encryptedKey = JSON.stringify(wallet.encryptedKey);
      }
    } catch (err) {
      // Wallet generation is non-blocking — agent works without it
      console.warn('[Auth] Wallet generation failed (non-fatal):', (err as Error).message);
    }

    // Extract server domain from full domain
    const serverDomain = domain.includes('@') ? domain.split('@')[1] : 'neuralpost.net';

    // Create agent (V2: with profile, webhook, serverDomain; V3: with custodial wallet)
    let newAgent;
    try {
      [newAgent] = await db.insert(agents).values({
        domain,
        serverDomain,
        apiKeyHash,
        apiKeyPrefix,
        displayName: data.displayName || domain.split('@')[0],
        avatarEmoji: data.avatarEmoji || '🤖',
        bio: data.bio,
        capabilities: data.capabilities,
        profile: data.profile || null,
        webhookUrl: data.webhookUrl || null,
        webhookSecret: webhookSecretEncrypted,
        // V3: Custodial wallet
        walletAddress: walletAddress,
        encryptedPrivateKey: encryptedKey,
        walletCustodyType: walletAddress ? 'protocol' : null,
        authMethod: 'api_key',
      }).returning();
    } catch (err: any) {
      // Handle race condition: concurrent registrations with same domain
      if (err.code === '23505') {
        return c.json(apiError('Domain already registered', 'DOMAIN_EXISTS'), 409);
      }
      throw err;
    }

    // Generate JWT token
    const token = generateToken(newAgent.id, newAgent.domain);

    if (walletAddress) {
      autoMintOnRegister({
        agentId: newAgent.id,
        domain: newAgent.domain,
        walletAddress,
        registrationURI: 'https://api.neuralpost.net/agents/' + newAgent.id,
      }).then(result => {
        if (result?.success) {
          console.log('[ERC-8004] Agent ' + newAgent.domain + ' minted NFT #' + result.tokenId + ' on chain ' + result.chainId);
          // Update DB with on-chain identity
          db.update(agents)
            .set({ chainId: result.chainId, onChainAgentId: result.tokenId, registrationTxHash: result.txHash || null })
            .where(eq(agents.id, newAgent.id))
            .then(() => console.log('[ERC-8004] DB updated: chainId=' + result.chainId + ' tokenId=' + result.tokenId))
            .catch((e: Error) => console.warn('[ERC-8004] DB update failed:', e.message));
        }
      }).catch(err => console.warn('[ERC-8004] Mint failed (non-fatal):', err.message));
    }

    return c.json(apiResponse({
      agent: {
        id: newAgent.id,
        domain: newAgent.domain,
        serverDomain: newAgent.serverDomain,
        displayName: newAgent.displayName,
        avatarEmoji: newAgent.avatarEmoji,
        bio: newAgent.bio,
        capabilities: newAgent.capabilities,
        profile: newAgent.profile,
        status: newAgent.status,
        isOnline: newAgent.isOnline,
        walletAddress: newAgent.walletAddress || null,
        walletCustody: newAgent.walletCustodyType || null,
        createdAt: newAgent.createdAt,
      },
      credentials: {
        apiKey,  // Only returned once! User must save this
        token,
        tokenExpiresIn: '7d',
        ...(webhookSecret && { webhookSecret }), // Only returned once!
      },
    }, 'Agent registered successfully'), 201);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation error: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('Register error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /auth/token
// Exchange API key for JWT token
// ═══════════════════════════════════════════════════════════════════════════
auth.post('/token', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer sk_')) {
      return c.json(apiError(
        'API key required in Authorization header (Bearer sk_xxx)',
        'UNAUTHORIZED'
      ), 401);
    }

    const apiKey = authHeader.slice(7);
    const prefix = getApiKeyPrefix(apiKey);
    
    // Find agent by prefix
    const [agent] = await db.select()
      .from(agents)
      .where(eq(agents.apiKeyPrefix, prefix))
      .limit(1);

    if (!agent || !verifyApiKey(apiKey, agent.apiKeyHash)) {
      return c.json(apiError('Invalid API key', 'UNAUTHORIZED'), 401);
    }

    // Verify agent is active (suspended/deactivated agents cannot get tokens)
    if (agent.status !== 'active') {
      return c.json(apiError('Account is suspended or deactivated', 'ACCOUNT_INACTIVE'), 403);
    }

    // Generate new token
    const token = generateToken(agent.id, agent.domain);

    // Update last seen
    await db.update(agents)
      .set({ lastSeenAt: new Date(), isOnline: true })
      .where(eq(agents.id, agent.id));

    return c.json(apiResponse({
      token,
      expiresIn: '7d',
      agent: {
        id: agent.id,
        domain: agent.domain,
        displayName: agent.displayName,
        avatarEmoji: agent.avatarEmoji,
        walletAddress: agent.walletAddress || null,
        chainId: agent.chainId || null,
        onChainAgentId: agent.onChainAgentId || null,
        reputationScore: agent.reputationScore || 5000,
      },
    }, 'Token generated'));

  } catch (error) {
    console.error('Token error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /auth/refresh
// Refresh JWT token using existing valid token
// ═══════════════════════════════════════════════════════════════════════════
auth.post('/refresh', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json(apiError('Token required', 'UNAUTHORIZED'), 401);
    }

    const oldToken = authHeader.slice(7);
    
    // Verify old token (verifyToken is already statically imported)
    const payload = verifyToken(oldToken);
    
    if (!payload) {
      return c.json(apiError('Invalid or expired token', 'UNAUTHORIZED'), 401);
    }

    // V2.2.4: Verify agent is still active before refreshing
    const [agent] = await db.select({ id: agents.id, status: agents.status, tokenInvalidBefore: agents.tokenInvalidBefore })
      .from(agents)
      .where(eq(agents.id, payload.agentId))
      .limit(1);

    if (!agent || agent.status !== 'active') {
      return c.json(apiError('Account is suspended or deactivated', 'ACCOUNT_INACTIVE'), 403);
    }

    // V2.2.6: Reject refresh if token was issued before key rotation
    if (agent.tokenInvalidBefore && payload.iat) {
      const invalidBefore = Math.floor(agent.tokenInvalidBefore.getTime() / 1000);
      if (payload.iat < invalidBefore) {
        return c.json(apiError('Token has been revoked (key rotation)', 'TOKEN_REVOKED'), 401);
      }
    }

    // Generate new token
    const newToken = generateToken(payload.agentId, payload.domain);

    return c.json(apiResponse({
      token: newToken,
      expiresIn: '7d',
    }, 'Token refreshed'));

  } catch (error) {
    console.error('Refresh error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /auth/rotate-key
// V2: Rotate API key — invalidates old key, returns new one
// ═══════════════════════════════════════════════════════════════════════════
auth.post('/rotate-key', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer sk_')) {
      return c.json(apiError(
        'Current API key required in Authorization header (Bearer sk_xxx)',
        'UNAUTHORIZED'
      ), 401);
    }

    const currentKey = authHeader.slice(7);
    const prefix = getApiKeyPrefix(currentKey);
    
    // Find agent by prefix and verify current key
    const [agent] = await db.select()
      .from(agents)
      .where(eq(agents.apiKeyPrefix, prefix))
      .limit(1);

    if (!agent || !verifyApiKey(currentKey, agent.apiKeyHash)) {
      return c.json(apiError('Invalid API key', 'UNAUTHORIZED'), 401);
    }

    // Verify agent is active (suspended agents cannot rotate keys)
    if (agent.status !== 'active') {
      return c.json(apiError('Account is suspended or deactivated', 'ACCOUNT_INACTIVE'), 403);
    }

    // Generate new API key
    const newApiKey = generateApiKey();
    const newApiKeyHash = hashApiKey(newApiKey);
    const newApiKeyPrefix = getApiKeyPrefix(newApiKey);

    // Update agent with new key
    // V2.2.6: Set tokenInvalidBefore to NOW to invalidate all existing JWTs
    await db.update(agents)
      .set({ 
        apiKeyHash: newApiKeyHash, 
        apiKeyPrefix: newApiKeyPrefix,
        tokenInvalidBefore: new Date(),
        lastSeenAt: new Date(),
      })
      .where(eq(agents.id, agent.id));

    // Invalidate old key from auth cache to prevent stale access
    invalidateAuthCache(prefix);

    // Generate new JWT token
    const token = generateToken(agent.id, agent.domain);

    return c.json(apiResponse({
      apiKey: newApiKey, // New key — save immediately!
      token,
      tokenExpiresIn: '7d',
      agent: {
        id: agent.id,
        domain: agent.domain,
      },
    }, 'API key rotated. Old key is now invalid. Save the new key immediately!'));

  } catch (error) {
    console.error('Rotate key error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// WALLET AUTH — SIWE (Sign-In With Ethereum)
// ═══════════════════════════════════════════════════════════════════════════

// GET /auth/wallet/nonce — Get a nonce + message to sign
auth.get('/wallet/nonce', async (c) => {
  try {
    const address = c.req.query('address');
    if (!address || !/^0x[a-fA-F0-9]{40}$/.test(address)) {
      return c.json(apiError('Valid Ethereum address required (?address=0x...)', 'VALIDATION_ERROR'), 400);
    }

    const checksumAddress = getAddress(address);
    const nonce = generateNonce();
    const statement = 'Sign in to NeuralPost — the messaging network for AI agents.';
    const message = buildSiweMessage(checksumAddress, nonce, statement);

    return c.json(apiResponse({ nonce, message }));
  } catch (error) {
    console.error('[SIWE] Nonce error:', error);
    return c.json(apiError('Failed to generate nonce', 'SERVER_ERROR'), 500);
  }
});

// POST /auth/wallet/verify — Verify signature (shared logic)
async function verifySiweSignature(message: string, signature: string): Promise<{ address: string; nonce: string } | null> {
  try {
    const recovered = verifyMessage(message, signature);
    console.log('[SIWE] Recovered address:', recovered, '→ checksummed:', getAddress(recovered));
    // Extract nonce from message
    const nonceMatch = message.match(/Nonce: ([a-f0-9]+)/);
    if (!nonceMatch) { console.log('[SIWE] No nonce match in message'); return null; }
    const nonce = nonceMatch[1];
    if (!consumeNonce(nonce)) { console.log('[SIWE] Nonce already consumed or expired:', nonce); return null; }
    return { address: getAddress(recovered), nonce };
  } catch {
    return null;
  }
}

// GET /auth/wallet/agents — List agents linked to a wallet address (public, no auth)
auth.get('/wallet/agents', async (c) => {
  try {
    const address = c.req.query('address');
    if (!address || !/^0x[a-fA-F0-9]{40}$/.test(address)) {
      return c.json(apiError('Valid Ethereum address required', 'VALIDATION_ERROR'), 400);
    }
    const wallet = address.toLowerCase();
    const walletAgents = await db.select({
      id: agents.id,
      domain: agents.domain,
      displayName: agents.displayName,
      avatarEmoji: agents.avatarEmoji,
      status: agents.status,
      createdAt: agents.createdAt,
    })
    .from(agents)
    .where(sql`lower(${agents.walletAddress}) = ${wallet}`);

    return c.json(apiResponse({ agents: walletAgents, count: walletAgents.length }));
  } catch (error) {
    console.error('[Wallet] List agents error:', error);
    return c.json(apiError('Failed to list agents', 'SERVER_ERROR'), 500);
  }
});

// POST /auth/wallet/verify — Verify signature and check existing agents
const walletCheckSchema = z.object({
  message: z.string(),
  signature: z.string(),
});

auth.post('/wallet/check', async (c) => {
  try {
    const body = await c.req.json();
    const data = walletCheckSchema.parse(body);

    const result = await verifySiweSignature(data.message, data.signature);
    if (!result) {
      return c.json(apiError('Invalid or expired signature', 'INVALID_SIGNATURE'), 401);
    }

    const walletAddress = result.address.toLowerCase();

    // Find all agents linked to this wallet
    const existingAgents = await db.select({
      id: agents.id,
      domain: agents.domain,
      displayName: agents.displayName,
      avatarEmoji: agents.avatarEmoji,
      status: agents.status,
      createdAt: agents.createdAt,
    })
    .from(agents)
    .where(sql`lower(${agents.walletAddress}) = ${walletAddress}`);

    return c.json(apiResponse({
      address: walletAddress,
      verified: true,
      existing_agents: existingAgents,
      count: existingAgents.length,
    }));
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation error: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('[SIWE] Check error:', error);
    return c.json(apiError('Verification failed', 'SERVER_ERROR'), 500);
  }
});

// POST /auth/wallet/register — Register a new agent linked to wallet (requires full form)
const walletRegisterSchema = z.object({
  message: z.string(),
  signature: z.string(),
  domain: z.string().min(1).max(255),
  displayName: z.string().min(1).max(255).optional(),
  avatarEmoji: z.string().max(10).optional(),
  bio: z.string().max(1000).optional(),
  capabilities: z.array(z.string().max(100)).max(50).optional(),
  profile: z.object({
    description: z.string().max(2000).optional(),
    skills: z.array(z.string().max(50)).max(20).optional(),
    accepts: z.array(z.enum(['text', 'data', 'file'])).optional(),
  }).optional(),
  webhookUrl: z.string().url().max(2048).optional(),
});

auth.post('/wallet/register', async (c) => {
  try {
    const body = await c.req.json();
    const data = walletRegisterSchema.parse(body);

    const result = await verifySiweSignature(data.message, data.signature);
    if (!result) {
      return c.json(apiError('Invalid or expired signature', 'INVALID_SIGNATURE'), 401);
    }

    const walletAddress = result.address.toLowerCase();

    // Normalize domain
    const domain = normalizeDomain(data.domain);
    if (!isValidDomain(domain)) {
      return c.json(apiError('Invalid domain format', 'INVALID_DOMAIN'), 400);
    }

    // Check domain uniqueness
    const domainExists = await db.select({ id: agents.id }).from(agents).where(eq(agents.domain, domain)).limit(1);
    if (domainExists.length > 0) {
      return c.json(apiError('Domain already registered', 'DOMAIN_EXISTS'), 409);
    }

    // Validate webhook
    if (data.webhookUrl && !isPublicUrl(data.webhookUrl)) {
      return c.json(apiError('Webhook URL must be a public HTTPS URL', 'INVALID_WEBHOOK_URL'), 400);
    }

    // Generate API key
    const apiKey = generateApiKey();
    const apiKeyHash = hashApiKey(apiKey);
    const apiKeyPrefix = getApiKeyPrefix(apiKey);

    const webhookSecret = data.webhookUrl ? generateWebhookSecret() : null;
    const webhookSecretEncrypted = webhookSecret ? encryptWebhookSecret(webhookSecret) : null;

    const serverDomain = domain.includes('@') ? domain.split('@')[1] : 'neuralpost.net';

    const [newAgent] = await db.insert(agents).values({
      domain,
      serverDomain,
      apiKeyHash,
      apiKeyPrefix,
      displayName: data.displayName || domain.split('@')[0],
      avatarEmoji: data.avatarEmoji || '🤖',
      bio: data.bio || null,
      capabilities: data.capabilities,
      profile: data.profile || null,
      webhookUrl: data.webhookUrl || null,
      webhookSecret: webhookSecretEncrypted,
      walletAddress,
      walletCustodyType: 'self',
      authMethod: 'wallet',
    }).returning();

    const token = generateToken(newAgent.id, newAgent.domain);

    // Auto-mint ERC-8004 NFT (same as API key register)
    if (walletAddress) {
      autoMintOnRegister({
        agentId: newAgent.id,
        domain: newAgent.domain,
        walletAddress,
        registrationURI: 'https://api.neuralpost.net/agents/' + newAgent.id,
      }).then(result => {
        if (result?.success) {
          console.log('[ERC-8004] Wallet-registered agent ' + newAgent.domain + ' minted NFT #' + result.tokenId + ' on chain ' + result.chainId);
          db.update(agents)
            .set({ chainId: result.chainId, onChainAgentId: result.tokenId, registrationTxHash: result.txHash || null })
            .where(eq(agents.id, newAgent.id))
            .then(() => console.log('[ERC-8004] DB updated: chainId=' + result.chainId + ' tokenId=' + result.tokenId))
            .catch((e: Error) => console.warn('[ERC-8004] DB update failed:', e.message));
        }
      }).catch(err => console.warn('[ERC-8004] Mint failed (non-fatal):', err.message));
    }

    return c.json(apiResponse({
      agent: {
        id: newAgent.id,
        domain: newAgent.domain,
        serverDomain: newAgent.serverDomain,
        displayName: newAgent.displayName,
        avatarEmoji: newAgent.avatarEmoji,
        bio: newAgent.bio,
        status: newAgent.status,
        isOnline: newAgent.isOnline,
        walletAddress: newAgent.walletAddress,
        walletCustody: newAgent.walletCustodyType,
        createdAt: newAgent.createdAt,
      },
      credentials: {
        apiKey,
        token,
        tokenExpiresIn: '7d',
        ...(webhookSecret && { webhookSecret }),
      },
    }, 'Agent registered with wallet'), 201);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation error: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('[SIWE] Register error:', error);
    return c.json(apiError('Registration failed', 'SERVER_ERROR'), 500);
  }
});

// POST /auth/wallet/login — Sign in with wallet (optionally specify agent_id)
const walletLoginSchema = z.object({
  message: z.string(),
  signature: z.string(),
  agent_id: z.string().uuid().optional(), // specify which agent to login as
});

auth.post('/wallet/login', async (c) => {
  try {
    const body = await c.req.json();
    const data = walletLoginSchema.parse(body);

    const result = await verifySiweSignature(data.message, data.signature);
    if (!result) {
      return c.json(apiError('Invalid or expired signature', 'INVALID_SIGNATURE'), 401);
    }

    const walletAddress = result.address.toLowerCase();

    // Find all agents for this wallet
    console.log('[Wallet Login] Looking up wallet:', walletAddress);
    const walletAgents = await db.select()
      .from(agents)
      .where(sql`lower(${agents.walletAddress}) = ${walletAddress}`);

    console.log('[Wallet Login] Found agents:', walletAgents.length, walletAgents.map(a => a.domain));

    if (walletAgents.length === 0) {
      // Debug: check what wallets exist
      const allWallets = await db.select({ domain: agents.domain, wa: agents.walletAddress })
        .from(agents)
        .limit(5);
      console.log('[Wallet Login] Sample DB wallets:', allWallets.map(a => ({ d: a.domain, w: a.wa?.substring(0, 10) })));
      return c.json(apiError(
        'No agent registered with this wallet. Register first.',
        'WALLET_NOT_FOUND'
      ), 404);
    }

    // Determine which agent to login as
    let agent;
    if (data.agent_id) {
      agent = walletAgents.find(a => a.id === data.agent_id);
      if (!agent) {
        return c.json(apiError('Agent not found for this wallet', 'AGENT_NOT_FOUND'), 404);
      }
    } else if (walletAgents.length === 1) {
      agent = walletAgents[0];
    } else {
      // Multiple agents — return list for user to choose
      return c.json(apiResponse({
        multiple: true,
        agents: walletAgents.map(a => ({
          id: a.id,
          domain: a.domain,
          displayName: a.displayName,
          avatarEmoji: a.avatarEmoji,
          status: a.status,
        })),
        message: 'Multiple agents found. Specify agent_id to login.',
      }));
    }

    if (agent.status !== 'active') {
      return c.json(apiError('Account is suspended or deactivated', 'ACCOUNT_INACTIVE'), 403);
    }

    const token = generateToken(agent.id, agent.domain);

    await db.update(agents)
      .set({ lastSeenAt: new Date(), isOnline: true })
      .where(eq(agents.id, agent.id));

    return c.json(apiResponse({
      token,
      expiresIn: '7d',
      agent: {
        id: agent.id,
        domain: agent.domain,
        displayName: agent.displayName,
        avatarEmoji: agent.avatarEmoji,
        walletAddress: agent.walletAddress || null,
        chainId: agent.chainId || null,
        onChainAgentId: agent.onChainAgentId || null,
        reputationScore: agent.reputationScore || 5000,
      },
    }, 'Signed in with wallet'));

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation error: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('[SIWE] Login error:', error);
    return c.json(apiError('Login failed', 'SERVER_ERROR'), 500);
  }
});

export default auth;
