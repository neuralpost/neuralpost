// ═══════════════════════════════════════════════════════════════════════════
// WALLET AUTH ROUTES
// Sign-In With Ethereum (SIWE / EIP-4361) authentication
// Allows agents to authenticate via wallet signature alongside API key auth
// ═══════════════════════════════════════════════════════════════════════════

import { Hono } from 'hono';
import { z } from 'zod';
import { db } from '../db';
import { agents } from '../db/schema';
import { eq, and, sql } from 'drizzle-orm';
import {
  apiResponse,
  apiError,
  generateToken,
  verifyToken,
  generateApiKey,
  hashApiKey,
  getApiKeyPrefix,
  isValidDomain,
  generateWebhookSecret,
  encryptWebhookSecret,
  isPublicUrl,
  verifyApiKey,
} from '../utils';
import {
  generateSIWENonce,
  verifySIWESignature,
  parseSIWEMessage,
  isValidEthAddress,
  generateRegistrationFile,
  getBlockchainStatus,
} from '../crypto/blockchain';


const walletAuth = new Hono();

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION SCHEMAS
// ═══════════════════════════════════════════════════════════════════════════

const walletRegisterSchema = z.object({
  // SIWE fields
  message: z.string().min(1).max(5000),
  signature: z.string().regex(/^0x[a-fA-F0-9]{130}$/, 'Invalid signature format'),

  // NeuralPost agent fields  
  domain: z.string().min(1).max(255),
  displayName: z.string().min(1).max(255).optional(),
  avatarEmoji: z.string().max(10).optional(),
  bio: z.string().max(1000).optional(),
  capabilities: z.array(z.string().max(100)).max(50).optional(),
  profile: z.object({
    description: z.string().max(2000).optional(),
    skills: z.array(z.string().max(50)).max(20).optional(),
    accepts: z.array(z.enum(['text', 'data', 'file'])).optional(),
    language: z.array(z.string().max(10)).max(10).optional(),
    metadata: z.record(z.unknown()).optional(),
  }).optional(),
  webhookUrl: z.string().url().max(2048).optional(),
  
  // On-chain fields (optional — can register off-chain first, link on-chain later)
  chainId: z.number().optional(),
  onChainAgentId: z.number().optional(),
});

const walletLoginSchema = z.object({
  message: z.string().min(1).max(5000),
  signature: z.string().regex(/^0x[a-fA-F0-9]{130}$/, 'Invalid signature format'),
  agent_id: z.string().uuid().optional(),
});

const linkWalletSchema = z.object({
  message: z.string().min(1).max(5000),
  signature: z.string().regex(/^0x[a-fA-F0-9]{130}$/, 'Invalid signature format'),
  chainId: z.number().optional(),
});

const DEFAULT_DOMAIN_SUFFIX = '@neuralpost.net';

function normalizeDomain(input: string): string {
  const trimmed = input.trim().toLowerCase();
  if (trimmed.includes('@')) return trimmed;
  const clean = trimmed.replace(/[^a-z0-9._-]/g, '');
  return `${clean}${DEFAULT_DOMAIN_SUFFIX}`;
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /wallet/nonce
// Generate SIWE nonce for wallet authentication
// ═══════════════════════════════════════════════════════════════════════════

walletAuth.get('/nonce', (c) => {
  const { nonce, expiresAt } = generateSIWENonce();
  
  return c.json(apiResponse({
    nonce,
    expiresAt: new Date(expiresAt).toISOString(),
    // SIWE message template for client to sign
    messageTemplate: {
      domain: 'neuralpost.net',
      uri: 'https://api.neuralpost.net',
      version: '1',
      statement: 'Sign in to NeuralPost — SMTP for AI Agents',
    },
  }, 'Nonce generated'));
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /wallet/register
// Register a new agent using wallet signature (SIWE)
// ═══════════════════════════════════════════════════════════════════════════

walletAuth.post('/register', async (c) => {
  try {
    const body = await c.req.json();
    const data = walletRegisterSchema.parse(body);

    // Verify SIWE signature
    const siweResult = await verifySIWESignature(data.message, data.signature);
    if (!siweResult || !siweResult.valid) {
      return c.json(apiError('Invalid wallet signature', 'INVALID_SIGNATURE'), 401);
    }

    const walletAddress = siweResult.address.toLowerCase();
    const chainId = data.chainId || siweResult.chainId;

    // Normalize and validate domain
    const domain = normalizeDomain(data.domain);
    if (!isValidDomain(domain)) {
      return c.json(apiError('Invalid domain format', 'INVALID_DOMAIN'), 400);
    }

    // Check domain uniqueness
    const existingByDomain = await db.select({ id: agents.id })
      .from(agents)
      .where(eq(agents.domain, domain))
      .limit(1);

    if (existingByDomain.length > 0) {
      return c.json(apiError('Domain already registered', 'DOMAIN_EXISTS'), 409);
    }

    // Validate webhook URL
    if (data.webhookUrl && !isPublicUrl(data.webhookUrl)) {
      return c.json(apiError(
        'Webhook URL must be a public HTTPS URL',
        'INVALID_WEBHOOK_URL'
      ), 400);
    }

    // Generate API key (agents still need API key for programmatic access)
    const apiKey = generateApiKey();
    const apiKeyHash = hashApiKey(apiKey);
    const apiKeyPrefix = getApiKeyPrefix(apiKey);

    const webhookSecret = data.webhookUrl ? generateWebhookSecret() : null;
    const webhookSecretEncrypted = webhookSecret ? encryptWebhookSecret(webhookSecret) : null;
    const serverDomain = domain.includes('@') ? domain.split('@')[1] : 'neuralpost.net';

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
        // Crypto fields
        walletAddress: walletAddress,
        chainId: chainId,
        onChainAgentId: data.onChainAgentId || null,
        walletCustodyType: 'self',
        authMethod: 'wallet',
      }).returning();
    } catch (err: any) {
      if (err.code === '23505') {
        return c.json(apiError('Domain or wallet already registered', 'CONFLICT'), 409);
      }
      throw err;
    }

    // Generate JWT
    const token = generateToken(newAgent.id, newAgent.domain);

    // Auto-mint ERC-8004 NFT
    if (walletAddress) {
      const { autoMintOnRegister } = await import('../crypto/sponsor');
      autoMintOnRegister({
        agentId: newAgent.id,
        domain: newAgent.domain,
        walletAddress,
        registrationURI: 'https://api.neuralpost.net/agents/' + newAgent.id,
      }).then(result => {
        if (result?.success) {
          console.log('[ERC-8004] wallet.ts agent ' + newAgent.domain + ' minted NFT #' + result.tokenId);
          db.update(agents)
            .set({ chainId: result.chainId, onChainAgentId: result.tokenId, registrationTxHash: result.txHash || null })
            .where(eq(agents.id, newAgent.id))
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
        walletAddress: newAgent.walletAddress || null,
        chainId: newAgent.chainId || null,
        onChainAgentId: newAgent.onChainAgentId || null,
        status: newAgent.status,
        createdAt: newAgent.createdAt,
      },
      credentials: {
        apiKey,
        token,
        tokenExpiresIn: '7d',
        ...(webhookSecret && { webhookSecret }),
      },
      blockchain: getBlockchainStatus(),
    }, 'Agent registered via wallet'), 201);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation error: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('Wallet register error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /wallet/login
// Authenticate existing agent using wallet signature
// ═══════════════════════════════════════════════════════════════════════════

walletAuth.post('/login', async (c) => {
  try {
    const body = await c.req.json();
    const data = walletLoginSchema.parse(body);

    // Verify SIWE signature
    const siweResult = await verifySIWESignature(data.message, data.signature);
    if (!siweResult || !siweResult.valid) {
      return c.json(apiError('Invalid wallet signature', 'INVALID_SIGNATURE'), 401);
    }

    const walletAddress = siweResult.address.toLowerCase();

    // Find all agents for this wallet (case-insensitive)
    const walletAgents = await db.select()
      .from(agents)
      .where(sql`lower(${agents.walletAddress}) = ${walletAddress}`);

    if (walletAgents.length === 0) {
      return c.json(apiError('No agent registered for this wallet', 'WALLET_NOT_FOUND'), 404);
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

    // Generate JWT
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
        avatarEmoji: agent.avatarEmoji || '🤖',
        walletAddress: agent.walletAddress || null,
        chainId: agent.chainId || null,
        onChainAgentId: agent.onChainAgentId || null,
        reputationScore: agent.reputationScore || 5000,
      },
    }, 'Authenticated via wallet'));

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('Wallet login error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /wallet/link
// Link a wallet to an existing API-key-registered agent
// ═══════════════════════════════════════════════════════════════════════════

walletAuth.post('/link', async (c) => {
  try {
    // Require existing auth (API key or JWT)
    const authHeader = c.req.header('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json(apiError('Authentication required', 'UNAUTHORIZED'), 401);
    }

    const body = await c.req.json();
    const data = linkWalletSchema.parse(body);

    // Verify SIWE signature
    const siweResult = await verifySIWESignature(data.message, data.signature);
    if (!siweResult || !siweResult.valid) {
      return c.json(apiError('Invalid wallet signature', 'INVALID_SIGNATURE'), 401);
    }

    const walletAddress = siweResult.address.toLowerCase();
    const chainId = data.chainId || siweResult.chainId;

    // Get current agent from auth context
    // NOTE: This uses the standard auth middleware context
    const agent = c.get('agent') as any;
    if (!agent?.id) {
      return c.json(apiError('Could not identify agent from auth', 'UNAUTHORIZED'), 401);
    }

    // Link wallet
    await db.update(agents)
      .set({ 
        walletAddress: walletAddress, 
        chainId: chainId,
        walletCustodyType: 'self',
        authMethod: 'hybrid', // Both API key and wallet
      })
      .where(eq(agents.id, agent.id));

    // Auto-mint ERC-8004 NFT if agent doesn't have one yet
    const { autoMintOnRegister } = await import('../crypto/sponsor');
    autoMintOnRegister({
      agentId: agent.id,
      domain: agent.domain,
      walletAddress,
      registrationURI: 'https://api.neuralpost.net/agents/' + agent.id,
    }).then(result => {
      if (result?.success) {
        console.log('[ERC-8004] Linked agent ' + agent.domain + ' minted NFT #' + result.tokenId);
        db.update(agents)
          .set({ chainId: result.chainId, onChainAgentId: result.tokenId, registrationTxHash: result.txHash || null })
          .where(eq(agents.id, agent.id))
          .catch((e: Error) => console.warn('[ERC-8004] DB update failed:', e.message));
      }
    }).catch(err => console.warn('[ERC-8004] Mint on link failed (non-fatal):', err.message));

    return c.json(apiResponse({
      linked: true,
      walletAddress,
      chainId,
      agentId: agent.id,
      domain: agent.domain,
    }, 'Wallet linked successfully'));

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('Link wallet error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /wallet/info
// Get current agent's wallet info (requires JWT auth)
// ═══════════════════════════════════════════════════════════════════════════

walletAuth.get('/info', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json(apiError('JWT required', 'UNAUTHORIZED'), 401);
    }
    const decoded = verifyToken(authHeader.slice(7));
    if (!decoded) return c.json(apiError('Invalid token', 'UNAUTHORIZED'), 401);

    const [agent] = await db.select().from(agents).where(eq(agents.id, decoded.agentId)).limit(1);
    if (!agent) return c.json(apiError('Agent not found', 'NOT_FOUND'), 404);

    return c.json(apiResponse({
      walletAddress: agent.walletAddress || null,
      custodyType: agent.walletCustodyType || null,
      chainId: agent.chainId || null,
      onChainAgentId: agent.onChainAgentId || null,
      reputationScore: agent.reputationScore || 5000,
      x402Enabled: agent.x402Enabled || false,
      keyExported: !!agent.keyExportedAt,
      keyExportedAt: agent.keyExportedAt || null,
      hasWallet: !!agent.walletAddress,
      isProtocolCustodied: agent.walletCustodyType === 'protocol' && !agent.keyExportedAt,
    }, 'Wallet info'));
  } catch (error) {
    console.error('Wallet info error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /wallet/export
// Export private key of protocol-generated wallet
// Agent must confirm they understand the risks
// After export, custody type changes to 'self'
// ═══════════════════════════════════════════════════════════════════════════

walletAuth.post('/export', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json(apiError('Authorization required', 'UNAUTHORIZED'), 401);
    }
    const token = authHeader.slice(7);

    let agent: any;

    // Check if it's an API key (sk_...) or JWT
    if (token.startsWith('sk_')) {
      // API key auth — verify against stored hash
      const prefix = getApiKeyPrefix(token);
      const [found] = await db.select().from(agents)
        .where(eq(agents.apiKeyPrefix, prefix)).limit(1);
      if (!found || !verifyApiKey(token, found.apiKeyHash)) {
        return c.json(apiError('Invalid API key', 'UNAUTHORIZED'), 401);
      }
      agent = found;
    } else {
      // JWT auth
      const decoded = verifyToken(token);
      if (!decoded) return c.json(apiError('Invalid token', 'UNAUTHORIZED'), 401);
      const [found] = await db.select().from(agents).where(eq(agents.id, decoded.agentId)).limit(1);
      if (!found) return c.json(apiError('Agent not found', 'NOT_FOUND'), 404);
      agent = found;
    }

    const body = await c.req.json();
    const { confirmExport } = z.object({
      confirmExport: z.literal(true, { errorMap: () => ({ message: 'Must confirm export with confirmExport: true' }) }),
    }).parse(body);

    if (!agent.walletAddress) {
      return c.json(apiError('No wallet associated with this agent', 'NO_WALLET'), 400);
    }

    if (!agent.encryptedPrivateKey) {
      return c.json(apiError(
        'This wallet was not created by NeuralPost (self-custodied). ' +
        'Private key is not stored on our servers.',
        'SELF_CUSTODIED'
      ), 400);
    }

    // Decrypt and return private key
    const { exportWallet: doExport } = await import('../crypto/wallet');
    const result = doExport(agent.encryptedPrivateKey);

    // Mark as exported — custody transitions to 'self'
    await db.update(agents)
      .set({
        keyExportedAt: new Date(),
        walletCustodyType: 'self',
      })
      .where(eq(agents.id, agent.id));

    return c.json(apiResponse({
      address: result.address,
      privateKey: result.privateKey,
      warning: result.warning,
      custodyType: 'self',
      exportedAt: new Date().toISOString(),
      importInstructions: {
        metamask: 'Settings → Security → Import Private Key → paste the privateKey',
        rainbow: 'Settings → Wallets → Add Wallet → Import → paste the privateKey',
        trust: 'Settings → Wallets → Import → Ethereum → paste the privateKey',
      },
    }, 'Private key exported. You now have full control of this wallet.'));

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('Export wallet error:', error);
    return c.json(apiError('Internal server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /wallet/set-agent-wallet/params
// Returns EIP-712 typed data for self-custodied wallets to sign in MetaMask
// ═══════════════════════════════════════════════════════════════════════════

walletAuth.get('/set-agent-wallet/params', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json(apiError('Authorization required', 'UNAUTHORIZED'), 401);
    }
    const decoded = verifyToken(authHeader.slice(7));
    if (!decoded) return c.json(apiError('Invalid token', 'UNAUTHORIZED'), 401);

    const [agent] = await db.select().from(agents).where(eq(agents.id, decoded.agentId)).limit(1);
    if (!agent) return c.json(apiError('Agent not found', 'NOT_FOUND'), 404);
    if (!agent.onChainAgentId || !agent.chainId) {
      return c.json(apiError('Agent has no NFT yet', 'NO_NFT'), 400);
    }
    if (!agent.walletAddress) {
      return c.json(apiError('No wallet address', 'NO_WALLET'), 400);
    }

    const { CHAIN_CONFIGS } = await import('../crypto/types');
    const chain = CHAIN_CONFIGS[agent.chainId as keyof typeof CHAIN_CONFIGS];
    if (!chain?.contracts?.identityRegistry) {
      return c.json(apiError('Chain not configured', 'UNSUPPORTED_CHAIN'), 400);
    }

    const deadline = Math.floor(Date.now() / 1000) + 600; // 10 min

    return c.json(apiResponse({
      domain: {
        name: 'ERC8004IdentityRegistry',
        version: '1',
        chainId: agent.chainId,
        verifyingContract: chain.contracts.identityRegistry,
      },
      types: {
        AgentWalletSet: [
          { name: 'agentId', type: 'uint256' },
          { name: 'newWallet', type: 'address' },
          { name: 'owner', type: 'address' },
          { name: 'deadline', type: 'uint256' },
        ],
      },
      value: {
        agentId: agent.onChainAgentId.toString(),
        newWallet: agent.walletAddress,
        owner: agent.walletAddress,
        deadline: deadline.toString(),
      },
      deadline,
      chainId: agent.chainId,
      contractAddress: chain.contracts.identityRegistry,
      tokenId: agent.onChainAgentId,
    }, 'EIP-712 params for setAgentWallet'));
  } catch (error: any) {
    console.error('[SetAgentWallet/params]', error.message);
    return c.json(apiError('Server error', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /wallet/set-agent-wallet
// Accepts EIP-712 signature from MetaMask, calls contract via sponsor wallet
// ═══════════════════════════════════════════════════════════════════════════

const setAgentWalletSchema = z.object({
  signature: z.string().regex(/^0x[a-fA-F0-9]+$/, 'Invalid signature'),
  deadline: z.number().int().positive(),
});

walletAuth.post('/set-agent-wallet', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json(apiError('Authorization required', 'UNAUTHORIZED'), 401);
    }
    const decoded = verifyToken(authHeader.slice(7));
    if (!decoded) return c.json(apiError('Invalid token', 'UNAUTHORIZED'), 401);

    const [agent] = await db.select().from(agents).where(eq(agents.id, decoded.agentId)).limit(1);
    if (!agent) return c.json(apiError('Agent not found', 'NOT_FOUND'), 404);
    if (!agent.onChainAgentId || !agent.chainId) {
      return c.json(apiError('Agent has no NFT minted yet', 'NO_NFT'), 400);
    }
    if (!agent.walletAddress) {
      return c.json(apiError('Agent has no wallet address', 'NO_WALLET'), 400);
    }

    const body = await c.req.json();
    const data = setAgentWalletSchema.parse(body);

    const { CHAIN_CONFIGS, IDENTITY_REGISTRY_ABI } = await import('../crypto/types');
    const { Wallet, Contract, JsonRpcProvider } = await import('ethers');

    const chain = CHAIN_CONFIGS[agent.chainId as keyof typeof CHAIN_CONFIGS];
    if (!chain?.contracts?.identityRegistry) {
      return c.json(apiError('Chain not configured', 'UNSUPPORTED_CHAIN'), 400);
    }

    const sponsorKey = process.env.SPONSOR_WALLET_KEY;
    if (!sponsorKey) {
      return c.json(apiError('Sponsor wallet not configured', 'SERVER_ERROR'), 500);
    }

    const provider = new JsonRpcProvider(chain.rpcUrl);
    const sponsorWallet = new Wallet(sponsorKey, provider);
    const registry = new Contract(chain.contracts.identityRegistry, IDENTITY_REGISTRY_ABI, sponsorWallet);

    console.log(`[SetAgentWallet] Calling for agent ${agent.domain}, tokenId=${agent.onChainAgentId}, wallet=${agent.walletAddress}`);

    const setTx = await registry.setAgentWallet(
      agent.onChainAgentId,
      agent.walletAddress,
      data.deadline,
      data.signature,
      { gasLimit: 500000 }
    );
    const receipt = await setTx.wait(1);

    if (!receipt || receipt.status === 0) {
      throw new Error('Transaction reverted');
    }

    console.log(`[SetAgentWallet] ✅ ${agent.domain} wallet set on-chain, tx: ${setTx.hash}`);

    return c.json(apiResponse({
      success: true,
      txHash: setTx.hash,
      tokenId: agent.onChainAgentId,
      walletAddress: agent.walletAddress,
    }, 'Agent wallet set on-chain'));

  } catch (error: any) {
    console.error('[SetAgentWallet] Error:', error.message);
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    return c.json(apiError(error.reason || error.message || 'Failed to set agent wallet', 'CONTRACT_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /wallet/status
// Get blockchain integration status
// ═══════════════════════════════════════════════════════════════════════════

walletAuth.get('/status', (c) => {
  return c.json(apiResponse(getBlockchainStatus(), 'Blockchain status'));
});

export default walletAuth;
