import { Hono } from 'hono';
import { z } from 'zod';
import { db } from '../db';
import { agents, messageRequests, connections, threads, threadParticipants, messages, messageRecipients } from '../db/schema';
import { eq, like, or, and, sql, desc, lt, gt } from 'drizzle-orm';
import { authMiddleware } from '../middleware/auth';
import { apiResponse, apiError } from '../utils';
import {
  scanClient,
  ERC8004ScanError,
  type ScanSearchParams,
  type DiscoveredAgent,
} from '../services/erc8004scan';

const discoverRoute = new Hono();

// Auth required for all discovery endpoints
discoverRoute.use('/*', authMiddleware);

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION SCHEMAS
// ═══════════════════════════════════════════════════════════════════════════

const discoverQuerySchema = z.object({
  q: z.string().min(1).max(200).optional(),
  categories: z.string().max(500).optional(),     // comma-separated
  chain_id: z.coerce.number().int().optional(),
  verified: z.enum(['true', 'false']).optional(),
  testnet: z.enum(['true', 'false']).optional(),
  has_a2a: z.enum(['true', 'false']).optional(),
  has_mcp: z.enum(['true', 'false']).optional(),
  x402: z.enum(['true', 'false']).optional(),
  min_score: z.coerce.number().min(0).max(1).optional(),
  trust_model: z.string().max(100).optional(),
  tags: z.string().max(500).optional(),
  owner_address: z.string().max(42).optional(),
  sort: z.enum(['score', 'newest', 'stars', 'feedbacks']).optional(),
  source: z.enum(['all', 'local', 'erc8004']).optional(),
  limit: z.coerce.number().int().min(1).max(50).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /discover
// Unified discovery: search local NeuralPost agents + ERC-8004 ecosystem
//
// Query params:
//   q          - Text search (name, description, domain)
//   categories - Comma-separated categories (defi, ai, security, ...)
//   chain_id   - Filter by chain ID
//   verified   - Only verified agents
//   testnet    - Include testnet agents (default: true)
//   has_a2a    - Has A2A Protocol endpoint
//   has_mcp    - Has MCP server
//   x402       - Supports x402 payments
//   min_score  - Minimum score (0.0 - 1.0)
//   sort       - Sort by: score, newest, stars, feedbacks
//   source     - Data source: all (default), local, erc8004
//   limit      - Results per page (1-50, default 20)
//   offset     - Pagination offset
// ═══════════════════════════════════════════════════════════════════════════

discoverRoute.get('/', async (c) => {
  try {
    const raw = c.req.query();
    const params = discoverQuerySchema.parse(raw);

    const source = params.source || 'all';
    const limit = params.limit || 20;
    const offset = params.offset || 0;

    // Results from both sources
    let localResults: LocalAgentResult[] = [];
    let externalResults: DiscoveredAgent[] = [];
    let externalTotal = 0;
    let scanError: string | null = null;

    // ─── Local search ──────────────────────────────────────────────

    if (source === 'all' || source === 'local') {
      localResults = await searchLocalAgents(params, limit, offset);
    }

    // ─── 8004scan search ───────────────────────────────────────────

    if ((source === 'all' || source === 'erc8004') && scanClient.isConfigured()) {
      try {
        const scanParams = buildScanParams(params, limit, offset);
        const scanResponse = await scanClient.searchAgents(scanParams);

        externalResults = scanClient.normalizeMany(scanResponse.items);
        externalTotal = scanResponse.total;
      } catch (err) {
        if (err instanceof ERC8004ScanError) {
          scanError = `8004scan: ${err.code}`;
          console.warn(`[Discover] 8004scan error: ${err.message}`);
        } else {
          scanError = '8004scan: unavailable';
          console.error('[Discover] 8004scan unexpected error:', err);
        }
      }
    } else if (source === 'erc8004' && !scanClient.isConfigured()) {
      scanError = '8004scan: not configured (missing ERC8004SCAN_API_KEY)';
    }

    // ─── Merge & deduplicate ───────────────────────────────────────

    // Convert local agents to unified format
    const localDiscovered = localResults.map(toDiscoveredLocal);

    // Deduplicate: if a local agent has walletAddress matching an external agent's
    // ownerAddress or agentWallet, prefer the merged version
    const merged = mergeResults(localDiscovered, externalResults);

    // ─── Sort merged results ─────────────────────────────────────
    const sortBy = params.sort || 'newest';
    merged.sort((a, b) => {
      if (sortBy === 'newest') return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
      if (sortBy === 'score') return (b.scores?.total || 0) - (a.scores?.total || 0);
      if (sortBy === 'stars') return (b.stars || 0) - (a.stars || 0);
      if (sortBy === 'feedbacks') return (b.reputation?.feedbacks || 0) - (a.reputation?.feedbacks || 0);
      return 0;
    });

    return c.json(apiResponse({
      agents: merged,
      pagination: {
        limit,
        offset,
        local_count: localResults.length,
        external_count: externalResults.length,
        external_total: externalTotal,
        merged_count: merged.length,
      },
      sources: {
        local: source !== 'erc8004',
        erc8004: source !== 'local' && scanClient.isConfigured(),
        erc8004_error: scanError,
      },
      rate_limit: scanClient.isConfigured()
        ? scanClient.getRateLimitStatus()
        : null,
    }));

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Invalid query: ' + error.errors[0].message, 'VALIDATION_ERROR'), 400);
    }
    console.error('[Discover] Error:', error);
    return c.json(apiError('Discovery failed', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /discover/agent/:chain/:tokenId
// Get detailed agent profile from 8004scan
// ═══════════════════════════════════════════════════════════════════════════

discoverRoute.get('/agent/:chain/:tokenId', async (c) => {
  try {
    const chain = c.req.param('chain');
    const tokenId = c.req.param('tokenId');

    if (!scanClient.isConfigured()) {
      return c.json(apiError('8004scan not configured', 'NOT_CONFIGURED'), 503);
    }

    const raw = await scanClient.getAgent(chain, tokenId);
    const agent = scanClient.normalize(raw);

    // Check if this agent exists locally (by wallet address match)
    const localMatch = await findLocalByWallet(raw.owner_address, raw.agent_wallet);

    return c.json(apiResponse({
      agent,
      local_match: localMatch ? {
        id: localMatch.id,
        domain: localMatch.domain,
        displayName: localMatch.displayName,
        isOnline: localMatch.isOnline,
      } : null,
    }));

  } catch (err) {
    if (err instanceof ERC8004ScanError) {
      const status = err.code === 'RATE_LIMITED' ? 429 : err.code === 'AUTH_ERROR' ? 401 : 502;
      return c.json(apiError(err.message, err.code), status);
    }
    console.error('[Discover] Agent detail error:', err);
    return c.json(apiError('Failed to fetch agent', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /discover/agent/:chain/:tokenId/feedbacks
// Get feedbacks/reviews for an agent
// ═══════════════════════════════════════════════════════════════════════════

discoverRoute.get('/agent/:chain/:tokenId/feedbacks', async (c) => {
  try {
    const chain = c.req.param('chain');
    const tokenId = c.req.param('tokenId');

    if (!scanClient.isConfigured()) {
      return c.json(apiError('8004scan not configured', 'NOT_CONFIGURED'), 503);
    }

    const feedbacks = await scanClient.getAgentFeedbacks(chain, tokenId);

    return c.json(apiResponse({ feedbacks }));

  } catch (err) {
    if (err instanceof ERC8004ScanError) {
      const status = err.code === 'RATE_LIMITED' ? 429 : 502;
      return c.json(apiError(err.message, err.code), status);
    }
    console.error('[Discover] Feedbacks error:', err);
    return c.json(apiError('Failed to fetch feedbacks', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /discover/categories
// Get available categories from 8004scan ecosystem
// ═══════════════════════════════════════════════════════════════════════════

discoverRoute.get('/categories', async (c) => {
  // Known ERC-8004 categories observed from the API data
  const categories = [
    { slug: 'defi', label: 'DeFi', description: 'Decentralized finance agents' },
    { slug: 'ai', label: 'AI', description: 'Artificial intelligence and ML agents' },
    { slug: 'security', label: 'Security', description: 'Auditing, monitoring, and protection' },
    { slug: 'analytics', label: 'Analytics', description: 'Data analysis and insights' },
    { slug: 'infrastructure', label: 'Infrastructure', description: 'Blockchain infrastructure tools' },
    { slug: 'nft', label: 'NFT', description: 'NFT creation and management' },
    { slug: 'gaming', label: 'Gaming', description: 'Blockchain gaming agents' },
    { slug: 'governance', label: 'Governance', description: 'DAO and governance tools' },
    { slug: 'social', label: 'Social', description: 'Social and community agents' },
    { slug: 'data', label: 'Data', description: 'Data indexing and streaming' },
    { slug: 'trading', label: 'Trading', description: 'Trading and market-making' },
    { slug: 'lending', label: 'Lending', description: 'Lending protocol agents' },
  ];

  return c.json(apiResponse({ categories }));
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /discover/stats
// Ecosystem statistics
// ═══════════════════════════════════════════════════════════════════════════

discoverRoute.get('/stats', async (c) => {
  try {
    // Local agent count
    const [localCount] = await db.select({
      count: sql<number>`count(*)::int`,
    })
    .from(agents)
    .where(eq(agents.status, 'active'));

    // 8004scan total (from cached search)
    let externalTotal = 0;
    let scanAvailable = false;

    if (scanClient.isConfigured()) {
      try {
        const res = await scanClient.searchAgents({ limit: 1 });
        externalTotal = res.total;
        scanAvailable = true;
      } catch {
        scanAvailable = false;
      }
    }

    return c.json(apiResponse({
      local_agents: localCount.count,
      erc8004_agents: externalTotal,
      total_discoverable: localCount.count + externalTotal,
      sources: {
        local: true,
        erc8004: scanAvailable,
      },
      rate_limit: scanClient.isConfigured()
        ? scanClient.getRateLimitStatus()
        : null,
      cache: scanClient.getCacheStats(),
    }));

  } catch (error) {
    console.error('[Discover] Stats error:', error);
    return c.json(apiError('Failed to get stats', 'SERVER_ERROR'), 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS
// ═══════════════════════════════════════════════════════════════════════════

// ─── Types ───────────────────────────────────────────────────────────────

interface LocalAgentResult {
  id: string;
  domain: string;
  serverDomain: string;
  displayName: string | null;
  avatarEmoji: string | null;
  bio: string | null;
  capabilities: string[] | null;
  profile: Record<string, unknown> | null;
  isOnline: boolean | null;
  walletAddress: string | null;
  chainId: number | null;
  onChainAgentId: number | null;
  reputationScore: number | null;
  registrationUri: string | null;
  x402Enabled: boolean | null;
  createdAt: Date | null;
  connectionCount: number;
}

// ─── Local DB Search ─────────────────────────────────────────────────────

async function searchLocalAgents(
  params: z.infer<typeof discoverQuerySchema>,
  limit: number,
  offset: number,
): Promise<LocalAgentResult[]> {
  const conditions: any[] = [eq(agents.status, 'active')];

  // Text search
  if (params.q && params.q.length >= 2) {
    const pattern = `%${params.q.toLowerCase().replace(/[%_\\]/g, '\\$&')}%`;
    conditions.push(
      or(
        like(agents.domain, pattern),
        sql`lower(${agents.displayName}) LIKE ${pattern}`,
        sql`lower(${agents.bio}) LIKE ${pattern}`,
      )
    );
  }

  // x402 filter
  if (params.x402 === 'true') {
    conditions.push(eq(agents.x402Enabled, true));
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
    walletAddress: agents.walletAddress,
    chainId: agents.chainId,
      registrationTxHash: agents.registrationTxHash,
    onChainAgentId: agents.onChainAgentId,
    reputationScore: agents.reputationScore,
    registrationUri: agents.registrationUri,
    x402Enabled: agents.x402Enabled,
    createdAt: agents.createdAt,
  })
  .from(agents)
  .where(and(...conditions))
  .orderBy(
    params.sort === 'newest' ? desc(agents.createdAt) :
    params.sort === 'score' ? desc(agents.reputationScore) :
    desc(agents.createdAt)
  )
  .limit(limit)
  .offset(offset);

  // Fetch connection counts for all returned agents
  const agentIds = results.map(r => r.id);
  let connCounts: Record<string, number> = {};
  if (agentIds.length > 0) {
    try {
      const accepted = await db.select({
        requesterId: connections.requesterId,
        targetId: connections.targetId,
      })
      .from(connections)
      .where(eq(connections.status, 'accepted'));

      for (const c of accepted) {
        if (agentIds.includes(c.requesterId)) {
          connCounts[c.requesterId] = (connCounts[c.requesterId] || 0) + 1;
        }
        if (agentIds.includes(c.targetId)) {
          connCounts[c.targetId] = (connCounts[c.targetId] || 0) + 1;
        }
      }
    } catch (e) {
      console.error('[Discover] Connection count failed:', e);
    }
  }

  const withCounts = results.map(r => ({ ...r, connectionCount: connCounts[r.id] || 0 }));

  // Sort by stars in JS if needed
  if (params.sort === 'stars') {
    withCounts.sort((a, b) => b.connectionCount - a.connectionCount);
  }

  return withCounts;
}

// ─── Build 8004scan params ───────────────────────────────────────────────

function buildScanParams(
  params: z.infer<typeof discoverQuerySchema>,
  limit: number,
  offset: number,
): ScanSearchParams {
  const scanParams: ScanSearchParams = {
    limit,
    offset,
  };

  if (params.q) scanParams.search = params.q;
  if (params.categories) scanParams.categories = params.categories.split(',').map(s => s.trim());
  if (params.chain_id) scanParams.chain_id = params.chain_id;
  if (params.verified === 'true') scanParams.is_verified = true;
  if (params.testnet !== undefined) scanParams.is_testnet = params.testnet === 'true';
  if (params.has_a2a === 'true') scanParams.has_a2a = true;
  if (params.has_mcp === 'true') scanParams.has_mcp = true;
  if (params.x402 === 'true') scanParams.x402 = true;
  if (params.min_score !== undefined) scanParams.min_score = params.min_score;
  if (params.trust_model) scanParams.trust_model = params.trust_model;
  if (params.tags) scanParams.tags = params.tags;
  if (params.owner_address) scanParams.owner_address = params.owner_address;

  // Sort mapping — use safe fallback for external API
  if (params.sort) {
    const sortMap: Record<string, ScanSearchParams['sort_by']> = {
      'score': 'total_score',
      'newest': 'created_at',
      'stars': 'total_score',      // fallback: 8004scan may not support star_count
      'feedbacks': 'total_feedbacks',
    };
    scanParams.sort_by = sortMap[params.sort] || 'total_score';
    scanParams.sort_order = 'desc';
  }

  return scanParams;
}

// ─── Convert local agent → DiscoveredAgent ───────────────────────────────

function toDiscoveredLocal(agent: LocalAgentResult): DiscoveredAgent {
  const profile = agent.profile as Record<string, unknown> | null;
  const skills = (profile?.skills as string[]) || agent.capabilities || [];
  const description = (profile?.description as string) || agent.bio || '';

  return {
    source: 'local',
    scanId: '',
    agentId: agent.onChainAgentId
      ? `${agent.chainId}:neuralpost:${agent.onChainAgentId}`
      : `local:${agent.id}`,
    tokenId: agent.onChainAgentId || 0,
    chainId: agent.chainId || 0,
    isTestnet: false,
    contractAddress: agent.chainId === 324705682 ? (process.env.SKALE_BASE_SEP_IDENTITY_REGISTRY || '0xf7b202D79773C26464f447Ad1a58EE4287f7eD12') : '',

    name: agent.displayName || agent.domain,
    npDomain: agent.domain,  // actual NeuralPost domain for messaging
    description,
    imageUrl: null,
    categories: skills.slice(0, 5),
    tags: [],

    ownerAddress: agent.walletAddress || '',
    ownerEns: null,
    agentWallet: agent.walletAddress || '',

    isVerified: false,
    isEndpointVerified: false,
    verifiedDomain: null,
    isActive: true,
    healthStatus: agent.isOnline ? 'online' : 'offline',
    healthScore: null,
    scores: {
      total: 0,  // new agents start at 0
      quality: 0,
      popularity: 0,
      activity: 0,
      wallet: agent.walletAddress ? 0.5 : 0,
      freshness: 0,
      completeness: 0,
    },
    reputation: {
      feedbacks: 0,
      validations: 0,
      successfulValidations: 0,
      averageScore: 0,  // new agents have no feedback yet
      rank: null,
    },
    stars: agent.connectionCount || 0,

    x402Supported: agent.x402Enabled || false,
    protocols: [],
    a2aEndpoint: `https://${agent.serverDomain}/a2a/${agent.domain}`,
    a2aVersion: '0.3',
    mcpServer: null,
    mcpVersion: null,
    services: [{
      name: 'A2A',
      endpoint: `https://${agent.serverDomain}/a2a/${agent.domain}`,
      version: '0.3',
    }],

    crossChainLinks: [],

    ens: null,
    did: null,

    parseStatus: null,
    parseWarnings: 0,

    scanUrl: '',
    explorerUrl: agent.chainId === 324705682 ? 'https://base-sepolia-testnet-explorer.skalenodes.com' : '',
    txHash: (agent as any).registrationTxHash || '',

    createdAt: agent.createdAt?.toISOString() || new Date().toISOString(),
    updatedAt: agent.createdAt?.toISOString() || new Date().toISOString(),
  };
}

// ─── Merge & deduplicate ─────────────────────────────────────────────────

interface MergedAgent extends DiscoveredAgent {
  localId?: string;        // NeuralPost agent UUID if exists locally
  localDomain?: string;    // NeuralPost domain if exists locally
  isOnNeuralPost: boolean; // Whether agent is registered on NeuralPost
}

function mergeResults(
  local: DiscoveredAgent[],
  external: DiscoveredAgent[],
): MergedAgent[] {
  const merged: MergedAgent[] = [];
  const matchedExternalIds = new Set<string>();

  // Index external by wallet addresses for fast lookup
  const externalByWallet = new Map<string, DiscoveredAgent>();
  for (const ext of external) {
    if (ext.ownerAddress) {
      externalByWallet.set(ext.ownerAddress.toLowerCase(), ext);
    }
    if (ext.agentWallet && ext.agentWallet !== ext.ownerAddress) {
      externalByWallet.set(ext.agentWallet.toLowerCase(), ext);
    }
  }

  // Process local agents — try to find matching external
  for (const loc of local) {
    const walletLower = loc.ownerAddress?.toLowerCase();
    const externalMatch = walletLower ? externalByWallet.get(walletLower) : undefined;

    if (externalMatch) {
      // Merge: enrich local with external data
      matchedExternalIds.add(externalMatch.scanId);
      merged.push({
        ...externalMatch,               // External has richer data
        source: 'both',
        localId: loc.agentId.startsWith('local:') ? loc.agentId.slice(6) : undefined,
        localDomain: loc.a2aEndpoint ? loc.a2aEndpoint.split('/a2a/').pop() : loc.name,
        isOnNeuralPost: true,
        // Override with live NeuralPost data
        a2aEndpoint: loc.a2aEndpoint || externalMatch.a2aEndpoint,
        healthStatus: loc.healthStatus || externalMatch.healthStatus,
      });
    } else {
      // Local only
      merged.push({
        ...loc,
        source: 'local',
        localId: loc.agentId.startsWith('local:') ? loc.agentId.slice(6) : undefined,
        localDomain: loc.a2aEndpoint ? loc.a2aEndpoint.split('/a2a/').pop() : loc.name,
        isOnNeuralPost: true,
      });
    }
  }

  // Add remaining external agents (not matched to local)
  for (const ext of external) {
    if (!matchedExternalIds.has(ext.scanId)) {
      merged.push({
        ...ext,
        source: 'erc8004',
        isOnNeuralPost: false,
      });
    }
  }

  return merged;
}

// ─── Find local agent by wallet address ──────────────────────────────────

async function findLocalByWallet(ownerAddress: string, agentWallet: string) {
  const addresses = [ownerAddress, agentWallet]
    .filter(Boolean)
    .map(a => a.toLowerCase());

  if (addresses.length === 0) return null;

  const conditions = addresses.map(addr =>
    sql`lower(${agents.walletAddress}) = ${addr}`
  );

  const [match] = await db.select({
    id: agents.id,
    domain: agents.domain,
    displayName: agents.displayName,
    isOnline: agents.isOnline,
  })
  .from(agents)
  .where(and(
    eq(agents.status, 'active'),
    or(...conditions),
  ))
  .limit(1);

  return match || null;
}

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE REQUESTS — Send messages to agents not yet on NeuralPost
// Stored for 24 hours. When target agent registers, they see the messages.
// ═══════════════════════════════════════════════════════════════════════════

const messageRequestSchema = z.object({
  target_wallet_address: z.string().optional(),
  target_agent_id: z.string().optional(),
  target_token_id: z.coerce.number().int().optional(),
  target_chain_id: z.coerce.number().int().optional(),
  target_name: z.string().max(255).optional(),
  subject: z.string().max(500).optional(),
  body: z.string().min(1).max(5000),
});

// POST /discover/message-request — Send a message request to an external agent
discoverRoute.post('/message-request', async (c) => {
  try {
    const agent = c.get('agent' as never) as { id: string; domain: string };
    const data = messageRequestSchema.parse(await c.req.json());

    if (!data.target_wallet_address && !data.target_agent_id) {
      return c.json(apiError('Either target_wallet_address or target_agent_id is required', 'VALIDATION_ERROR'), 400);
    }

    // Rate limit: max 10 pending requests per sender
    const [pendingCount] = await db.select({ count: sql<number>`count(*)::int` })
      .from(messageRequests)
      .where(and(
        eq(messageRequests.senderAgentId, agent.id),
        eq(messageRequests.status, 'pending'),
      ));

    if (pendingCount.count >= 10) {
      return c.json(apiError('Maximum 10 pending message requests allowed', 'RATE_LIMITED'), 429);
    }

    // Check if target is already on NeuralPost (by wallet)
    if (data.target_wallet_address) {
      const existing = await findLocalByWallet(data.target_wallet_address, data.target_wallet_address);
      if (existing) {
        return c.json(apiError(
          `This agent is already on NeuralPost as "${existing.displayName || existing.domain}". Send them a direct message instead.`,
          'AGENT_EXISTS'
        ), 409);
      }
    }

    // 24 hour expiry
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    const [request] = await db.insert(messageRequests).values({
      senderAgentId: agent.id,
      targetWalletAddress: data.target_wallet_address?.toLowerCase() || null,
      targetAgentId: data.target_agent_id || null,
      targetTokenId: data.target_token_id || null,
      targetChainId: data.target_chain_id || null,
      targetName: data.target_name || null,
      subject: data.subject || null,
      body: data.body,
      status: 'pending',
      expiresAt,
    }).returning();

    console.log(`[MessageRequest] Created ${request.id} from ${agent.domain} → ${data.target_wallet_address || data.target_agent_id}`);

    return c.json(apiResponse({
      id: request.id,
      status: 'pending',
      expires_at: expiresAt.toISOString(),
      message: 'Message request sent. It will be delivered when the agent joins NeuralPost (expires in 24 hours).',
    }), 201);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json(apiError('Validation error: ' + error.errors.map((e: any) => e.message).join(', '), 'VALIDATION_ERROR'), 400);
    }
    console.error('[MessageRequest] Error:', error);
    return c.json(apiError('Failed to send message request', 'SERVER_ERROR'), 500);
  }
});

// GET /discover/message-requests — List sent message requests
discoverRoute.get('/message-requests', async (c) => {
  try {
    const agent = c.get('agent' as never) as { id: string };

    const requests = await db.select({
      id: messageRequests.id,
      targetWalletAddress: messageRequests.targetWalletAddress,
      targetAgentId: messageRequests.targetAgentId,
      targetTokenId: messageRequests.targetTokenId,
      targetChainId: messageRequests.targetChainId,
      targetName: messageRequests.targetName,
      subject: messageRequests.subject,
      body: messageRequests.body,
      status: messageRequests.status,
      expiresAt: messageRequests.expiresAt,
      createdAt: messageRequests.createdAt,
      deliveredAt: messageRequests.deliveredAt,
    })
    .from(messageRequests)
    .where(eq(messageRequests.senderAgentId, agent.id))
    .orderBy(desc(messageRequests.createdAt))
    .limit(50);

    return c.json(apiResponse({ requests }));
  } catch (error) {
    console.error('[MessageRequest] List error:', error);
    return c.json(apiError('Failed to list message requests', 'SERVER_ERROR'), 500);
  }
});

// GET /discover/pending-requests — Check for message requests targeting this agent (by wallet)
// Called after login to check if anyone sent message requests before registration
discoverRoute.get('/pending-requests', async (c) => {
  try {
    const agent = c.get('agent' as never) as { id: string; walletAddress?: string };

    // Find agent's wallet address
    const [agentData] = await db.select({ walletAddress: agents.walletAddress })
      .from(agents)
      .where(eq(agents.id, agent.id));

    if (!agentData?.walletAddress) {
      return c.json(apiResponse({ requests: [], count: 0 }));
    }

    const wallet = agentData.walletAddress.toLowerCase();
    const now = new Date();

    const pending = await db.select({
      id: messageRequests.id,
      senderAgentId: messageRequests.senderAgentId,
      subject: messageRequests.subject,
      body: messageRequests.body,
      createdAt: messageRequests.createdAt,
    })
    .from(messageRequests)
    .where(and(
      eq(messageRequests.targetWalletAddress, wallet),
      eq(messageRequests.status, 'pending'),
      gt(messageRequests.expiresAt, now),
    ))
    .orderBy(desc(messageRequests.createdAt));

    return c.json(apiResponse({ requests: pending, count: pending.length }));
  } catch (error) {
    console.error('[MessageRequest] Pending check error:', error);
    return c.json(apiError('Failed to check pending requests', 'SERVER_ERROR'), 500);
  }
});

// POST /discover/claim-requests — Deliver pending message requests to newly registered agent
// Creates connection + thread + message so conversation appears seamlessly in inbox
discoverRoute.post('/claim-requests', async (c) => {
  try {
    const agent = c.get('agent' as never) as { id: string };

    const [agentData] = await db.select({ walletAddress: agents.walletAddress })
      .from(agents)
      .where(eq(agents.id, agent.id));

    if (!agentData?.walletAddress) {
      return c.json(apiResponse({ claimed: 0, threads: [] }));
    }

    const wallet = agentData.walletAddress.toLowerCase();
    const now = new Date();

    // Get full pending requests (need sender, subject, body)
    const pending = await db.select({
      id: messageRequests.id,
      senderAgentId: messageRequests.senderAgentId,
      subject: messageRequests.subject,
      body: messageRequests.body,
      createdAt: messageRequests.createdAt,
    })
    .from(messageRequests)
    .where(and(
      eq(messageRequests.targetWalletAddress, wallet),
      eq(messageRequests.status, 'pending'),
      gt(messageRequests.expiresAt, now),
    ))
    .orderBy(desc(messageRequests.createdAt));

    if (pending.length === 0) {
      return c.json(apiResponse({ claimed: 0, threads: [] }));
    }

    const createdThreads: string[] = [];

    for (const req of pending) {
      try {
        // 1. Mark request as delivered
        await db.update(messageRequests)
          .set({
            status: 'delivered' as any,
            deliveredToAgentId: agent.id,
            deliveredAt: now,
          })
          .where(eq(messageRequests.id, req.id));

        // 2. Auto-create accepted connection (skip if already exists)
        const existingConn = await db.select({ id: connections.id })
          .from(connections)
          .where(or(
            and(eq(connections.requesterId, req.senderAgentId), eq(connections.targetId, agent.id)),
            and(eq(connections.requesterId, agent.id), eq(connections.targetId, req.senderAgentId)),
          ))
          .limit(1);

        if (existingConn.length === 0) {
          await db.insert(connections).values({
            requesterId: req.senderAgentId,
            targetId: agent.id,
            status: 'accepted',
            respondedAt: now,
          });
        } else {
          // Update existing to accepted if pending
          await db.update(connections)
            .set({ status: 'accepted', respondedAt: now })
            .where(eq(connections.id, existingConn[0].id));
        }

        // 3. Create thread
        const [newThread] = await db.insert(threads).values({
          subject: req.subject || null,
          messageCount: 1,
          updatedAt: now,
        }).returning();

        // 4. Add participants
        await db.insert(threadParticipants).values([
          { threadId: newThread.id, agentId: req.senderAgentId },
          { threadId: newThread.id, agentId: agent.id },
        ]);

        // 5. Create message from the request body
        const body = req.body || '';
        const [newMessage] = await db.insert(messages).values({
          threadId: newThread.id,
          senderId: req.senderAgentId,
          type: 'message',
          parts: [{ kind: 'text', content: body }],
          body: body.substring(0, 5000),
          bodyHtml: body.substring(0, 5000),
        }).returning();

        // 6. Create recipient record
        await db.insert(messageRecipients).values({
          messageId: newMessage.id,
          recipientId: agent.id,
          status: 'sent',
        });

        createdThreads.push(newThread.id);
        console.log(`[MessageRequest] Claimed ${req.id} → thread ${newThread.id}`);
      } catch (err) {
        console.error(`[MessageRequest] Failed to process request ${req.id}:`, err);
      }
    }

    console.log(`[MessageRequest] Claimed ${createdThreads.length}/${pending.length} requests for ${wallet}`);

    return c.json(apiResponse({ claimed: createdThreads.length, threads: createdThreads }));
  } catch (error) {
    console.error('[MessageRequest] Claim error:', error);
    return c.json(apiError('Failed to claim requests', 'SERVER_ERROR'), 500);
  }
});

export default discoverRoute;
