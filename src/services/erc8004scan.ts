// ═══════════════════════════════════════════════════════════════════════════
// ERC-8004 SCAN API CLIENT
// Primary data source for on-chain agent discovery
// API: https://www.8004scan.io/api/v1
// Rate limits: 5,000/day, 60/min (free tier)
// ═══════════════════════════════════════════════════════════════════════════

// ─── Types ───────────────────────────────────────────────────────────────

/** Raw agent from 8004scan API */
export interface ScanAgent {
  id: string;                          // UUID internal to 8004scan
  agent_id: string;                    // "chainId:contract:tokenId"
  token_id: string;
  chain_id: number;
  is_testnet: boolean;
  contract_address: string;

  // Identity
  name: string;
  description: string;
  image_url: string | null;
  agent_type: string | null;
  tags: string[];
  categories: string[];

  // On-chain ownership
  owner_address: string;
  owner_ens: string | null;
  creator_address: string;
  agent_wallet: string;

  // Verification & health
  is_verified: boolean;
  is_endpoint_verified: boolean;
  endpoint_verified_domain: string | null;
  is_active: boolean;
  health_status: string | null;
  health_score: number | null;

  // Scores (0.0 - 1.0)
  total_score: number;
  quality_score: number;
  popularity_score: number;
  activity_score: number;
  wallet_score: number;
  freshness_score: number;
  metadata_completeness_score: number;

  // Reputation
  total_feedbacks: number;
  total_validations: number;
  successful_validations: number;
  average_score: number;
  rank: number | null;

  // Social
  star_count: number;
  watch_count: number;

  // Protocol support
  x402_supported: boolean;
  supported_protocols: string[];
  supported_trust_models: string[];
  cross_chain_links: CrossChainLink[];

  // Endpoints
  services: ServiceEndpoint[] | null;
  endpoints: LegacyEndpoint[] | null;
  mcp_server: string | null;
  mcp_version: string | null;
  a2a_endpoint: string | null;
  a2a_version: string | null;
  agent_url: string | null;

  // Identity systems
  ens: string | null;
  did: string | null;

  // Metadata parse status
  parse_status: ParseStatus | null;

  // Raw on-chain + off-chain metadata
  raw_metadata: {
    onchain: Array<{ key: string; value: string; decoded: unknown }>;
    offchain_uri: string;
    offchain_content: Record<string, unknown>;
  } | null;

  // Timestamps
  created_at: string;
  updated_at: string;
  created_block_number: number;
  created_tx_hash: string;
}

export interface CrossChainLink {
  chain_id: number;
  token_id: string;
  contract_address: string;
}

export interface ServiceEndpoint {
  name: string;
  endpoint: string;
  version?: string;
  skills?: string[];
}

export interface LegacyEndpoint {
  url: string;
  protocol: string;
}

export interface ParseStatus {
  status: 'ok' | 'warning' | 'error';
  errors: ParseIssue[];
  warnings: ParseIssue[];
  info: ParseIssue[];
  llm_attempted: boolean;
  last_parsed_at: string;
}

export interface ParseIssue {
  code: string;
  field: string;
  message: string;
  source?: string;
  uri_type?: string;
}

export interface ScanFeedback {
  id: string;
  agent_id: string;
  from_agent_id: string;
  score: number;
  comment: string;
  tx_hash: string;
  created_at: string;
}

/** Paginated response from 8004scan */
export interface ScanPaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

/** Search/filter parameters */
export interface ScanSearchParams {
  search?: string;           // Text search (name, description)
  categories?: string[];     // Filter by categories
  chain_id?: number;         // Filter by chain
  is_verified?: boolean;     // Only verified agents
  is_testnet?: boolean;      // Testnet or mainnet
  has_a2a?: boolean;         // Has A2A endpoint
  has_mcp?: boolean;         // Has MCP server
  x402?: boolean;            // Supports x402 payments
  min_score?: number;        // Minimum total_score
  trust_model?: string;      // Trust model filter
  tags?: string;             // Comma-separated tags
  owner_address?: string;    // Owner wallet address
  sort_by?: 'total_score' | 'created_at' | 'total_feedbacks';
  sort_order?: 'asc' | 'desc';
  limit?: number;            // 1-100, default 20
  offset?: number;
}

// ─── Normalized type for NeuralPost consumption ──────────────────────────

/** Unified agent profile combining 8004scan data into NeuralPost-friendly format */
export interface DiscoveredAgent {
  // Source identification
  source: 'erc8004' | 'local' | 'both';
  scanId: string;                      // 8004scan UUID
  agentId: string;                     // "chainId:contract:tokenId"
  tokenId: number;
  chainId: number;
  isTestnet: boolean;
  contractAddress: string;

  // Identity
  name: string;
  description: string;
  imageUrl: string | null;
  categories: string[];
  tags: string[];

  // On-chain ownership
  ownerAddress: string;
  ownerEns: string | null;
  agentWallet: string;

  // Trust & reputation
  isVerified: boolean;
  isEndpointVerified: boolean;
  verifiedDomain: string | null;
  isActive: boolean;
  healthStatus: string | null;
  healthScore: number | null;
  scores: {
    total: number;
    quality: number;
    popularity: number;
    activity: number;
    wallet: number;
    freshness: number;
    completeness: number;
  };
  reputation: {
    feedbacks: number;
    validations: number;
    successfulValidations: number;
    averageScore: number;
    rank: number | null;
  };
  stars: number;

  // Protocol support
  x402Supported: boolean;
  protocols: string[];
  a2aEndpoint: string | null;
  a2aVersion: string | null;
  mcpServer: string | null;
  mcpVersion: string | null;
  services: ServiceEndpoint[];

  // Cross-chain presence
  crossChainLinks: CrossChainLink[];

  // Identity systems
  ens: string | null;
  did: string | null;

  // Metadata quality
  parseStatus: 'ok' | 'warning' | 'error' | null;
  parseWarnings: number;

  // Links
  scanUrl: string;
  explorerUrl: string;
  txHash: string;

  // Timestamps
  createdAt: string;
  updatedAt: string;
}

// ─── Rate Limit Tracker ──────────────────────────────────────────────────

interface RateLimitState {
  dayLimit: number;
  dayRemaining: number;
  minuteLimit: number;
  minuteRemaining: number;
  lastUpdated: number;
}

// ─── Client ──────────────────────────────────────────────────────────────

const API_BASE = 'https://www.8004scan.io/api/v1';
const SCAN_URL_BASE = 'https://www.8004scan.io/agents';

// Block explorer mapping for known chains
const EXPLORER_MAP: Record<number, string> = {
  1: 'https://etherscan.io',
  10: 'https://optimistic.etherscan.io',
  137: 'https://polygonscan.com',
  8453: 'https://basescan.org',
  42161: 'https://arbiscan.io',
  84532: 'https://sepolia.basescan.org',
  324705682: 'https://base-sepolia-testnet-explorer.skalenodes.com',
  1187947933: 'https://base-mainnet-explorer.skalenodes.com',
  10143: 'https://testnet.explorer.calypso.network', // SKALE testnet
  421614: 'https://sepolia.arbiscan.io',
  11155111: 'https://sepolia.etherscan.io',
};

class ERC8004ScanClient {
  private apiKey: string;
  private rateLimit: RateLimitState;
  private cache: Map<string, { data: unknown; expiresAt: number }>;
  private readonly cacheTTL: number; // ms

  constructor() {
    this.apiKey = process.env.ERC8004SCAN_API_KEY || '';
    this.rateLimit = {
      dayLimit: 5000,
      dayRemaining: 5000,
      minuteLimit: 60,
      minuteRemaining: 60,
      lastUpdated: 0,
    };
    this.cache = new Map();
    this.cacheTTL = parseInt(process.env.ERC8004SCAN_CACHE_TTL || '300000', 10); // 5min default
  }

  // ─── Configuration ───────────────────────────────────────────────────

  isConfigured(): boolean {
    return this.apiKey.length > 0;
  }

  getRateLimitStatus(): RateLimitState {
    return { ...this.rateLimit };
  }

  // ─── Core HTTP ───────────────────────────────────────────────────────

  private async fetch<T>(path: string, params?: Record<string, string>): Promise<T> {
    // Pre-flight rate limit check
    if (this.rateLimit.minuteRemaining <= 2) {
      throw new ERC8004ScanError('Rate limit approaching (minute)', 'RATE_LIMITED');
    }
    if (this.rateLimit.dayRemaining <= 50) {
      throw new ERC8004ScanError('Rate limit approaching (daily)', 'RATE_LIMITED');
    }

    // Build URL
    const url = new URL(`${API_BASE}${path}`);
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== '') url.searchParams.set(k, v);
      });
    }

    // Check cache
    const cacheKey = url.toString();
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.data as T;
    }

    // Make request
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000); // 10s timeout

    try {
      const res = await globalThis.fetch(url.toString(), {
        headers: {
          'X-API-Key': this.apiKey,
          'Accept': 'application/json',
          'User-Agent': 'NeuralPost/2.2.12',
        },
        signal: controller.signal,
      });

      // Update rate limit from headers
      this.updateRateLimit(res.headers);

      if (!res.ok) {
        if (res.status === 429) {
          throw new ERC8004ScanError('Rate limited by 8004scan', 'RATE_LIMITED');
        }
        if (res.status === 401 || res.status === 403) {
          throw new ERC8004ScanError('Invalid API key', 'AUTH_ERROR');
        }
        throw new ERC8004ScanError(`8004scan API error: ${res.status}`, 'API_ERROR');
      }

      const data = await res.json() as T;

      // Cache response
      this.cache.set(cacheKey, { data, expiresAt: Date.now() + this.cacheTTL });

      return data;
    } catch (err) {
      if (err instanceof ERC8004ScanError) throw err;
      if ((err as Error).name === 'AbortError') {
        throw new ERC8004ScanError('8004scan request timed out', 'TIMEOUT');
      }
      throw new ERC8004ScanError(`8004scan fetch failed: ${(err as Error).message}`, 'NETWORK_ERROR');
    } finally {
      clearTimeout(timeout);
    }
  }

  private updateRateLimit(headers: Headers) {
    const dayLimit = headers.get('x-ratelimit-limit-day');
    const dayRemaining = headers.get('x-ratelimit-remaining-day');
    const minuteLimit = headers.get('x-ratelimit-limit-minute');
    const minuteRemaining = headers.get('x-ratelimit-remaining-minute');

    if (dayLimit) this.rateLimit.dayLimit = parseInt(dayLimit, 10);
    if (dayRemaining) this.rateLimit.dayRemaining = parseInt(dayRemaining, 10);
    if (minuteLimit) this.rateLimit.minuteLimit = parseInt(minuteLimit, 10);
    if (minuteRemaining) this.rateLimit.minuteRemaining = parseInt(minuteRemaining, 10);
    this.rateLimit.lastUpdated = Date.now();
  }

  // ─── Cache Management ────────────────────────────────────────────────

  clearCache() {
    this.cache.clear();
  }

  /** Evict expired entries (call periodically) */
  pruneCache() {
    const now = Date.now();
    for (const [key, entry] of this.cache) {
      if (entry.expiresAt <= now) this.cache.delete(key);
    }
  }

  getCacheStats() {
    return {
      entries: this.cache.size,
      ttlMs: this.cacheTTL,
    };
  }

  // ─── API Methods ─────────────────────────────────────────────────────

  /** List/search agents with filters */
  async searchAgents(params: ScanSearchParams = {}): Promise<ScanPaginatedResponse<ScanAgent>> {
    const queryParams: Record<string, string> = {};

    if (params.search) queryParams.search = params.search;
    if (params.limit) queryParams.limit = String(Math.min(params.limit, 100));
    if (params.offset) queryParams.offset = String(params.offset);
    if (params.chain_id) queryParams.chain_id = String(params.chain_id);
    if (params.sort_by) queryParams.sort_by = params.sort_by;
    if (params.sort_order) queryParams.sort_order = params.sort_order;

    // Boolean filters — only send if explicitly set
    if (params.is_verified !== undefined) queryParams.is_verified = String(params.is_verified);
    if (params.is_testnet !== undefined) queryParams.is_testnet = String(params.is_testnet);
    if (params.has_a2a !== undefined) queryParams.has_a2a = String(params.has_a2a);
    if (params.has_mcp !== undefined) queryParams.has_mcp = String(params.has_mcp);
    if (params.x402 !== undefined) queryParams.x402 = String(params.x402);

    // Category filter as comma-separated
    if (params.categories?.length) queryParams.categories = params.categories.join(',');

    // Extended filters
    if (params.trust_model) queryParams.trust_model = params.trust_model;
    if (params.tags) queryParams.tags = params.tags;
    if (params.owner_address) queryParams.owner_address = params.owner_address;

    return this.fetch<ScanPaginatedResponse<ScanAgent>>('/agents', queryParams);
  }

  /** Get single agent by chain + tokenId */
  async getAgent(chain: string, tokenId: string | number): Promise<ScanAgent> {
    return this.fetch<ScanAgent>(`/agents/${chain}/${tokenId}`);
  }

  /** Get agent feedbacks */
  async getAgentFeedbacks(chain: string, tokenId: string | number): Promise<ScanFeedback[]> {
    return this.fetch<ScanFeedback[]>(`/agents/${chain}/${tokenId}/feedbacks`);
  }

  // ─── Normalization ───────────────────────────────────────────────────

  /** Convert raw ScanAgent → NeuralPost DiscoveredAgent */
  normalize(agent: ScanAgent): DiscoveredAgent {
    const explorer = EXPLORER_MAP[agent.chain_id] || '';
    const chainSlug = agent.is_testnet
      ? `${agent.chain_id}`
      : this.chainSlug(agent.chain_id);

    return {
      source: 'erc8004',
      scanId: agent.id,
      agentId: agent.agent_id,
      tokenId: parseInt(agent.token_id, 10),
      chainId: agent.chain_id,
      isTestnet: agent.is_testnet,
      contractAddress: agent.contract_address,

      name: agent.name || 'Unnamed Agent',
      description: agent.description || '',
      imageUrl: agent.image_url,
      categories: Array.isArray(agent.categories) ? agent.categories : [],
      tags: Array.isArray(agent.tags) ? agent.tags : [],

      ownerAddress: agent.owner_address,
      ownerEns: agent.owner_ens,
      agentWallet: agent.agent_wallet,

      isVerified: agent.is_verified,
      isEndpointVerified: agent.is_endpoint_verified,
      verifiedDomain: agent.endpoint_verified_domain,
      isActive: agent.is_active,
      healthStatus: agent.health_status,
      healthScore: agent.health_score,
      scores: {
        total: agent.total_score,
        quality: agent.quality_score,
        popularity: agent.popularity_score,
        activity: agent.activity_score,
        wallet: agent.wallet_score,
        freshness: agent.freshness_score,
        completeness: agent.metadata_completeness_score,
      },
      reputation: {
        feedbacks: agent.total_feedbacks,
        validations: agent.total_validations,
        successfulValidations: agent.successful_validations,
        averageScore: agent.average_score,
        rank: agent.rank,
      },
      stars: agent.star_count,

      x402Supported: agent.x402_supported,
      protocols: Array.isArray(agent.supported_protocols) ? agent.supported_protocols : [],
      a2aEndpoint: agent.a2a_endpoint,
      a2aVersion: agent.a2a_version,
      mcpServer: agent.mcp_server,
      mcpVersion: agent.mcp_version,
      services: Array.isArray(agent.services) ? agent.services : [],

      crossChainLinks: Array.isArray(agent.cross_chain_links) ? agent.cross_chain_links : [],

      ens: agent.ens,
      did: agent.did,

      parseStatus: agent.parse_status?.status || null,
      parseWarnings: (agent.parse_status?.warnings?.length || 0),

      scanUrl: `${SCAN_URL_BASE}/${chainSlug}/${agent.token_id}`,
      explorerUrl: explorer
        ? `${explorer}/tx/${agent.created_tx_hash}`
        : '',
      txHash: agent.created_tx_hash,

      createdAt: agent.created_at,
      updatedAt: agent.updated_at,
    };
  }

  /** Batch normalize */
  normalizeMany(agents: ScanAgent[]): DiscoveredAgent[] {
    return agents.map(a => this.normalize(a));
  }

  private chainSlug(chainId: number): string {
    const slugs: Record<number, string> = {
      1: 'ethereum',
      10: 'optimism',
      137: 'polygon',
      8453: 'base',
      42161: 'arbitrum',
      84532: 'base-sepolia',
      10143: 'skale-testnet',
    };
    return slugs[chainId] || String(chainId);
  }
}

// ─── Error class ─────────────────────────────────────────────────────────

export class ERC8004ScanError extends Error {
  constructor(
    message: string,
    public readonly code: 'RATE_LIMITED' | 'AUTH_ERROR' | 'API_ERROR' | 'TIMEOUT' | 'NETWORK_ERROR' | 'NOT_CONFIGURED',
  ) {
    super(message);
    this.name = 'ERC8004ScanError';
  }
}

// ─── Singleton ───────────────────────────────────────────────────────────

export const scanClient = new ERC8004ScanClient();

// Prune cache every 5 minutes
const _pruneInterval = setInterval(() => scanClient.pruneCache(), 300_000);

// Allow clean shutdown
export function stopScanCachePrune() {
  clearInterval(_pruneInterval);
}
