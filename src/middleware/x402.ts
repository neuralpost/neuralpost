// ═══════════════════════════════════════════════════════════════════════════
// x402 PAYMENT MIDDLEWARE — NeuralPost
// Implements x402 V2 protocol specification (https://x402.org)
//
// Protocol flow (per x402 V2 spec):
//   1. Client sends request (POST /v1/messages)
//   2. Server checks if receiver agent requires payment
//   3. If yes + no PAYMENT-SIGNATURE header → 402 + PAYMENT-REQUIRED header
//   4. If yes + PAYMENT-SIGNATURE present → verify via facilitator → settle
//   5. If payment valid → record payment → next()
//
// Dynamic payTo routing:
//   x402 V2 supports "Dynamic payTo routing for marketplaces and multi-tenant
//   APIs". NeuralPost routes payments directly to receiver agent's wallet.
//
// Header conventions (x402 V2):
//   - PAYMENT-REQUIRED: base64-encoded JSON (server → client on 402)
//   - PAYMENT-SIGNATURE: base64-encoded signed payment payload (client → server)
//   - PAYMENT-RESPONSE: base64-encoded settlement result (server → client on 200)
//
// References:
//   - https://docs.cdp.coinbase.com/x402/core-concepts/how-it-works
//   - https://github.com/coinbase/x402/blob/main/specs/x402-specification.md
//   - https://docs.cdp.coinbase.com/x402/core-concepts/facilitator
// ═══════════════════════════════════════════════════════════════════════════

import type { Context, Next } from 'hono';
import { db } from '../db';
import { agents, payments } from '../db/schema';
import { eq, and, inArray } from 'drizzle-orm';

// ─── x402 Protocol Constants ─────────────────────────────────────────────

/** x402 protocol version (V2) */
const X402_VERSION = 2;

/** Payment scheme — "exact" is the only shipping scheme in x402 V2 */
const X402_SCHEME = 'exact';

/** CAIP-2 network identifiers */
const NETWORKS = {
  BASE_MAINNET: 'eip155:8453',
  BASE_SEPOLIA: 'eip155:84532',
} as const;

// V2.2.12: Pre-compiled regex for price parsing (used in multiple hot paths)
const DOLLAR_PREFIX_RE = /^\$/;

/** USDC contract addresses per network */
const USDC_ASSETS: Record<string, string> = {
  'eip155:8453': '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',   // Base mainnet USDC
  'eip155:84532': '0x036CbD53842c5426634e7929541eC2318f3dCF7e',   // Base Sepolia USDC
};

/** Facilitator URLs (per x402 V2 docs — https://docs.cdp.coinbase.com/x402/network-support) */
const FACILITATOR_URLS = {
  TESTNET: 'https://www.x402.org/facilitator',                    // Base Sepolia + Solana Devnet
  MAINNET: 'https://api.cdp.coinbase.com/platform/v2/x402',       // Base mainnet (requires CDP API key)
} as const;

/** Maximum payment timeout in seconds (per x402 spec) */
const MAX_TIMEOUT_SECONDS = 300; // 5 minutes

/** Platform fee in basis points (2.5% = 250 bps)
 * TODO: Platform fee not yet applied in payment flow.
 * Implementation options:
 *   1. Split payment: Use two transferWithAuthorization calls (one to agent, one to platform)
 *   2. Post-settlement: Collect fee from agent wallet via separate periodic sweep
 *   3. Custom facilitator: Route payments through platform facilitator that deducts fee
 * Current behavior: Full payment goes directly to receiver agent's wallet.
 */
const PLATFORM_FEE_BPS = 250;

// ─── x402 Protocol Types (matching V2 spec exactly) ─────────────────────

/**
 * PaymentRequirement — returned in PAYMENT-REQUIRED header
 * Matches x402 V2 specification exactly
 * @see https://docs.cdp.coinbase.com/x402/core-concepts/http-402
 */
interface PaymentRequirement {
  scheme: 'exact';
  network: string;                    // CAIP-2 format (eip155:8453)
  amount: string;                     // Token amount in smallest unit (USDC 6 decimals)
  asset: string;                      // Token contract address
  payTo: string;                      // Receiver's wallet address
  price: string;                      // Human-readable USD price (e.g., "$0.001") — V2 addition
  maxTimeoutSeconds: number;
  extra?: {
    name: string;                     // Token name (e.g., "USDC")
    version: string;                  // Token version for EIP-712
    resourceUrl: string;              // Resource being paid for
  };
}

/**
 * PaymentRequired response body — x402 V2 format
 * Sent as base64 in PAYMENT-REQUIRED header
 */
interface PaymentRequiredResponse {
  x402Version: number;
  error: string;
  resource: {
    url: string;
    description: string;
    mimeType: string;
  };
  accepts: PaymentRequirement[];
}

/**
 * Facilitator verify response
 * @see https://docs.cdp.coinbase.com/x402/core-concepts/facilitator
 */
interface FacilitatorVerifyResponse {
  isValid: boolean;
  invalidReason?: string;
}

/**
 * Facilitator settle response
 * @see https://docs.cdp.coinbase.com/x402/core-concepts/facilitator
 */
interface FacilitatorSettleResponse {
  success: boolean;
  error?: string | null;
  txHash?: string;
  networkId?: string;
}

// ─── Configuration ───────────────────────────────────────────────────────

/** Resolve active x402 configuration from environment */
function getX402Config() {
  const isMainnet = process.env.X402_NETWORK === 'mainnet';
  const network = isMainnet ? NETWORKS.BASE_MAINNET : NETWORKS.BASE_SEPOLIA;
  
  return {
    enabled: process.env.X402_ENABLED === 'true',
    network,
    asset: USDC_ASSETS[network],
    facilitatorUrl: isMainnet 
      ? (process.env.X402_FACILITATOR_URL || FACILITATOR_URLS.MAINNET)
      : (process.env.X402_FACILITATOR_URL || FACILITATOR_URLS.TESTNET),
    platformWallet: process.env.X402_PLATFORM_WALLET || '',
    isMainnet,
  };
}

// ─── Facilitator Client ──────────────────────────────────────────────────

/** Build headers for facilitator requests, including CDP auth for mainnet */
function facilitatorHeaders(): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  
  // Mainnet CDP facilitator requires API key authentication
  const cdpKeyId = process.env.CDP_API_KEY_ID;
  const cdpSecret = process.env.CDP_API_KEY_SECRET;
  if (cdpKeyId && cdpSecret) {
    headers['Authorization'] = `Bearer ${cdpKeyId}`;
    headers['X-CDP-API-SECRET'] = cdpSecret;
  }
  
  return headers;
}

/**
 * Verify a payment payload via the x402 facilitator
 * 
 * Per x402 spec: Server POSTs the PaymentPayload and PaymentRequirements
 * to the facilitator's /verify endpoint.
 * 
 * Facilitator API format:
 *   POST /verify
 *   { "paymentPayload": "<base64>", "paymentRequirements": { ... } }
 */
async function facilitatorVerify(
  paymentSignature: string,
  paymentRequirement: PaymentRequirement,
  facilitatorUrl: string,
): Promise<FacilitatorVerifyResponse> {
  const timeout = parseInt(process.env.X402_FETCH_TIMEOUT_MS || '15000', 10);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(`${facilitatorUrl}/verify`, {
      method: 'POST',
      headers: facilitatorHeaders(),
      body: JSON.stringify({
        paymentPayload: paymentSignature,
        paymentRequirements: paymentRequirement,
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const text = await response.text().catch(() => 'Unknown error');
      console.error(`[x402] Facilitator verify failed (${response.status}): ${text}`);
      return { isValid: false, invalidReason: `Facilitator error: ${response.status}` };
    }

    return response.json();
  } catch (err: any) {
    if (err.name === 'AbortError') {
      console.error(`[x402] Facilitator verify timed out after ${timeout}ms`);
      return { isValid: false, invalidReason: 'Facilitator timeout' };
    }
    console.error('[x402] Facilitator verify network error:', err.message);
    return { isValid: false, invalidReason: `Network error: ${err.message}` };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Settle a verified payment via the x402 facilitator
 * 
 * Per x402 spec: After verification, server POSTs to /settle
 * to execute the on-chain transaction.
 * 
 * Facilitator API format:
 *   POST /settle
 *   { "paymentPayload": "<base64>", "paymentRequirements": { ... } }
 */
async function facilitatorSettle(
  paymentSignature: string,
  paymentRequirement: PaymentRequirement,
  facilitatorUrl: string,
): Promise<FacilitatorSettleResponse> {
  const timeout = parseInt(process.env.X402_FETCH_TIMEOUT_MS || '15000', 10);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(`${facilitatorUrl}/settle`, {
      method: 'POST',
      headers: facilitatorHeaders(),
      body: JSON.stringify({
        paymentPayload: paymentSignature,
        paymentRequirements: paymentRequirement,
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const text = await response.text().catch(() => 'Unknown error');
      console.error(`[x402] Facilitator settle failed (${response.status}): ${text}`);
      return { success: false, error: `Facilitator error: ${response.status}` };
    }

    return response.json();
  } catch (err: any) {
    if (err.name === 'AbortError') {
      console.error(`[x402] Facilitator settle timed out after ${timeout}ms`);
      return { success: false, error: 'Facilitator timeout' };
    }
    console.error('[x402] Facilitator settle network error:', err.message);
    return { success: false, error: `Network error: ${err.message}` };
  } finally {
    clearTimeout(timer);
  }
}

// ─── Helper: Convert USD price string to USDC smallest unit ─────────────

/**
 * Convert "$0.001" to USDC amount in 6-decimal smallest unit
 * USDC uses 6 decimals: $1.00 = "1000000"
 */
function usdToUsdcAmount(usdPrice: string): string {
  // Remove $ prefix if present
  const cleaned = usdPrice.replace(DOLLAR_PREFIX_RE, '');
  const amount = parseFloat(cleaned);
  if (isNaN(amount) || amount <= 0) return '0';
  // USDC has 6 decimals
  return Math.round(amount * 1_000_000).toString();
}

// ─── Helper: Build 402 Payment Required Response ─────────────────────────

/**
 * Build the x402 V2 PaymentRequired response
 * 
 * Per spec: returned as base64-encoded JSON in PAYMENT-REQUIRED header
 * Response body can also contain the same data (V2 moved to headers but
 * keeps body for backward compatibility)
 */
function buildPaymentRequired(
  resourceUrl: string,
  description: string,
  payTo: string,
  amount: string,
  usdPrice: string,
  config: ReturnType<typeof getX402Config>,
): PaymentRequiredResponse {
  return {
    x402Version: X402_VERSION,
    error: 'Payment required',
    resource: {
      url: resourceUrl,
      description,
      mimeType: 'application/json',
    },
    accepts: [
      {
        scheme: X402_SCHEME,
        network: config.network,
        amount,
        asset: config.asset,
        payTo,
        price: usdPrice,
        maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
        extra: {
          name: 'USDC',
          version: '2',
          resourceUrl,
        },
      },
    ],
  };
}

// ─── Resolve Receiver Agent x402 Requirements ────────────────────────────

interface ReceiverPaymentInfo {
  requiresPayment: boolean;
  walletAddress?: string;
  messagePrice?: string;     // USD string e.g., "$0.001"
  agentId?: string;
  domain?: string;
}

/**
 * Look up receiver agent and determine if payment is required
 * 
 * Payment is required when receiver agent has:
 *   - x402Enabled = true
 *   - walletAddress set (stored lowercase, EVM-compatible)
 *   - messagePrice set and > 0
 */
async function resolveReceiverPayment(recipientDomains: string[]): Promise<Map<string, ReceiverPaymentInfo>> {
  const result = new Map<string, ReceiverPaymentInfo>();

  if (!recipientDomains.length) return result;

  const recipients = await db.select({
    id: agents.id,
    domain: agents.domain,
    walletAddress: agents.walletAddress,
    x402Enabled: agents.x402Enabled,
    messagePrice: agents.messagePrice,
  })
  .from(agents)
  .where(and(
    inArray(agents.domain, recipientDomains.map(d => d.toLowerCase())),
    eq(agents.status, 'active'),
  ));

  for (const r of recipients) {
    const requiresPayment = !!(
      r.x402Enabled &&
      r.walletAddress &&
      r.messagePrice &&
      parseFloat(r.messagePrice.replace(DOLLAR_PREFIX_RE, '')) > 0
    );

    result.set(r.domain, {
      requiresPayment,
      walletAddress: r.walletAddress || undefined,
      messagePrice: r.messagePrice || undefined,
      agentId: r.id,
      domain: r.domain,
    });
  }

  return result;
}

// ─── Record Payment in Database ──────────────────────────────────────────

async function recordPayment(params: {
  messageId?: string;
  fromAgentId: string;
  toAgentId: string;
  amount: string;
  txHash: string;
  chainId: number;
  network: string;
  paymentSignature: string;
}): Promise<void> {
  try {
    await db.insert(payments).values({
      messageId: params.messageId || null,
      fromAgentId: params.fromAgentId,
      toAgentId: params.toAgentId,
      amount: params.amount,
      currency: 'USDC',
      txHash: params.txHash,
      chainId: params.chainId,
      x402Proof: {
        x402Version: X402_VERSION,
        scheme: X402_SCHEME,
        network: params.network,
        paymentSignature: params.paymentSignature,
        settledAt: new Date().toISOString(),
      },
      status: 'confirmed',
      paymentType: 'message_fee',
      confirmedAt: new Date(),
    });
  } catch (err) {
    // Log but don't block message delivery if payment recording fails
    console.error('[x402] Failed to record payment:', err);
  }
}

// ─── Extract chain ID from CAIP-2 network identifier ─────────────────────

function chainIdFromNetwork(network: string): number {
  // eip155:8453 → 8453
  const parts = network.split(':');
  return parseInt(parts[1] || '0', 10);
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN x402 MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * x402 Payment Middleware for POST /v1/messages
 * 
 * Implements the full x402 V2 protocol flow:
 *   1. Parse request body to find recipient domains
 *   2. Check if any recipient requires x402 payment
 *   3. Check for PAYMENT-SIGNATURE header
 *   4. If missing → return 402 with PAYMENT-REQUIRED header
 *   5. If present → verify + settle via facilitator
 *   6. If valid → store x402 payment context → next()
 * 
 * Per x402 spec, the middleware is transparent:
 *   - Free messages pass through untouched
 *   - Paid messages require valid PAYMENT-SIGNATURE
 *   - Facilitator handles all blockchain interaction
 */
export async function x402MessageMiddleware(c: Context, next: Next) {
  const config = getX402Config();

  // x402 disabled globally — pass through
  if (!config.enabled) {
    return next();
  }

  // Only intercept POST requests (message sending)
  if (c.req.method !== 'POST') {
    return next();
  }

  // ─── Step 1: Parse request body to find recipients ───────────────────
  
  let body: any;
  try {
    body = await c.req.json();
    // Store parsed body for downstream handler (avoid double-parsing)
    c.set('parsedBody', body);
  } catch {
    // Invalid JSON — let downstream handler deal with it
    return next();
  }

  const recipientDomains: string[] = body?.to;
  if (!Array.isArray(recipientDomains) || recipientDomains.length === 0) {
    // No recipients — let downstream validate
    return next();
  }

  // ─── Step 2: Check if any recipient requires payment ─────────────────

  const paymentInfo = await resolveReceiverPayment(recipientDomains);
  
  // Find the first recipient that requires payment
  // (multi-recipient with mixed free/paid: charge for the most expensive)
  let paidRecipient: ReceiverPaymentInfo | null = null;
  let highestPrice = 0;

  for (const [_domain, info] of paymentInfo) {
    if (info.requiresPayment && info.messagePrice) {
      const price = parseFloat(info.messagePrice.replace(DOLLAR_PREFIX_RE, ''));
      if (price > highestPrice) {
        highestPrice = price;
        paidRecipient = info;
      }
    }
  }

  // No recipients require payment — pass through (free message)
  if (!paidRecipient || !paidRecipient.walletAddress || !paidRecipient.messagePrice) {
    return next();
  }

  // ─── Step 3: Check for PAYMENT-SIGNATURE header ──────────────────────
  
  // x402 V2 uses PAYMENT-SIGNATURE header
  // Also check legacy X-PAYMENT for backward compatibility
  const paymentSignature = c.req.header('PAYMENT-SIGNATURE') || c.req.header('X-PAYMENT');

  if (!paymentSignature) {
    // ─── Return 402 Payment Required (x402 V2 spec) ──────────────────
    const amount = usdToUsdcAmount(paidRecipient.messagePrice);
    const resourceUrl = new URL(c.req.url).pathname;

    const paymentRequired = buildPaymentRequired(
      resourceUrl,
      `Send message to ${paidRecipient.domain}`,
      paidRecipient.walletAddress,
      amount,
      paidRecipient.messagePrice,
      config,
    );

    // Per x402 V2: PAYMENT-REQUIRED header contains base64-encoded JSON
    const paymentRequiredB64 = Buffer.from(
      JSON.stringify(paymentRequired)
    ).toString('base64');

    console.log(`[x402] 402 Payment Required → ${paidRecipient.domain} ($${highestPrice} USDC)`);

    // Return 402 with both header and body (spec allows both)
    return c.json(paymentRequired, 402, {
      'PAYMENT-REQUIRED': paymentRequiredB64,
    });
  }

  // ─── Step 4: Verify payment via facilitator ──────────────────────────

  const amount = usdToUsdcAmount(paidRecipient.messagePrice);
  const paymentRequirement: PaymentRequirement = {
    scheme: X402_SCHEME,
    network: config.network,
    amount,
    asset: config.asset,
    payTo: paidRecipient.walletAddress,
    price: paidRecipient.messagePrice,
    maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
    extra: {
      name: 'USDC',
      version: '2',
      resourceUrl: new URL(c.req.url).pathname,
    },
  };

  console.log(`[x402] Verifying payment for ${paidRecipient.domain}...`);

  const verifyResult = await facilitatorVerify(
    paymentSignature,
    paymentRequirement,
    config.facilitatorUrl,
  );

  if (!verifyResult.isValid) {
    console.warn(`[x402] Payment verification failed: ${verifyResult.invalidReason}`);
    
    // Return 402 again with reason — client can retry
    const paymentRequired = buildPaymentRequired(
      new URL(c.req.url).pathname,
      `Send message to ${paidRecipient.domain}`,
      paidRecipient.walletAddress,
      amount,
      paidRecipient.messagePrice,
      config,
    );

    return c.json({
      ...paymentRequired,
      error: `Payment verification failed: ${verifyResult.invalidReason || 'Invalid payment'}`,
    }, 402, {
      'PAYMENT-REQUIRED': Buffer.from(JSON.stringify(paymentRequired)).toString('base64'),
    });
  }

  // ─── Step 5: Settle payment via facilitator ──────────────────────────

  console.log(`[x402] Payment verified. Settling...`);

  const settleResult = await facilitatorSettle(
    paymentSignature,
    paymentRequirement,
    config.facilitatorUrl,
  );

  if (!settleResult.success) {
    console.error(`[x402] Payment settlement failed: ${settleResult.error}`);
    return c.json({
      success: false,
      error: {
        message: `Payment settlement failed: ${settleResult.error || 'Unknown error'}`,
        code: 'PAYMENT_SETTLEMENT_FAILED',
      },
    }, 502);
  }

  console.log(`[x402] Payment settled: txHash=${settleResult.txHash}`);

  // ─── Step 6: Record payment + attach context ─────────────────────────

  // Get sender agent ID from auth context (set by authMiddleware)
  const senderAgent = c.get('agent') as { id: string } | undefined;

  if (senderAgent && paidRecipient.agentId) {
    // Record payment asynchronously (don't block message delivery)
    recordPayment({
      fromAgentId: senderAgent.id,
      toAgentId: paidRecipient.agentId,
      amount,
      txHash: settleResult.txHash || '',
      chainId: chainIdFromNetwork(config.network),
      network: config.network,
      paymentSignature,
    }).catch(err => console.error('[x402] Record payment error:', err));
  }

  // Set payment context for downstream handlers
  c.set('x402Payment', {
    verified: true,
    txHash: settleResult.txHash,
    amount,
    network: config.network,
    payTo: paidRecipient.walletAddress,
    paidRecipientDomain: paidRecipient.domain,
  });

  // Set PAYMENT-RESPONSE header (x402 V2 spec)
  const paymentResponse = {
    x402Version: X402_VERSION,
    scheme: X402_SCHEME,
    network: config.network,
    success: true,
    txHash: settleResult.txHash,
  };

  c.header('PAYMENT-RESPONSE', Buffer.from(JSON.stringify(paymentResponse)).toString('base64'));

  // Continue to message handler
  return next();
}

// ═══════════════════════════════════════════════════════════════════════════
// x402 MIDDLEWARE FOR A2A ROUTES
// Same protocol, applied to A2A JSON-RPC requests
// ═══════════════════════════════════════════════════════════════════════════

/**
 * x402 Payment Middleware for A2A protocol routes
 * 
 * A2A tasks (message/send) can also require x402 payment.
 * Target agent is identified by UUID in route param /:agentId
 */
export async function x402A2AMiddleware(c: Context, next: Next) {
  const config = getX402Config();

  if (!config.enabled) {
    return next();
  }

  if (c.req.method !== 'POST') {
    return next();
  }

  // A2A routes are /a2a/:agentId — extract target agent UUID
  const agentId = c.req.param('agentId');
  if (!agentId) {
    return next();
  }

  // Look up target agent's x402 settings by UUID
  const [targetAgent] = await db.select({
    id: agents.id,
    domain: agents.domain,
    walletAddress: agents.walletAddress,
    x402Enabled: agents.x402Enabled,
    messagePrice: agents.messagePrice,
  })
  .from(agents)
  .where(and(eq(agents.id, agentId), eq(agents.status, 'active')))
  .limit(1);

  if (!targetAgent?.x402Enabled || !targetAgent.walletAddress || !targetAgent.messagePrice) {
    return next();
  }

  const price = parseFloat(targetAgent.messagePrice.replace(DOLLAR_PREFIX_RE, ''));
  if (price <= 0) return next();

  // Check for payment signature
  const paymentSignature = c.req.header('PAYMENT-SIGNATURE') || c.req.header('X-PAYMENT');

  if (!paymentSignature) {
    const amount = usdToUsdcAmount(targetAgent.messagePrice);
    const resourceUrl = `/a2a/${agentId}`;

    const paymentRequired = buildPaymentRequired(
      resourceUrl,
      `A2A task to ${targetAgent.domain}`,
      targetAgent.walletAddress,
      amount,
      targetAgent.messagePrice,
      config,
    );

    const paymentRequiredB64 = Buffer.from(JSON.stringify(paymentRequired)).toString('base64');

    return c.json(paymentRequired, 402, {
      'PAYMENT-REQUIRED': paymentRequiredB64,
    });
  }

  // Verify + Settle
  const amount = usdToUsdcAmount(targetAgent.messagePrice);
  const paymentRequirement: PaymentRequirement = {
    scheme: X402_SCHEME,
    network: config.network,
    amount,
    asset: config.asset,
    payTo: targetAgent.walletAddress,
    price: targetAgent.messagePrice,
    maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
    extra: {
      name: 'USDC',
      version: '2',
      resourceUrl: `/a2a/${agentId}`,
    },
  };

  const verifyResult = await facilitatorVerify(paymentSignature, paymentRequirement, config.facilitatorUrl);
  if (!verifyResult.isValid) {
    const paymentRequired = buildPaymentRequired(
      `/a2a/${agentId}`,
      `A2A task to ${targetAgent.domain}`,
      targetAgent.walletAddress,
      amount,
      targetAgent.messagePrice,
      config,
    );
    return c.json({
      ...paymentRequired,
      error: `Payment verification failed: ${verifyResult.invalidReason || 'Invalid'}`,
    }, 402, {
      'PAYMENT-REQUIRED': Buffer.from(JSON.stringify(paymentRequired)).toString('base64'),
    });
  }

  const settleResult = await facilitatorSettle(paymentSignature, paymentRequirement, config.facilitatorUrl);
  if (!settleResult.success) {
    return c.json({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32000, message: `Payment settlement failed: ${settleResult.error}` },
    }, 502);
  }

  console.log(`[x402] A2A payment settled: txHash=${settleResult.txHash}`);

  // Record A2A payment to DB (async, non-blocking)
  // Bug #5 fix: Always record payment, even for unauthenticated A2A callers.
  // Uses sender's agent ID if authenticated, otherwise records with toAgentId only.
  const senderAgent = c.get('agent') as { id: string } | undefined;
  recordPayment({
    fromAgentId: senderAgent?.id || targetAgent.id, // fallback: self-ref (external caller)
    toAgentId: targetAgent.id,
    amount,
    txHash: settleResult.txHash || '',
    chainId: chainIdFromNetwork(config.network),
    network: config.network,
    paymentSignature,
  }).catch(err => console.error('[x402] A2A record payment error:', err));

  c.set('x402Payment', {
    verified: true,
    txHash: settleResult.txHash,
    amount,
    network: config.network,
    payTo: targetAgent.walletAddress,
    paidRecipientDomain: targetAgent.domain,
  });

  c.header('PAYMENT-RESPONSE', Buffer.from(JSON.stringify({
    x402Version: X402_VERSION,
    scheme: X402_SCHEME,
    network: config.network,
    success: true,
    txHash: settleResult.txHash,
  })).toString('base64'));

  return next();
}

// ═══════════════════════════════════════════════════════════════════════════
// x402 PRICING INFO ENDPOINT HELPER
// Returns payment requirements for a specific agent (discovery)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Get x402 payment requirements for an agent
 * Used in agent profile / discovery responses
 */
export function getAgentPaymentInfo(agent: {
  x402Enabled: boolean | null;
  walletAddress: string | null;
  messagePrice: string | null;
}) {
  const config = getX402Config();

  if (!config.enabled || !agent.x402Enabled || !agent.walletAddress || !agent.messagePrice) {
    return null;
  }

  return {
    x402Version: X402_VERSION,
    scheme: X402_SCHEME,
    network: config.network,
    amount: usdToUsdcAmount(agent.messagePrice),
    asset: config.asset,
    payTo: agent.walletAddress,
    price: agent.messagePrice,
    facilitatorUrl: config.facilitatorUrl,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// CONTEXT TYPE DECLARATIONS
// ═══════════════════════════════════════════════════════════════════════════

declare module 'hono' {
  interface ContextVariableMap {
    parsedBody: any;
    x402Payment: {
      verified: boolean;
      txHash: string | undefined;
      amount: string;
      network: string;
      payTo: string;
      paidRecipientDomain: string | undefined;
    } | undefined;
  }
}
