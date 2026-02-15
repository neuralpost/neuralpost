// ═══════════════════════════════════════════════════════════════════════════
// NeuralPost x402 Payment Integration — Official @x402/hono SDK
//
// Uses Coinbase's official x402 SDK (@x402/hono, @x402/evm, @x402/core)
// for standard payment flow on protected endpoints.
//
// Two integration modes:
//   1. Static paywall  — paymentMiddleware() for fixed routes (demo, premium API)
//   2. Dynamic paywall — x402ResourceServer for per-agent pricing (messaging)
//
// Settlement pattern (per official SDK):
//   verify → execute handler → settle (deferred settlement)
//   If handler fails, payment is NOT settled (protects buyer)
//
// Network: Base Sepolia (testnet) → Base mainnet (production)
// Facilitator: x402.org/facilitator (testnet) → CDP (mainnet)
// ═══════════════════════════════════════════════════════════════════════════

import type { Context, Next } from 'hono';
import { paymentMiddleware, x402ResourceServer } from '@x402/hono';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { HTTPFacilitatorClient } from '@x402/core/server';
import { db } from '../db';
import { agents, payments } from '../db/schema';
import { eq, and, inArray } from 'drizzle-orm';

// ─── Configuration ───────────────────────────────────────────────────────

const DOLLAR_PREFIX_RE = /^\$/;

export function getX402SDKConfig() {
  const isMainnet = process.env.X402_NETWORK === 'mainnet';

  return {
    enabled: process.env.X402_ENABLED === 'true',
    isMainnet,
    // CAIP-2 network identifier
    network: isMainnet ? 'eip155:8453' : 'eip155:84532',
    // USDC contract address
    asset: isMainnet
      ? '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'   // Base mainnet USDC
      : '0x036CbD53842c5426634e7929541eC2318f3dCF7e',   // Base Sepolia USDC
    // Facilitator URL
    facilitatorUrl: process.env.X402_FACILITATOR_URL
      || (isMainnet
        ? 'https://api.cdp.coinbase.com/platform/v2/x402'
        : 'https://x402.org/facilitator'),
    // Platform wallet (receives payments on static endpoints)
    platformWallet: process.env.X402_PLATFORM_WALLET || '',
  };
}

// ─── Resource Server (shared singleton) ──────────────────────────────────

let _resourceServer: InstanceType<typeof x402ResourceServer> | null = null;
let _initPromise: Promise<void> | null = null;

export function getResourceServer() {
  if (_resourceServer) return _resourceServer;

  const config = getX402SDKConfig();
  const facilitatorClient = new HTTPFacilitatorClient({
    url: config.facilitatorUrl,
  });

  _resourceServer = new x402ResourceServer(facilitatorClient)
    .register(config.network, new ExactEvmScheme());

  // Initialize once — fetches supported kinds from facilitator
  // Required before verifyPayment/settlePayment can resolve facilitator clients
  _initPromise = _resourceServer.initialize().catch(err => {
    console.warn('[x402] Facilitator initialization warning:', err.message);
  });

  return _resourceServer;
}

/** Ensure resource server is initialized before verify/settle */
async function ensureInitialized() {
  if (_initPromise) {
    await _initPromise;
    _initPromise = null;
  }
}

// ─── Base64 Helpers ──────────────────────────────────────────────────────
// Matches @x402/core internal decodePaymentSignatureHeader (not exported)

function decodePaymentSignature(header: string): any {
  try {
    const json = Buffer.from(header, 'base64').toString('utf-8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function encodeBase64(obj: any): string {
  return Buffer.from(JSON.stringify(obj)).toString('base64');
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. STATIC PAYWALL — Official @x402/hono paymentMiddleware
//    For fixed-price endpoints (demo, premium API, etc.)
//
//    The SDK handles the full flow internally:
//      402 response → verify → execute handler → settle (deferred)
// ═══════════════════════════════════════════════════════════════════════════

export function createStaticPaywall() {
  const config = getX402SDKConfig();

  if (!config.enabled || !config.platformWallet) {
    return async (_c: Context, next: Next) => next();
  }

  return paymentMiddleware(
    {
      'GET /v1/x402/weather': {
        accepts: {
          scheme: 'exact',
          price: '$0.001',
          network: config.network,
          payTo: config.platformWallet,
        },
        description: 'NeuralPost weather demo — x402 protected endpoint',
        mimeType: 'application/json',
      },
      'GET /v1/x402/agent-search': {
        accepts: {
          scheme: 'exact',
          price: '$0.01',
          network: config.network,
          payTo: config.platformWallet,
        },
        description: 'Premium agent search with detailed profiles',
        mimeType: 'application/json',
      },
    },
    getResourceServer(),
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. DYNAMIC PAYWALL — Per-agent pricing for messaging
//    Payments route directly to receiver agent's wallet (dynamic payTo)
//
//    Uses x402ResourceServer.verifyPayment() + settlePayment() directly
//    (cannot use paymentMiddleware because payTo is dynamic per-recipient)
//
//    Settlement pattern (matching official SDK Hono middleware):
//      1. verify payment
//      2. await next() — execute message handler
//      3. settle ONLY if handler status < 400 (deferred settlement)
//      This protects buyers: if handler fails, payment is NOT settled.
// ═══════════════════════════════════════════════════════════════════════════

export async function x402DynamicMiddleware(c: Context, next: Next) {
  const config = getX402SDKConfig();

  if (!config.enabled) return next();
  if (c.req.method !== 'POST') return next();

  // ─── Parse request body ──────────────────────────────────────────────
  let body: any;
  try {
    body = await c.req.json();
    c.set('parsedBody', body);
  } catch {
    return next();
  }

  const recipientDomains: string[] = body?.to;
  if (!Array.isArray(recipientDomains) || recipientDomains.length === 0) {
    return next();
  }

  // ─── Find recipient that requires payment ────────────────────────────
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

  let paidRecipient: typeof recipients[0] | null = null;
  let highestPrice = 0;

  for (const r of recipients) {
    if (r.x402Enabled && r.walletAddress && r.messagePrice) {
      const price = parseFloat(r.messagePrice.replace(DOLLAR_PREFIX_RE, ''));
      if (price > highestPrice) {
        highestPrice = price;
        paidRecipient = r;
      }
    }
  }

  if (!paidRecipient || !paidRecipient.walletAddress || !paidRecipient.messagePrice) {
    return next(); // Free message
  }

  // ─── Build payment requirement (x402 v2) ─────────────────────────────
  const amount = usdToUsdcAmount(paidRecipient.messagePrice);
  const resourceUrl = new URL(c.req.url).pathname;

  const paymentRequirement = {
    scheme: 'exact' as const,
    network: config.network,
    amount,
    asset: config.asset,
    payTo: paidRecipient.walletAddress,
    maxTimeoutSeconds: 300,
    extra: {
      name: 'USDC',
      version: '2',
      resourceUrl,
    },
  };

  // ─── Check for PAYMENT-SIGNATURE header ──────────────────────────────
  const paymentHeader = c.req.header('PAYMENT-SIGNATURE')
    || c.req.header('payment-signature')
    || c.req.header('X-PAYMENT');

  if (!paymentHeader) {
    const paymentRequired = {
      x402Version: 2,
      error: 'Payment required',
      resource: {
        url: resourceUrl,
        description: `Send message to ${paidRecipient.domain}`,
        mimeType: 'application/json',
      },
      accepts: [paymentRequirement],
    };

    console.log(`[x402] 402 → ${paidRecipient.domain} ($${highestPrice} USDC)`);

    return c.json(paymentRequired, 402, {
      'PAYMENT-REQUIRED': encodeBase64(paymentRequired),
    });
  }

  // ─── Decode base64 → PaymentPayload object ───────────────────────────
  // Per x402 v2: PAYMENT-SIGNATURE header is base64-encoded JSON
  const paymentPayload = decodePaymentSignature(paymentHeader);
  if (!paymentPayload) {
    return c.json({
      x402Version: 2,
      error: 'Invalid PAYMENT-SIGNATURE header (base64 decode failed)',
      accepts: [paymentRequirement],
    }, 402, {
      'PAYMENT-REQUIRED': encodeBase64({
        x402Version: 2,
        error: 'Invalid payment signature',
        accepts: [paymentRequirement],
      }),
    });
  }

  // ─── Verify + Settle via official SDK ────────────────────────────────
  try {
    await ensureInitialized();
    const server = getResourceServer();

    // Step 1: Verify payment — server.verifyPayment(decodedPayload, requirement)
    const verifyResult = await server.verifyPayment(paymentPayload, paymentRequirement);

    if (!verifyResult.isValid) {
      console.warn(`[x402] Verify failed: ${verifyResult.invalidReason}`);
      return c.json({
        x402Version: 2,
        error: `Payment verification failed: ${verifyResult.invalidReason}`,
        resource: { url: resourceUrl, description: `Send message to ${paidRecipient.domain}` },
        accepts: [paymentRequirement],
      }, 402, {
        'PAYMENT-REQUIRED': encodeBase64({
          x402Version: 2,
          error: verifyResult.invalidReason,
          accepts: [paymentRequirement],
        }),
      });
    }

    console.log(`[x402] Payment verified for ${paidRecipient.domain}`);

    // Step 2: Set context → execute handler
    c.set('x402Payment', {
      verified: true,
      txHash: undefined,
      amount,
      network: config.network,
      payTo: paidRecipient.walletAddress,
      paidRecipientDomain: paidRecipient.domain,
    });

    await next();

    // Step 3: Deferred settlement — only if handler succeeded
    const responseStatus = c.res?.status || 200;
    if (responseStatus >= 400) {
      console.log(`[x402] Handler returned ${responseStatus} — skipping settlement (buyer protected)`);
      return;
    }

    // server.settlePayment(decodedPayload, requirement)
    const settleResult = await server.settlePayment(paymentPayload, paymentRequirement);

    if (!settleResult.success) {
      console.error(`[x402] Settle failed: ${settleResult.errorReason}`);
      c.res = undefined as any;
      return c.json({
        error: `Payment settlement failed: ${settleResult.errorReason || settleResult.errorMessage}`,
      }, 502);
    }

    console.log(`[x402] Settled: tx=${settleResult.transaction}, network=${settleResult.network}`);

    // Step 4: Attach PAYMENT-RESPONSE header
    if (c.res) {
      c.res.headers.set('PAYMENT-RESPONSE', encodeBase64({
        x402Version: 2,
        success: true,
        transaction: settleResult.transaction,
        network: settleResult.network,
      }));
    }

    c.set('x402Payment', {
      verified: true,
      txHash: settleResult.transaction,
      amount,
      network: config.network,
      payTo: paidRecipient.walletAddress,
      paidRecipientDomain: paidRecipient.domain,
    });

    // Record payment (async, non-blocking)
    const senderAgent = c.get('agent') as { id: string } | undefined;
    if (senderAgent && paidRecipient.id) {
      recordPayment({
        fromAgentId: senderAgent.id,
        toAgentId: paidRecipient.id,
        amount,
        txHash: settleResult.transaction || '',
        network: config.network,
        paymentSignature: paymentHeader,
      }).catch(err => console.error('[x402] Record error:', err));
    }

  } catch (err: any) {
    console.error('[x402] SDK error:', err.message);
    return c.json({ error: `Payment processing error: ${err.message}` }, 502);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. A2A x402 MIDDLEWARE — Dynamic paywall for A2A routes
//    Same deferred settlement pattern as messaging middleware
// ═══════════════════════════════════════════════════════════════════════════

export async function x402A2ADynamicMiddleware(c: Context, next: Next) {
  const config = getX402SDKConfig();
  if (!config.enabled) return next();
  if (c.req.method !== 'POST') return next();

  const agentId = c.req.param('agentId');
  if (!agentId) return next();

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

  const amount = usdToUsdcAmount(targetAgent.messagePrice);

  const paymentRequirement = {
    scheme: 'exact' as const,
    network: config.network,
    amount,
    asset: config.asset,
    payTo: targetAgent.walletAddress,
    maxTimeoutSeconds: 300,
    extra: {
      name: 'USDC',
      version: '2',
      resourceUrl: `/a2a/${agentId}`,
    },
  };

  const paymentHeader = c.req.header('PAYMENT-SIGNATURE')
    || c.req.header('payment-signature')
    || c.req.header('X-PAYMENT');

  if (!paymentHeader) {
    const paymentRequired = {
      x402Version: 2,
      error: 'Payment required',
      resource: {
        url: `/a2a/${agentId}`,
        description: `A2A task to ${targetAgent.domain}`,
        mimeType: 'application/json',
      },
      accepts: [paymentRequirement],
    };
    return c.json(paymentRequired, 402, {
      'PAYMENT-REQUIRED': encodeBase64(paymentRequired),
    });
  }

  // Decode base64 → PaymentPayload
  const paymentPayload = decodePaymentSignature(paymentHeader);
  if (!paymentPayload) {
    return c.json({ error: 'Invalid PAYMENT-SIGNATURE header' }, 402);
  }

  try {
    await ensureInitialized();
    const server = getResourceServer();

    // Verify
    const verifyResult = await server.verifyPayment(paymentPayload, paymentRequirement);
    if (!verifyResult.isValid) {
      return c.json({
        x402Version: 2,
        error: `Payment verification failed: ${verifyResult.invalidReason}`,
        accepts: [paymentRequirement],
      }, 402);
    }

    // Set context + execute handler
    c.set('x402Payment', {
      verified: true,
      txHash: undefined,
      amount,
      network: config.network,
      payTo: targetAgent.walletAddress,
      paidRecipientDomain: targetAgent.domain,
    });

    await next();

    // Deferred settlement — only if handler succeeded
    const responseStatus = c.res?.status || 200;
    if (responseStatus >= 400) return;

    const settleResult = await server.settlePayment(paymentPayload, paymentRequirement);
    if (!settleResult.success) {
      c.res = undefined as any;
      return c.json({
        jsonrpc: '2.0', id: null,
        error: { code: -32000, message: `Settlement failed: ${settleResult.errorReason}` },
      }, 502);
    }

    console.log(`[x402] A2A settled: tx=${settleResult.transaction}`);

    if (c.res) {
      c.res.headers.set('PAYMENT-RESPONSE', encodeBase64({
        x402Version: 2, success: true,
        transaction: settleResult.transaction,
        network: settleResult.network,
      }));
    }

    // Record payment
    const senderAgent = c.get('agent') as { id: string } | undefined;
    recordPayment({
      fromAgentId: senderAgent?.id || targetAgent.id,
      toAgentId: targetAgent.id,
      amount,
      txHash: settleResult.transaction || '',
      network: config.network,
      paymentSignature: paymentHeader,
    }).catch(err => console.error('[x402] A2A record error:', err));

  } catch (err: any) {
    console.error('[x402] A2A SDK error:', err.message);
    return c.json({ error: `Payment error: ${err.message}` }, 502);
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────

function usdToUsdcAmount(usdPrice: string): string {
  const cleaned = usdPrice.replace(DOLLAR_PREFIX_RE, '');
  const amount = parseFloat(cleaned);
  if (isNaN(amount) || amount <= 0) return '0';
  return Math.round(amount * 1_000_000).toString();
}

async function recordPayment(params: {
  fromAgentId: string;
  toAgentId: string;
  amount: string;
  txHash: string;
  network: string;
  paymentSignature: string;
}): Promise<void> {
  try {
    await db.insert(payments).values({
      fromAgentId: params.fromAgentId,
      toAgentId: params.toAgentId,
      amount: params.amount,
      currency: 'USDC',
      txHash: params.txHash,
      chainId: parseInt(params.network.split(':')[1] || '0', 10),
      x402Proof: {
        x402Version: 2,
        scheme: 'exact',
        network: params.network,
        paymentSignature: params.paymentSignature,
        settledAt: new Date().toISOString(),
      },
      status: 'confirmed',
      paymentType: 'message_fee',
      confirmedAt: new Date(),
    });
  } catch (err) {
    console.error('[x402] Failed to record payment:', err);
  }
}

// ─── Agent payment info for discovery ────────────────────────────────────

export function getAgentPaymentInfo(agent: {
  x402Enabled: boolean | null;
  walletAddress: string | null;
  messagePrice: string | null;
}) {
  const config = getX402SDKConfig();

  if (!config.enabled || !agent.x402Enabled || !agent.walletAddress || !agent.messagePrice) {
    return null;
  }

  return {
    x402Version: 2,
    scheme: 'exact',
    network: config.network,
    amount: usdToUsdcAmount(agent.messagePrice),
    asset: config.asset,
    payTo: agent.walletAddress,
    price: agent.messagePrice,
    facilitatorUrl: config.facilitatorUrl,
  };
}

// ─── Context type declarations ───────────────────────────────────────────

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
