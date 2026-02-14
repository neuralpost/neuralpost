// ═══════════════════════════════════════════════════════════════════════════
// NEURALPOST x402 PAYMENT MIDDLEWARE — SKALE Integration
//
// Protects NeuralPost agent API endpoints with x402 payments on SKALE.
// Uses Kobaru facilitator (https://gateway.kobaru.io) for settlement.
//
// Architecture:
//   Client → [x402 402 check] → Kobaru facilitator → [settle on SKALE] → Access granted
//
// Pricing model:
//   - Agent discovery (free)
//   - Agent messaging: 0.001 USDC per message
//   - Agent reputation query: 0.0005 USDC per query
//   - Premium agent services: configurable per-agent
//
// Usage:
//   import { createNeuralPostPaywall } from './x402-middleware';
//   app.use('/api/agents/:id/message', createNeuralPostPaywall('message'));
// ═══════════════════════════════════════════════════════════════════════════

import {
  SKALE_FACILITATOR_URL,
  SKALE_PAYMENT_TOKENS,
  SKALE_PAYMENT_CHAIN,
  CHAIN_CONFIGS,
  X402_TRANSPORT,
} from './types';

// ─── Payment Configuration ──────────────────────────────────────────────

export interface PaywallConfig {
  facilitatorUrl: string;
  receivingAddress: string;
  network: string;            // CAIP-2 format: "eip155:324705682"
  asset: string;              // USDC address on target chain
  assetName: string;          // "Bridged USDC (SKALE Bridge)"
}

// Default config for SKALE Base Sepolia
export function getDefaultPaywallConfig(): PaywallConfig {
  const chainId = SKALE_PAYMENT_CHAIN;
  return {
    facilitatorUrl: process.env.FACILITATOR_URL || SKALE_FACILITATOR_URL,
    receivingAddress: process.env.PAYMENT_RECEIVING_ADDRESS || '',
    network: `eip155:${chainId}`,
    asset: SKALE_PAYMENT_TOKENS.bridgedUsdc,
    assetName: 'Bridged USDC (SKALE Bridge)',
  };
}

// ─── Price Tiers (in USDC atomic units, 6 decimals) ─────────────────────

export const PRICE_TIERS = {
  // Agent messaging
  message: '1000',        // 0.001 USDC
  messageBatch: '5000',   // 0.005 USDC (batch of 10)

  // Reputation queries
  reputation: '500',      // 0.0005 USDC
  reputationFull: '2000', // 0.002 USDC (full history)

  // Agent registration (premium features)
  premiumRegister: '10000',  // 0.01 USDC (priority queue)

  // Validation requests
  validation: '5000',     // 0.005 USDC

  // Free tier
  free: '0',
} as const;

export type PriceTier = keyof typeof PRICE_TIERS;

// ─── x402 Payment Requirements Builder ──────────────────────────────────
//
// Builds the 402 response body per x402 spec.
// This is what gets sent to the client when they hit a paywalled endpoint.

export function buildPaymentRequirements(
  tier: PriceTier,
  description: string,
  config?: Partial<PaywallConfig>,
): {
  accepts: Array<{
    scheme: 'exact';
    network: string;
    payTo: string;
    price: {
      amount: string;
      asset: string;
      extra: { name: string; version: string };
    };
  }>;
  description: string;
  mimeType: string;
} {
  const c = { ...getDefaultPaywallConfig(), ...config };

  return {
    accepts: [
      {
        scheme: 'exact',
        network: c.network,
        payTo: c.receivingAddress,
        price: {
          amount: PRICE_TIERS[tier],
          asset: c.asset,
          extra: {
            name: c.assetName,
            version: '1',
          },
        },
      },
    ],
    description,
    mimeType: 'application/json',
  };
}

// ─── x402 Header Helpers ────────────────────────────────────────────────

export function encodePaymentRequired(paymentReqs: ReturnType<typeof buildPaymentRequirements>): string {
  return Buffer.from(JSON.stringify(paymentReqs)).toString('base64');
}

export function decodePaymentSignature(header: string): unknown {
  try {
    return JSON.parse(Buffer.from(header, 'base64').toString('utf-8'));
  } catch {
    return null;
  }
}

// ─── Facilitator Client ─────────────────────────────────────────────────

export async function verifyPayment(
  paymentPayload: unknown,
  config?: Partial<PaywallConfig>,
): Promise<{ valid: boolean; invalidMessage?: string }> {
  const c = { ...getDefaultPaywallConfig(), ...config };

  const res = await fetch(`${c.facilitatorUrl}${X402_TRANSPORT.facilitator.endpoints.verify}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(paymentPayload),
  });

  if (!res.ok) {
    return { valid: false, invalidMessage: `Facilitator error: ${res.status}` };
  }

  return res.json();
}

export async function settlePayment(
  paymentPayload: unknown,
  config?: Partial<PaywallConfig>,
): Promise<{ success: boolean; transaction?: string; errorMessage?: string }> {
  const c = { ...getDefaultPaywallConfig(), ...config };

  const res = await fetch(`${c.facilitatorUrl}${X402_TRANSPORT.facilitator.endpoints.settle}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(paymentPayload),
  });

  if (!res.ok) {
    return { success: false, errorMessage: `Settlement failed: ${res.status}` };
  }

  return res.json();
}

// ─── Express/Hono-style Middleware Factory ───────────────────────────────
//
// Generic middleware that works with any HTTP framework.
// Returns a function: (req, res, next) => void
//
// Example with Express:
//   app.post('/api/agents/:id/message', createPaywallMiddleware('message'), handler);
//
// Example with Hono (using @x402/hono instead):
//   See SKALE docs: docs.skale.space/cookbook/x402/accepting-payments

export function createPaywallMiddleware(
  tier: PriceTier,
  description?: string,
  config?: Partial<PaywallConfig>,
) {
  const paymentReqs = buildPaymentRequirements(
    tier,
    description || `NeuralPost: ${tier} access`,
    config,
  );

  return async function x402Middleware(
    req: { headers: Record<string, string | undefined> },
    res: {
      status: (code: number) => any;
      setHeader: (name: string, value: string) => any;
      json: (body: unknown) => any;
    },
    next: () => void,
  ) {
    // Check for payment header
    const paymentHeader = req.headers[X402_TRANSPORT.http.headers.paymentSignature.toLowerCase()]
      || req.headers[X402_TRANSPORT.http.headers.paymentSignature];

    if (!paymentHeader) {
      // No payment — return 402
      const encoded = encodePaymentRequired(paymentReqs);
      res.status(402);
      res.setHeader(X402_TRANSPORT.http.headers.paymentRequired, encoded);
      return res.json(paymentReqs);
    }

    // Decode and verify payment
    const paymentPayload = decodePaymentSignature(paymentHeader);
    if (!paymentPayload) {
      res.status(402);
      return res.json({ error: 'Invalid payment signature' });
    }

    // Verify with facilitator
    const verification = await verifyPayment(paymentPayload, config);
    if (!verification.valid) {
      res.status(402);
      return res.json({ error: 'Payment verification failed', message: verification.invalidMessage });
    }

    // Settle payment
    const settlement = await settlePayment(paymentPayload, config);
    if (!settlement.success) {
      res.status(402);
      return res.json({ error: 'Payment settlement failed', message: settlement.errorMessage });
    }

    // Payment OK — encode settlement response and proceed
    if (settlement.transaction) {
      const settlementEncoded = Buffer.from(JSON.stringify(settlement)).toString('base64');
      res.setHeader(X402_TRANSPORT.http.headers.paymentResponse, settlementEncoded);
    }

    next();
  };
}

// ─── Route Definitions for NeuralPost ───────────────────────────────────
//
// Pre-configured payment requirements for NeuralPost's API routes.
// Use with @x402/hono paymentMiddleware or the generic middleware above.

export function getNeuralPostRoutes(config?: Partial<PaywallConfig>) {
  const c = { ...getDefaultPaywallConfig(), ...config };

  return {
    // Free routes (no payment)
    'GET /api/agents': null,                        // Agent discovery
    'GET /api/agents/:id': null,                    // Agent profile
    'GET /.well-known/agent-card.json': null,       // A2A discovery

    // Paid routes
    'POST /api/agents/:id/message': buildPaymentRequirements('message', 'Send message to agent', c),
    'POST /api/agents/:id/message/batch': buildPaymentRequirements('messageBatch', 'Send batch messages', c),
    'GET /api/agents/:id/reputation': buildPaymentRequirements('reputation', 'Query agent reputation', c),
    'GET /api/agents/:id/reputation/full': buildPaymentRequirements('reputationFull', 'Full reputation history', c),
    'POST /api/agents/:id/validate': buildPaymentRequirements('validation', 'Request agent validation', c),
  };
}
