// ═══════════════════════════════════════════════════════════════════════════
// x402 PAYMENT STATUS ROUTES
//
// x402 payments are implemented as MIDDLEWARE on:
//   - POST /v1/messages  →  x402MessageMiddleware
//   - POST /a2a/:agentId →  x402A2AMiddleware
//
// When a receiver agent has x402Enabled=true, the middleware returns
// 402 Payment Required with PAYMENT-REQUIRED header. The sender includes
// a PAYMENT-SIGNATURE header to complete delivery.
//
// These routes provide status/info endpoints only.
// ═══════════════════════════════════════════════════════════════════════════

import { Hono } from 'hono';
import { db } from '../db';
import { payments, agents } from '../db/schema';
import { eq, desc, sql } from 'drizzle-orm';

export const x402Route = new Hono();

// ─── GET /v1/x402/status — x402 configuration info (free) ───────────────

x402Route.get('/status', async (c) => {
  const enabled = process.env.X402_ENABLED === 'true';
  const network = process.env.X402_NETWORK || 'testnet';

  // Count paid agents
  const [{ count: paidAgentCount }] = await db.select({
    count: sql<number>`count(*)::int`,
  })
  .from(agents)
  .where(eq(agents.x402Enabled, true));

  // Count total payments
  const [{ count: paymentCount }] = await db.select({
    count: sql<number>`count(*)::int`,
  })
  .from(payments);

  return c.json({
    success: true,
    x402: {
      enabled,
      version: 2,
      network,
      asset: 'USDC',
      implementation: 'Middleware on /v1/messages + /a2a/:agentId',
    },
    stats: {
      paidAgents: paidAgentCount,
      totalPayments: paymentCount,
    },
    flow: {
      step1: 'GET /v1/agents — Find agents with x402Enabled: true',
      step2: 'Check agent.messagePrice for cost',
      step3: 'POST /v1/messages without payment → 402 with PAYMENT-REQUIRED header',
      step4: 'POST /v1/messages with PAYMENT-SIGNATURE header → message delivered',
    },
  });
});

// ─── GET /v1/x402/payments — Recent payment history (free) ──────────────

x402Route.get('/payments', async (c) => {
  const recentPayments = await db.select({
    id: payments.id,
    amount: payments.amount,
    currency: payments.currency,
    txHash: payments.txHash,
    chainId: payments.chainId,
    status: payments.status,
    paymentType: payments.paymentType,
    createdAt: payments.createdAt,
  })
  .from(payments)
  .orderBy(desc(payments.createdAt))
  .limit(20);

  return c.json({
    success: true,
    payments: recentPayments,
    count: recentPayments.length,
  });
});
