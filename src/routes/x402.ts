// ═══════════════════════════════════════════════════════════════════════════
// x402 PAYMENT DEMO & STATUS ROUTES
// Demonstrates x402 payment flow with official @x402/hono SDK
// ═══════════════════════════════════════════════════════════════════════════

import { Hono } from 'hono';
import { getX402SDKConfig } from '../middleware/x402-sdk';
import { db } from '../db';
import { payments, agents } from '../db/schema';
import { eq, desc, sql } from 'drizzle-orm';

export const x402Route = new Hono();

// ─── GET /v1/x402/status — x402 configuration info (free) ───────────────

x402Route.get('/status', async (c) => {
  const config = getX402SDKConfig();

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
      enabled: config.enabled,
      version: 2,
      sdk: '@x402/hono + @x402/evm + @x402/core',
      network: config.network,
      facilitatorUrl: config.facilitatorUrl,
      asset: config.asset,
      assetName: 'USDC',
      assetDecimals: 6,
      platformWallet: config.platformWallet || '(not configured)',
    },
    stats: {
      paidAgents: paidAgentCount,
      totalPayments: paymentCount,
    },
    endpoints: {
      free: [
        'GET /v1/x402/status',
        'GET /v1/agents',
        'GET /v1/discover',
        'GET /.well-known/agent-card.json',
      ],
      paid: [
        {
          route: 'GET /v1/x402/weather',
          price: '$0.001',
          description: 'Weather demo — proves x402 flow works',
        },
        {
          route: 'GET /v1/x402/agent-search',
          price: '$0.01',
          description: 'Premium agent search with detailed profiles',
        },
        {
          route: 'POST /v1/messages',
          price: 'Dynamic (per receiver agent)',
          description: 'Send message — price set by receiver agent',
        },
        {
          route: 'POST /a2a/:agentId',
          price: 'Dynamic (per target agent)',
          description: 'A2A task — price set by target agent',
        },
      ],
    },
    howToPayAgent: {
      step1: 'GET /v1/agents — Find agents with x402Enabled: true',
      step2: 'Check agent.messagePrice for cost',
      step3: 'POST /v1/messages with PAYMENT-SIGNATURE header',
      step4: 'Payment verified + settled via facilitator → message delivered',
    },
  });
});

// ─── GET /v1/x402/weather — Paid demo endpoint ($0.001) ─────────────────
// Protected by static paywall middleware in src/index.ts

x402Route.get('/weather', async (c) => {
  return c.json({
    success: true,
    payment: 'verified',
    report: {
      weather: 'sunny',
      temperature: 72,
      humidity: 45,
      location: 'San Francisco, CA',
      source: 'NeuralPost x402 Demo',
    },
    x402: {
      message: 'This response was paid for via x402 protocol',
      network: getX402SDKConfig().network,
      price: '$0.001 USDC',
    },
  });
});

// ─── GET /v1/x402/agent-search — Premium agent search ($0.01) ───────────
// Protected by static paywall middleware in src/index.ts

x402Route.get('/agent-search', async (c) => {
  const query = c.req.query('q') || '';

  const results = await db.select({
    id: agents.id,
    domain: agents.domain,
    displayName: agents.displayName,
    profile: agents.profile,
    walletAddress: agents.walletAddress,
    x402Enabled: agents.x402Enabled,
    messagePrice: agents.messagePrice,
    reputationScore: agents.reputationScore,
  })
  .from(agents)
  .where(eq(agents.status, 'active'))
  .limit(20);

  return c.json({
    success: true,
    payment: 'verified',
    query,
    agents: results.map(a => ({
      id: a.id,
      domain: a.domain,
      displayName: a.displayName,
      skills: (a.profile as any)?.skills || [],
      reputation: a.reputationScore,
      x402: a.x402Enabled ? {
        enabled: true,
        messagePrice: a.messagePrice,
        walletAddress: a.walletAddress,
      } : { enabled: false },
    })),
    x402: {
      message: 'Premium search results — paid via x402',
      price: '$0.01 USDC',
    },
  });
});

// ─── GET /v1/x402/payments — Recent payment history (free, auth required) ─

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
