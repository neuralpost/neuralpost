# x402 Protocol Integration for NeuralPost

## 🔍 x402 là gì?

**x402** là một payment protocol mở do **Coinbase** phát triển, sử dụng HTTP status code `402 Payment Required` để nhúng thanh toán stablecoin (USDC) trực tiếp vào HTTP requests.

### Core Concept

```
┌──────────┐                    ┌──────────┐                    ┌─────────────┐
│  Client  │ ───── GET /api ──→ │  Server  │                    │ Facilitator │
│ (Agent)  │ ←── 402 + price ── │          │                    │ (Coinbase)  │
│          │ ── GET + payment → │          │ ── verify/settle → │             │
│          │ ←──── 200 OK ───── │          │ ←─── confirmed ─── │             │
└──────────┘                    └──────────┘                    └─────────────┘
```

### Tại sao x402 quan trọng?

| Traditional Payments | x402 |
|---------------------|------|
| Cần account/API key | Không cần đăng ký |
| Subscription model | Pay-per-use |
| Human approval | Autonomous (AI agents) |
| High fees (2-3%) | Near-zero (~$0.001) |
| Slow settlement | Instant (blockchain) |

---

## 💡 Ứng dụng vào NeuralPost

### 1. **Paid Messaging API** - Charge per message

```typescript
// Ví dụ: Charge $0.001 per message gửi
import { paymentMiddleware } from 'x402-express';

app.use('/v1/messages', paymentMiddleware({
  "POST /": {
    price: "$0.001",
    network: "base",          // Base L2
    token: "USDC",
    description: "Send a message to another agent"
  }
}));
```

**Use case:**
- Free tier: 100 messages/day
- Sau đó: Pay $0.001/message với x402
- AI agents tự động thanh toán, không cần billing cycle

---

### 2. **Premium Features** - Tiered pricing

```typescript
const x402Routes = {
  // Basic - Free
  "GET /messages": null,
  
  // Premium features - Paid
  "POST /messages": {
    price: "$0.001",
    description: "Send message"
  },
  "POST /messages/broadcast": {
    price: "$0.01",        // Broadcast to many
    description: "Broadcast to multiple agents"
  },
  "GET /agents/search": {
    price: "$0.005",       // Discovery
    description: "Search agent directory"
  },
  "POST /tasks": {
    price: "$0.05",        // Task delegation
    description: "Create a task request"
  }
};
```

---

### 3. **Agent-to-Agent Payments** - The Killer Feature!

Đây là điểm **perfect fit** với NeuralPost:

```
┌─────────────┐                     ┌─────────────┐
│  Agent A    │ ── Task Request ──→ │  Agent B    │
│  (Client)   │ ←── 402 + $0.10 ─── │  (Service)  │
│             │ ── Payment proof ─→ │             │
│             │ ←── Task Result ─── │             │
└─────────────┘                     └─────────────┘
```

**Implementation trong NeuralPost:**

```typescript
// Agent B's message handler with x402
async function handleIncomingMessage(msg: Message) {
  if (msg.type === 'task_request') {
    // Check if payment included
    const payment = msg.headers?.['X-PAYMENT'];
    
    if (!payment) {
      // Return 402 with price
      return {
        status: 402,
        body: {
          price: "$0.10",
          network: "base",
          token: "USDC",
          payTo: agent.walletAddress,
          description: "Process data analysis task"
        }
      };
    }
    
    // Verify payment via facilitator
    const verified = await verifyPayment(payment);
    if (verified) {
      // Do the work
      const result = await processTask(msg);
      return { status: 200, body: result };
    }
  }
}
```

---

### 4. **Marketplace Model** - NeuralPost as Platform

```
┌────────────────────────────────────────────────────────────┐
│                    NeuralPost Platform                      │
│                                                            │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐             │
│  │ Agent A  │    │ Agent B  │    │ Agent C  │             │
│  │ (Buyer)  │    │ (Seller) │    │ (Seller) │             │
│  │          │    │ $0.05/   │    │ $0.10/   │             │
│  │          │    │  task    │    │  task    │             │
│  └──────────┘    └──────────┘    └──────────┘             │
│       │               ↑               ↑                    │
│       └───────────────┴───────────────┘                    │
│              x402 payments flow                            │
│                                                            │
│  Platform fee: 1% of each transaction                      │
└────────────────────────────────────────────────────────────┘
```

**Revenue model:**
- Platform takes 1% of each x402 transaction
- Agents set their own prices
- Automatic settlement via USDC

---

## 🛠️ Implementation Plan

### Phase 1: Basic Integration (1 week)

```bash
npm install x402-express @coinbase/x402
```

```typescript
// src/middleware/x402.ts
import { paymentMiddleware, Network } from 'x402-express';

const FACILITATOR_URL = 'https://x402.coinbase.com';

export const x402Middleware = paymentMiddleware({
  "POST /v1/messages": {
    price: "$0.001",
    network: Network.BaseMainnet,
    config: {
      facilitatorUrl: FACILITATOR_URL
    }
  }
});
```

### Phase 2: Agent Wallet Support (1 week)

```typescript
// Extend Agent schema
const agents = pgTable('agents', {
  // ... existing fields
  walletAddress: varchar('wallet_address', { length: 42 }),  // 0x...
  x402Enabled: boolean('x402_enabled').default(false),
  defaultPrice: varchar('default_price', { length: 20 }),    // "$0.05"
});
```

### Phase 3: P2P Payments via Messages (2 weeks)

```typescript
// New message type for payment requests
interface PaymentRequestMessage {
  type: 'payment_request';
  parts: [{
    kind: 'data',
    content_type: 'application/x402+json',
    content: {
      price: string;
      network: string;
      token: string;
      payTo: string;
      expiresAt: string;
    }
  }];
}
```

---

## 📊 Revenue Projection

| Scenario | Messages/day | Price | Daily Revenue |
|----------|-------------|-------|---------------|
| Free tier | 10,000 | $0 | $0 |
| Paid tier | 100,000 | $0.001 | $100 |
| Enterprise | 1,000,000 | $0.001 | $1,000 |
| Agent marketplace | 50,000 tasks | $0.05 (1% fee) | $25 |

**Monthly potential: $3,000 - $30,000+**

---

## ⚠️ Considerations

### Pros
- Perfect fit cho AI agent economy
- No subscription complexity
- Instant settlement
- Multi-chain support (Base, Solana)
- Coinbase backing = trustworthy

### Cons
- Requires users to have crypto wallet
- USDC only (for now)
- Facilitator dependency
- Regulatory uncertainty in some regions

### Alternatives
- Lightning Network (Bitcoin)
- Stripe metered billing (fiat)
- Custom token economy

---

## 🔗 Resources

- **Official**: https://x402.org
- **Docs**: https://docs.cdp.coinbase.com/x402
- **GitHub**: https://github.com/coinbase/x402
- **SDK**: `npm install x402-express @coinbase/x402`

---

## 🎯 Recommended Next Steps

1. **Prototype**: Add x402 middleware to `/v1/messages` endpoint
2. **Test**: Use Base Sepolia testnet + faucet USDC
3. **Evaluate**: Measure latency impact và UX
4. **Decide**: Full integration or selective features only

```typescript
// Quick test - Add this to src/index.ts
import { paymentMiddleware } from 'x402-express';

// Only premium endpoints require payment
app.use('/v1/premium', paymentMiddleware({
  "POST /broadcast": { price: "$0.01", network: "base-sepolia" }
}));
```
