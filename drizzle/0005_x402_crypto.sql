-- ═══════════════════════════════════════════════════════════════════════════
-- V3: x402 Crypto & Payment Infrastructure
-- Adds wallet/payment columns to agents, creates payments, escrows,
-- reputation_history, and onchain_events tables.
-- x402 Protocol V2 — https://docs.cdp.coinbase.com/x402
-- ═══════════════════════════════════════════════════════════════════════════

-- ───────────────────────────────────────────────────────────────────────────
-- 1. Extend agents table with wallet & x402 columns
-- ───────────────────────────────────────────────────────────────────────────

ALTER TABLE "agents" ADD COLUMN IF NOT EXISTS "wallet_address" varchar(42);
ALTER TABLE "agents" ADD COLUMN IF NOT EXISTS "wallet_custody_type" varchar(20) DEFAULT 'protocol';
ALTER TABLE "agents" ADD COLUMN IF NOT EXISTS "x402_enabled" boolean DEFAULT false;
ALTER TABLE "agents" ADD COLUMN IF NOT EXISTS "message_price" varchar(20);
ALTER TABLE "agents" ADD COLUMN IF NOT EXISTS "reputation_score" integer DEFAULT 5000;

--> statement-breakpoint

CREATE INDEX IF NOT EXISTS "agents_wallet_idx" ON "agents" ("wallet_address");
CREATE INDEX IF NOT EXISTS "agents_reputation_idx" ON "agents" ("reputation_score");

--> statement-breakpoint

-- ───────────────────────────────────────────────────────────────────────────
-- 2. Payments table — tracks x402 message fees and task escrow payments
-- ───────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS "payments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"message_id" uuid,
	"task_id" varchar(255),
	"from_agent_id" uuid NOT NULL,
	"to_agent_id" uuid NOT NULL,
	"amount" varchar(78) NOT NULL,
	"currency" varchar(10) NOT NULL,
	"tx_hash" varchar(66),
	"chain_id" integer,
	"escrow_id" varchar(66),
	"x402_proof" jsonb,
	"status" varchar(20) DEFAULT 'pending' NOT NULL,
	"payment_type" varchar(30) DEFAULT 'message_fee' NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"confirmed_at" timestamp
);

--> statement-breakpoint

-- Foreign keys
ALTER TABLE "payments" ADD CONSTRAINT "payments_message_id_fk"
	FOREIGN KEY ("message_id") REFERENCES "messages"("id") ON DELETE SET NULL;
ALTER TABLE "payments" ADD CONSTRAINT "payments_from_agent_id_fk"
	FOREIGN KEY ("from_agent_id") REFERENCES "agents"("id");
ALTER TABLE "payments" ADD CONSTRAINT "payments_to_agent_id_fk"
	FOREIGN KEY ("to_agent_id") REFERENCES "agents"("id");

-- Indexes
CREATE INDEX IF NOT EXISTS "payments_from_agent_idx" ON "payments" ("from_agent_id");
CREATE INDEX IF NOT EXISTS "payments_to_agent_idx" ON "payments" ("to_agent_id");
CREATE INDEX IF NOT EXISTS "payments_task_idx" ON "payments" ("task_id");
CREATE INDEX IF NOT EXISTS "payments_status_idx" ON "payments" ("status");
CREATE UNIQUE INDEX IF NOT EXISTS "payments_tx_hash_unique_idx" ON "payments" ("tx_hash");

--> statement-breakpoint

-- ───────────────────────────────────────────────────────────────────────────
-- 3. Escrows table — task-based escrow tracking (NeuralPostEscrow contract)
-- ───────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS "escrows" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"escrow_id_onchain" varchar(66) UNIQUE,
	"task_id" varchar(255) NOT NULL,
	"client_agent_id" uuid NOT NULL,
	"server_agent_id" uuid NOT NULL,
	"payment_token" varchar(42) NOT NULL,
	"amount" varchar(78) NOT NULL,
	"relay_fee_bps" integer DEFAULT 250,
	"created_at" timestamp DEFAULT now(),
	"expires_at" timestamp NOT NULL,
	"settled_at" timestamp,
	"status" varchar(20) DEFAULT 'active' NOT NULL,
	"payout_amount" varchar(78),
	"fee_amount" varchar(78),
	"settlement_tx_hash" varchar(66)
);

--> statement-breakpoint

-- Foreign keys
ALTER TABLE "escrows" ADD CONSTRAINT "escrows_client_agent_id_fk"
	FOREIGN KEY ("client_agent_id") REFERENCES "agents"("id");
ALTER TABLE "escrows" ADD CONSTRAINT "escrows_server_agent_id_fk"
	FOREIGN KEY ("server_agent_id") REFERENCES "agents"("id");

-- Indexes
CREATE INDEX IF NOT EXISTS "escrows_task_idx" ON "escrows" ("task_id");
CREATE INDEX IF NOT EXISTS "escrows_client_idx" ON "escrows" ("client_agent_id");
CREATE INDEX IF NOT EXISTS "escrows_server_idx" ON "escrows" ("server_agent_id");
CREATE INDEX IF NOT EXISTS "escrows_status_idx" ON "escrows" ("status");

--> statement-breakpoint

-- ───────────────────────────────────────────────────────────────────────────
-- 4. Reputation history — score changes over time
-- ───────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS "reputation_history" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"agent_id" uuid NOT NULL,
	"old_score" integer NOT NULL,
	"new_score" integer NOT NULL,
	"delta" integer NOT NULL,
	"reason" varchar(50) NOT NULL,
	"reference_id" varchar(255),
	"tx_hash" varchar(66),
	"created_at" timestamp DEFAULT now()
);

--> statement-breakpoint

ALTER TABLE "reputation_history" ADD CONSTRAINT "reputation_history_agent_id_fk"
	FOREIGN KEY ("agent_id") REFERENCES "agents"("id") ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS "reputation_history_agent_idx"
	ON "reputation_history" ("agent_id", "created_at");

--> statement-breakpoint

-- ───────────────────────────────────────────────────────────────────────────
-- 5. On-chain events — indexed blockchain events for local queries
-- ───────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS "onchain_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"chain_id" integer NOT NULL,
	"contract_address" varchar(42) NOT NULL,
	"event_name" varchar(100) NOT NULL,
	"block_number" bigint NOT NULL,
	"tx_hash" varchar(66) NOT NULL,
	"log_index" integer NOT NULL,
	"event_data" jsonb NOT NULL,
	"processed" boolean DEFAULT false,
	"processed_at" timestamp,
	"created_at" timestamp DEFAULT now()
);

--> statement-breakpoint

CREATE INDEX IF NOT EXISTS "onchain_events_chain_block_idx"
	ON "onchain_events" ("chain_id", "block_number");
CREATE INDEX IF NOT EXISTS "onchain_events_name_idx"
	ON "onchain_events" ("event_name");
CREATE INDEX IF NOT EXISTS "onchain_events_processed_idx"
	ON "onchain_events" ("processed");
