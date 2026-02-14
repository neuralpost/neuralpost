-- ═══════════════════════════════════════════════════════════════════════════
-- MIGRATION 0003: x402 Payment Protocol + Crypto Infrastructure
-- NeuralPost v2.2.10
--
-- Adds:
--   - Wallet/crypto columns to agents table
--   - payments table (x402 payment records)
--   - escrows table (task-based escrow tracking)
--   - reputation_history table (agent reputation scores)
--   - onchain_events table (blockchain event logs)
--
-- Run: psql -d neuralpost -f migrations/0003_x402_crypto.sql
-- ═══════════════════════════════════════════════════════════════════════════

BEGIN;

-- ─── 1. Add crypto/wallet columns to agents ──────────────────────────────

ALTER TABLE agents ADD COLUMN IF NOT EXISTS wallet_address VARCHAR(42);
ALTER TABLE agents ADD COLUMN IF NOT EXISTS encrypted_private_key TEXT;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS wallet_custody_type VARCHAR(20) DEFAULT 'protocol';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS key_exported_at TIMESTAMP;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS chain_id INTEGER;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS on_chain_agent_id INTEGER;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS registration_tx_hash VARCHAR(66);
ALTER TABLE agents ADD COLUMN IF NOT EXISTS reputation_score INTEGER DEFAULT 5000;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS auth_method VARCHAR(20) DEFAULT 'apikey';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS registration_uri VARCHAR(500);
ALTER TABLE agents ADD COLUMN IF NOT EXISTS x402_enabled BOOLEAN DEFAULT false;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS message_price VARCHAR(20);

-- Indexes
CREATE INDEX IF NOT EXISTS agents_wallet_idx ON agents(wallet_address);
CREATE INDEX IF NOT EXISTS agents_reputation_idx ON agents(reputation_score);

-- ─── 2. Payments table (x402 payment records) ───────────────────────────

CREATE TABLE IF NOT EXISTS payments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  message_id UUID REFERENCES messages(id) ON DELETE SET NULL,
  task_id VARCHAR(255),
  from_agent_id UUID NOT NULL REFERENCES agents(id),
  to_agent_id UUID NOT NULL REFERENCES agents(id),
  
  amount VARCHAR(78) NOT NULL,
  currency VARCHAR(10) NOT NULL,
  
  tx_hash VARCHAR(66),
  chain_id INTEGER,
  escrow_id VARCHAR(66),
  x402_proof JSONB,
  
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  payment_type VARCHAR(30) NOT NULL DEFAULT 'message_fee',
  
  created_at TIMESTAMP DEFAULT NOW(),
  confirmed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS payments_from_agent_idx ON payments(from_agent_id);
CREATE INDEX IF NOT EXISTS payments_to_agent_idx ON payments(to_agent_id);
CREATE INDEX IF NOT EXISTS payments_task_idx ON payments(task_id);
CREATE INDEX IF NOT EXISTS payments_status_idx ON payments(status);
CREATE UNIQUE INDEX IF NOT EXISTS payments_tx_hash_unique_idx ON payments(tx_hash);

-- ─── 3. Escrows table (task-based escrow tracking) ──────────────────────

CREATE TABLE IF NOT EXISTS escrows (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  escrow_id_onchain VARCHAR(66) UNIQUE,
  task_id VARCHAR(255) NOT NULL,
  
  client_agent_id UUID NOT NULL REFERENCES agents(id),
  server_agent_id UUID NOT NULL REFERENCES agents(id),
  
  payment_token VARCHAR(42) NOT NULL,
  amount VARCHAR(78) NOT NULL,
  relay_fee_bps INTEGER DEFAULT 250,
  
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL,
  settled_at TIMESTAMP,
  
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  
  payout_amount VARCHAR(78),
  fee_amount VARCHAR(78),
  settlement_tx_hash VARCHAR(66)
);

CREATE INDEX IF NOT EXISTS escrows_task_idx ON escrows(task_id);
CREATE INDEX IF NOT EXISTS escrows_client_idx ON escrows(client_agent_id);
CREATE INDEX IF NOT EXISTS escrows_server_idx ON escrows(server_agent_id);
CREATE INDEX IF NOT EXISTS escrows_status_idx ON escrows(status);

-- ─── 4. Reputation history table ────────────────────────────────────────

CREATE TABLE IF NOT EXISTS reputation_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  
  old_score INTEGER NOT NULL,
  new_score INTEGER NOT NULL,
  delta INTEGER NOT NULL,
  
  reason VARCHAR(50) NOT NULL,
  reference_id VARCHAR(255),
  tx_hash VARCHAR(66),
  
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS reputation_history_agent_idx ON reputation_history(agent_id, created_at);

-- ─── 5. On-chain events table ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS onchain_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  chain_id INTEGER NOT NULL,
  contract_address VARCHAR(42) NOT NULL,
  event_name VARCHAR(100) NOT NULL,
  block_number BIGINT NOT NULL,
  tx_hash VARCHAR(66) NOT NULL,
  log_index INTEGER NOT NULL,
  
  event_data JSONB NOT NULL,
  
  processed BOOLEAN DEFAULT false,
  processed_at TIMESTAMP,
  
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS onchain_events_chain_block_idx ON onchain_events(chain_id, block_number);
CREATE INDEX IF NOT EXISTS onchain_events_name_idx ON onchain_events(event_name);
CREATE INDEX IF NOT EXISTS onchain_events_processed_idx ON onchain_events(processed);

-- ─── 6. Bidirectional connection uniqueness (from schema TODO) ──────────

CREATE UNIQUE INDEX IF NOT EXISTS connections_pair_unique_idx 
  ON connections (LEAST(requester_id, target_id), GREATEST(requester_id, target_id));

COMMIT;

-- ═══════════════════════════════════════════════════════════════════════════
-- ROLLBACK (if needed):
-- ═══════════════════════════════════════════════════════════════════════════
-- DROP TABLE IF EXISTS onchain_events CASCADE;
-- DROP TABLE IF EXISTS reputation_history CASCADE;
-- DROP TABLE IF EXISTS escrows CASCADE;
-- DROP TABLE IF EXISTS payments CASCADE;
-- DROP INDEX IF EXISTS connections_pair_unique_idx;
-- ALTER TABLE agents DROP COLUMN IF EXISTS wallet_address;
-- ALTER TABLE agents DROP COLUMN IF EXISTS encrypted_private_key;
-- ALTER TABLE agents DROP COLUMN IF EXISTS wallet_custody_type;
-- ALTER TABLE agents DROP COLUMN IF EXISTS key_exported_at;
-- ALTER TABLE agents DROP COLUMN IF EXISTS chain_id;
-- ALTER TABLE agents DROP COLUMN IF EXISTS on_chain_agent_id;
-- ALTER TABLE agents DROP COLUMN IF EXISTS registration_tx_hash;
-- ALTER TABLE agents DROP COLUMN IF EXISTS reputation_score;
-- ALTER TABLE agents DROP COLUMN IF EXISTS auth_method;
-- ALTER TABLE agents DROP COLUMN IF EXISTS registration_uri;
-- ALTER TABLE agents DROP COLUMN IF EXISTS x402_enabled;
-- ALTER TABLE agents DROP COLUMN IF EXISTS message_price;
