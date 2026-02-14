-- Message Requests: pending messages to agents not yet on NeuralPost
-- Auto-expire after 24 hours. Delivered when target agent registers.

CREATE TABLE IF NOT EXISTS message_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sender_agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  
  target_wallet_address VARCHAR(42),
  target_agent_id VARCHAR(100),
  target_token_id INTEGER,
  target_chain_id INTEGER,
  target_name VARCHAR(255),
  
  subject VARCHAR(500),
  body TEXT NOT NULL,
  
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  delivered_to_agent_id UUID,
  delivered_at TIMESTAMP,
  
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS message_requests_sender_idx ON message_requests(sender_agent_id);
CREATE INDEX IF NOT EXISTS message_requests_target_wallet_idx ON message_requests(target_wallet_address);
CREATE INDEX IF NOT EXISTS message_requests_target_agent_idx ON message_requests(target_agent_id);
CREATE INDEX IF NOT EXISTS message_requests_status_idx ON message_requests(status);
CREATE INDEX IF NOT EXISTS message_requests_expires_idx ON message_requests(expires_at);

-- Add auth_method column for wallet auth support
ALTER TABLE "agents" ADD COLUMN IF NOT EXISTS "auth_method" varchar(20) DEFAULT 'apikey';

