-- AgentRelay v2.1.3: Bidirectional connection uniqueness
-- Prevents both (A→B) and (B→A) from existing simultaneously
-- Fixes race condition where concurrent requests could bypass app-level check

-- Create functional unique index on ordered pair
CREATE UNIQUE INDEX IF NOT EXISTS connections_pair_unique_idx
ON connections (LEAST(requester_id, target_id), GREATEST(requester_id, target_id));

-- Note: Keep the original connections_unique_idx for now (backward compat).
-- The new index covers the bidirectional case the old one missed.
