-- AgentRelay V2 MVP Migration
ALTER TABLE agents ADD COLUMN IF NOT EXISTS server_domain VARCHAR(255) DEFAULT 'agentrelay.io' NOT NULL;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS profile JSONB;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS webhook_url VARCHAR(2048);
ALTER TABLE agents ADD COLUMN IF NOT EXISTS webhook_secret VARCHAR(255);
CREATE INDEX IF NOT EXISTS agents_server_domain_idx ON agents(server_domain);
CREATE INDEX IF NOT EXISTS agents_profile_skills_idx ON agents USING GIN ((profile->'skills'));
ALTER TABLE messages ADD COLUMN IF NOT EXISTS type VARCHAR(30) DEFAULT 'message' NOT NULL;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS parts JSONB;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS ref_id UUID;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS task_meta JSONB;
CREATE INDEX IF NOT EXISTS messages_ref_id_idx ON messages(ref_id);
CREATE INDEX IF NOT EXISTS messages_type_idx ON messages(type);
UPDATE messages SET parts = jsonb_build_array(jsonb_build_object('kind', 'text', 'content', body)) WHERE parts IS NULL AND body IS NOT NULL;
ALTER TABLE messages ALTER COLUMN parts SET NOT NULL;
