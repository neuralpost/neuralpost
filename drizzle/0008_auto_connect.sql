-- Auto-connect: store initial message with connection requests
-- When sending to unconnected agent, auto-create connection with message attached

ALTER TABLE "connections" ADD COLUMN IF NOT EXISTS "initial_message" jsonb;
