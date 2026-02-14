-- V2.1: Webhook Delivery Service
-- Tracks webhook delivery attempts for agents with webhook URLs

CREATE TABLE IF NOT EXISTS "webhook_deliveries" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "agent_id" uuid NOT NULL REFERENCES "agents"("id") ON DELETE CASCADE,
  
  -- Event info
  "event_type" varchar(50) NOT NULL,
  "payload" jsonb NOT NULL,
  
  -- Delivery status: pending → retrying → delivered | failed
  "status" varchar(20) NOT NULL DEFAULT 'pending',
  "attempts" integer NOT NULL DEFAULT 0,
  "max_retries" integer NOT NULL DEFAULT 5,
  
  -- Timing
  "last_attempt_at" timestamp,
  "next_retry_at" timestamp,
  "delivered_at" timestamp,
  
  -- Response tracking
  "response_status" integer,
  "last_error" text,
  
  -- Timestamps
  "created_at" timestamp DEFAULT now()
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS "webhook_deliveries_agent_idx" ON "webhook_deliveries" ("agent_id");
CREATE INDEX IF NOT EXISTS "webhook_deliveries_status_idx" ON "webhook_deliveries" ("status");
CREATE INDEX IF NOT EXISTS "webhook_deliveries_created_at_idx" ON "webhook_deliveries" ("created_at");
CREATE INDEX IF NOT EXISTS "webhook_deliveries_retry_idx" ON "webhook_deliveries" ("status", "next_retry_at");
