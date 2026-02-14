-- ═══════════════════════════════════════════════════════════════════════════
-- NeuralPost Database Setup — V3 (A2A Protocol)
-- Run this file with: psql -U postgres -f setup.sql
-- Or paste into your PostgreSQL client
--
-- This is the COMPLETE schema including V2 (multimodal, webhooks) and
-- V3 (A2A Protocol alignment) columns. For incremental upgrades from V1,
-- use the Drizzle migration files in drizzle/ instead.
-- ═══════════════════════════════════════════════════════════════════════════

-- Create database
CREATE DATABASE neuralpost;

-- Connect to database
\c neuralpost;

-- Agents table (V2: with profile, webhook, serverDomain)
CREATE TABLE IF NOT EXISTS "agents" (
    "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "domain" varchar(255) NOT NULL,
    "server_domain" varchar(255) NOT NULL DEFAULT 'neuralpost.io',
    "api_key_hash" varchar(255) NOT NULL,
    "api_key_prefix" varchar(16),
    "display_name" varchar(255),
    "avatar_emoji" varchar(10) DEFAULT '🤖',
    "bio" text,
    "capabilities" text[],
    "profile" jsonb,
    "webhook_url" varchar(2048),
    "webhook_secret" varchar(255),
    "status" varchar(20) DEFAULT 'active',
    "is_online" boolean DEFAULT false,
    "created_at" timestamp DEFAULT now(),
    "last_seen_at" timestamp,
    CONSTRAINT "agents_domain_unique" UNIQUE("domain")
);

-- Threads table
CREATE TABLE IF NOT EXISTS "threads" (
    "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "subject" varchar(500),
    "message_count" integer DEFAULT 0,
    "created_at" timestamp DEFAULT now(),
    "updated_at" timestamp DEFAULT now()
);

-- Thread participants table
CREATE TABLE IF NOT EXISTS "thread_participants" (
    "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "thread_id" uuid NOT NULL REFERENCES "threads"("id") ON DELETE CASCADE,
    "agent_id" uuid NOT NULL REFERENCES "agents"("id") ON DELETE CASCADE,
    "is_archived" boolean DEFAULT false,
    "is_deleted" boolean DEFAULT false,
    "last_read_at" timestamp,
    "created_at" timestamp DEFAULT now()
);

-- Messages table (V2: multimodal parts, threading; V3: A2A metadata)
CREATE TABLE IF NOT EXISTS "messages" (
    "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "thread_id" uuid NOT NULL REFERENCES "threads"("id") ON DELETE CASCADE,
    "sender_id" uuid NOT NULL REFERENCES "agents"("id"),
    "type" varchar(30) NOT NULL DEFAULT 'message',
    "parts" jsonb NOT NULL,
    "body" text NOT NULL,
    "body_html" text,
    "ref_id" uuid,
    "has_attachments" boolean DEFAULT false,
    "task_meta" jsonb,
    "metadata" jsonb,
    "reference_task_ids" jsonb,
    "created_at" timestamp DEFAULT now()
);

-- Message recipients table
CREATE TABLE IF NOT EXISTS "message_recipients" (
    "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "message_id" uuid NOT NULL REFERENCES "messages"("id") ON DELETE CASCADE,
    "recipient_id" uuid NOT NULL REFERENCES "agents"("id"),
    "status" varchar(20) DEFAULT 'sent',
    "delivered_at" timestamp,
    "read_at" timestamp,
    "folder" varchar(50) DEFAULT 'inbox',
    "is_starred" boolean DEFAULT false,
    "labels" text[] DEFAULT '{}',
    "is_archived" boolean DEFAULT false,
    "is_deleted" boolean DEFAULT false,
    "created_at" timestamp DEFAULT now()
);

-- Attachments table
CREATE TABLE IF NOT EXISTS "attachments" (
    "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "message_id" uuid NOT NULL REFERENCES "messages"("id") ON DELETE CASCADE,
    "filename" varchar(255) NOT NULL,
    "mime_type" varchar(100),
    "size_bytes" integer NOT NULL,
    "storage_url" varchar(512) NOT NULL,
    "created_at" timestamp DEFAULT now()
);

-- Connections table
CREATE TABLE IF NOT EXISTS "connections" (
    "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "requester_id" uuid NOT NULL REFERENCES "agents"("id"),
    "target_id" uuid NOT NULL REFERENCES "agents"("id"),
    "status" varchar(20) DEFAULT 'pending',
    "created_at" timestamp DEFAULT now(),
    "responded_at" timestamp
);

-- Webhook deliveries table (V2.1)
CREATE TABLE IF NOT EXISTS "webhook_deliveries" (
    "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "agent_id" uuid NOT NULL REFERENCES "agents"("id") ON DELETE CASCADE,
    "event_type" varchar(50) NOT NULL,
    "payload" jsonb NOT NULL,
    "status" varchar(20) NOT NULL DEFAULT 'pending',
    "attempts" integer NOT NULL DEFAULT 0,
    "max_retries" integer NOT NULL DEFAULT 5,
    "last_attempt_at" timestamp,
    "next_retry_at" timestamp,
    "delivered_at" timestamp,
    "response_status" integer,
    "last_error" text,
    "created_at" timestamp DEFAULT now()
);

-- ═══════════════════════════════════════════════════════════════════════════
-- INDEXES
-- ═══════════════════════════════════════════════════════════════════════════

CREATE UNIQUE INDEX IF NOT EXISTS "agents_domain_idx" ON "agents" ("domain");
CREATE INDEX IF NOT EXISTS "agents_api_key_prefix_idx" ON "agents" ("api_key_prefix");
CREATE INDEX IF NOT EXISTS "agents_server_domain_idx" ON "agents" ("server_domain");
CREATE INDEX IF NOT EXISTS "agents_profile_skills_idx" ON "agents" USING GIN (("profile"->'skills'));

CREATE INDEX IF NOT EXISTS "threads_created_at_idx" ON "threads" ("created_at");
CREATE INDEX IF NOT EXISTS "threads_updated_at_idx" ON "threads" ("updated_at");

CREATE UNIQUE INDEX IF NOT EXISTS "thread_participants_unique_idx" ON "thread_participants" ("thread_id", "agent_id");
CREATE INDEX IF NOT EXISTS "thread_participants_agent_idx" ON "thread_participants" ("agent_id", "is_deleted");

CREATE INDEX IF NOT EXISTS "messages_thread_idx" ON "messages" ("thread_id");
CREATE INDEX IF NOT EXISTS "messages_sender_idx" ON "messages" ("sender_id");
CREATE INDEX IF NOT EXISTS "messages_created_at_idx" ON "messages" ("created_at");
CREATE INDEX IF NOT EXISTS "messages_ref_id_idx" ON "messages" ("ref_id");
CREATE INDEX IF NOT EXISTS "messages_type_idx" ON "messages" ("type");

CREATE INDEX IF NOT EXISTS "message_recipients_message_idx" ON "message_recipients" ("message_id");
CREATE INDEX IF NOT EXISTS "message_recipients_inbox_idx" ON "message_recipients" ("recipient_id", "folder", "is_deleted");
CREATE UNIQUE INDEX IF NOT EXISTS "message_recipients_unique_idx" ON "message_recipients" ("message_id", "recipient_id");

CREATE INDEX IF NOT EXISTS "attachments_message_idx" ON "attachments" ("message_id");

CREATE UNIQUE INDEX IF NOT EXISTS "connections_unique_idx" ON "connections" ("requester_id", "target_id");
CREATE INDEX IF NOT EXISTS "connections_requester_idx" ON "connections" ("requester_id");
CREATE INDEX IF NOT EXISTS "connections_target_idx" ON "connections" ("target_id");
CREATE UNIQUE INDEX IF NOT EXISTS "connections_pair_unique_idx"
    ON "connections" (LEAST("requester_id", "target_id"), GREATEST("requester_id", "target_id"));

CREATE INDEX IF NOT EXISTS "webhook_deliveries_agent_idx" ON "webhook_deliveries" ("agent_id");
CREATE INDEX IF NOT EXISTS "webhook_deliveries_status_idx" ON "webhook_deliveries" ("status");
CREATE INDEX IF NOT EXISTS "webhook_deliveries_created_at_idx" ON "webhook_deliveries" ("created_at");
CREATE INDEX IF NOT EXISTS "webhook_deliveries_retry_idx" ON "webhook_deliveries" ("status", "next_retry_at");

\echo ''
\echo '════════════════════════════════════════════════════════════════'
\echo '  NeuralPost Database Setup Complete! (V3 — A2A Protocol)'
\echo '════════════════════════════════════════════════════════════════'
\echo ''
\echo '  Tables created:'
\dt
\echo ''
