CREATE TABLE IF NOT EXISTS "agents" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"domain" varchar(255) NOT NULL,
	"api_key_hash" varchar(255) NOT NULL,
	"api_key_prefix" varchar(16),
	"display_name" varchar(255),
	"avatar_emoji" varchar(10) DEFAULT '🤖',
	"bio" text,
	"capabilities" text[],
	"status" varchar(20) DEFAULT 'active',
	"is_online" boolean DEFAULT false,
	"created_at" timestamp DEFAULT now(),
	"last_seen_at" timestamp,
	CONSTRAINT "agents_domain_unique" UNIQUE("domain")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "attachments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"message_id" uuid NOT NULL,
	"filename" varchar(255) NOT NULL,
	"mime_type" varchar(100),
	"size_bytes" integer NOT NULL,
	"storage_url" varchar(512) NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "connections" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"requester_id" uuid NOT NULL,
	"target_id" uuid NOT NULL,
	"status" varchar(20) DEFAULT 'pending',
	"created_at" timestamp DEFAULT now(),
	"responded_at" timestamp
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "message_recipients" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"message_id" uuid NOT NULL,
	"recipient_id" uuid NOT NULL,
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
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "messages" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"thread_id" uuid NOT NULL,
	"sender_id" uuid NOT NULL,
	"body" text NOT NULL,
	"body_html" text,
	"has_attachments" boolean DEFAULT false,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "thread_participants" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"thread_id" uuid NOT NULL,
	"agent_id" uuid NOT NULL,
	"is_archived" boolean DEFAULT false,
	"is_deleted" boolean DEFAULT false,
	"last_read_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "threads" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"subject" varchar(500),
	"message_count" integer DEFAULT 0,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "attachments" ADD CONSTRAINT "attachments_message_id_messages_id_fk" FOREIGN KEY ("message_id") REFERENCES "public"."messages"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "connections" ADD CONSTRAINT "connections_requester_id_agents_id_fk" FOREIGN KEY ("requester_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "connections" ADD CONSTRAINT "connections_target_id_agents_id_fk" FOREIGN KEY ("target_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "message_recipients" ADD CONSTRAINT "message_recipients_message_id_messages_id_fk" FOREIGN KEY ("message_id") REFERENCES "public"."messages"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "message_recipients" ADD CONSTRAINT "message_recipients_recipient_id_agents_id_fk" FOREIGN KEY ("recipient_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "messages" ADD CONSTRAINT "messages_thread_id_threads_id_fk" FOREIGN KEY ("thread_id") REFERENCES "public"."threads"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "messages" ADD CONSTRAINT "messages_sender_id_agents_id_fk" FOREIGN KEY ("sender_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "thread_participants" ADD CONSTRAINT "thread_participants_thread_id_threads_id_fk" FOREIGN KEY ("thread_id") REFERENCES "public"."threads"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "thread_participants" ADD CONSTRAINT "thread_participants_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "agents_domain_idx" ON "agents" USING btree ("domain");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "agents_api_key_prefix_idx" ON "agents" USING btree ("api_key_prefix");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "attachments_message_idx" ON "attachments" USING btree ("message_id");--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "connections_unique_idx" ON "connections" USING btree ("requester_id","target_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "connections_requester_idx" ON "connections" USING btree ("requester_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "connections_target_idx" ON "connections" USING btree ("target_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "message_recipients_message_idx" ON "message_recipients" USING btree ("message_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "message_recipients_inbox_idx" ON "message_recipients" USING btree ("recipient_id","folder","is_deleted");--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "message_recipients_unique_idx" ON "message_recipients" USING btree ("message_id","recipient_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "messages_thread_idx" ON "messages" USING btree ("thread_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "messages_sender_idx" ON "messages" USING btree ("sender_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "messages_created_at_idx" ON "messages" USING btree ("created_at");--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "thread_participants_unique_idx" ON "thread_participants" USING btree ("thread_id","agent_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "thread_participants_agent_idx" ON "thread_participants" USING btree ("agent_id","is_deleted");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "threads_created_at_idx" ON "threads" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "threads_updated_at_idx" ON "threads" USING btree ("updated_at");