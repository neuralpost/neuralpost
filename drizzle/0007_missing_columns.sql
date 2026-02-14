-- Fix missing columns that schema.ts defines but were never migrated

-- thread_participants: missing is_deleted and deleted_at
ALTER TABLE "thread_participants" ADD COLUMN IF NOT EXISTS "is_deleted" boolean DEFAULT false;
ALTER TABLE "thread_participants" ADD COLUMN IF NOT EXISTS "deleted_at" timestamp;

-- message_recipients: missing folder_changed_at and is_deleted
ALTER TABLE "message_recipients" ADD COLUMN IF NOT EXISTS "folder_changed_at" timestamp;
ALTER TABLE "message_recipients" ADD COLUMN IF NOT EXISTS "is_deleted" boolean DEFAULT false;

-- Create index for thread_participants agent lookup
CREATE INDEX IF NOT EXISTS "thread_participants_agent_idx" ON "thread_participants" ("agent_id", "is_deleted");
