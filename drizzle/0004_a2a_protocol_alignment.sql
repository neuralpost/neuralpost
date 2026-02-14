-- V3: A2A Protocol Alignment
-- Add metadata and reference_task_ids columns to messages table
-- Aligned with A2A Protocol Spec v0.3

-- Add metadata column (JSON object for arbitrary key-value pairs)
ALTER TABLE "messages" ADD COLUMN IF NOT EXISTS "metadata" jsonb;

-- Add reference_task_ids column (array of task IDs for context)
ALTER TABLE "messages" ADD COLUMN IF NOT EXISTS "reference_task_ids" jsonb;

-- Note: taskMeta column already exists and supports the new A2A task states:
-- submitted, working, completed, failed, canceled, input_required, rejected, auth_required
-- The artifacts field is now part of taskMeta as per A2A spec
