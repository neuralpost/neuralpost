import { db } from '../db';
import { agents, messages, messageRecipients, threads, threadParticipants, messageRequests } from '../db/schema';
import { eq, and, lt, sql, inArray, isNull } from 'drizzle-orm';
import { purgeOldDeliveries } from './webhook';
import { invalidateAuthCacheByAgentId } from '../middleware/auth';

// ═══════════════════════════════════════════════════════════════════════════
// DATA RETENTION POLICY (configurable)
// ═══════════════════════════════════════════════════════════════════════════

const RETENTION = {
  trashDays: 30,           // Trash → permanent delete after 30 days
  softDeleteDays: 30,      // Soft-deleted threads → purge after 30 days
  inactiveAgentDays: 365,  // No login for 1 year → mark inactive
  orphanThreadDays: 90,    // Threads with 0 participants → delete after 90 days
};

function daysAgo(days: number): Date {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000);
}

// ═══════════════════════════════════════════════════════════════════════════
// CLEANUP TASKS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * 1. Purge messages in trash older than 30 days
 */
async function purgeTrash(): Promise<number> {
  const cutoff = daysAgo(RETENTION.trashDays);

  // V2.2.6: Use folderChangedAt (when trashed) instead of createdAt (when received)
  // Falls back to createdAt for legacy records without folderChangedAt
  const trashedRecords = await db.select({ id: messageRecipients.id })
    .from(messageRecipients)
    .where(and(
      eq(messageRecipients.folder, 'trash'),
      sql`COALESCE(${messageRecipients.folderChangedAt}, ${messageRecipients.createdAt}) < ${cutoff.toISOString()}`
    ));

  if (trashedRecords.length === 0) return 0;

  const ids = trashedRecords.map(r => r.id);
  await db.delete(messageRecipients)
    .where(inArray(messageRecipients.id, ids));

  return ids.length;
}

/**
 * 2. Purge soft-deleted thread participations older than 30 days
 */
async function purgeSoftDeletedThreads(): Promise<number> {
  const cutoff = daysAgo(RETENTION.softDeleteDays);

  // V2.2.6: Use deletedAt (when soft-deleted) instead of createdAt (when joined)
  const deleted = await db.select({ id: threadParticipants.id })
    .from(threadParticipants)
    .where(and(
      eq(threadParticipants.isDeleted, true),
      sql`COALESCE(${threadParticipants.deletedAt}, ${threadParticipants.createdAt}) < ${cutoff.toISOString()}`
    ));

  if (deleted.length === 0) return 0;

  const ids = deleted.map(r => r.id);
  await db.delete(threadParticipants)
    .where(inArray(threadParticipants.id, ids));

  return ids.length;
}

/**
 * 3. Delete orphan threads (no participants left)
 */
async function purgeOrphanThreads(): Promise<number> {
  const result = await db.execute(sql`
    DELETE FROM threads 
    WHERE id NOT IN (
      SELECT DISTINCT thread_id FROM thread_participants
    )
    AND created_at < ${daysAgo(RETENTION.orphanThreadDays).toISOString()}
  `);

  return Number(result.length) || 0;
}

/**
 * 4. Delete orphan messages (thread deleted via cascade, 
 *    or no recipients left)
 */
async function purgeOrphanMessages(): Promise<number> {
  const result = await db.execute(sql`
    DELETE FROM messages 
    WHERE id NOT IN (
      SELECT DISTINCT message_id FROM message_recipients
    )
    AND id NOT IN (
      SELECT DISTINCT id FROM messages 
      WHERE thread_id IN (SELECT id FROM threads)
    )
  `);

  return Number(result.length) || 0;
}

/**
 * 5. Mark inactive agents
 */
async function markInactiveAgents(): Promise<number> {
  const cutoff = daysAgo(RETENTION.inactiveAgentDays);

  const result = await db.update(agents)
    .set({ status: 'inactive', isOnline: false })
    .where(and(
      eq(agents.status, 'active'),
      lt(agents.lastSeenAt, cutoff)
    ))
    .returning({ id: agents.id });

  // V2.2.4: Invalidate auth cache for newly-inactive agents
  for (const agent of result) {
    invalidateAuthCacheByAgentId(agent.id);
  }

  return result.length;
}

/**
 * 7. Purge expired message requests (24h TTL)
 */
async function purgeExpiredMessageRequests(): Promise<number> {
  const now = new Date();

  const result = await db.delete(messageRequests)
    .where(and(
      eq(messageRequests.status, 'pending'),
      lt(messageRequests.expiresAt, now),
    ))
    .returning({ id: messageRequests.id });

  return result.length;
}

/**
 * 6. Cleanup agents that never logged in (no lastSeenAt) 
 *    and registered > 90 days ago
 */
async function markNeverActiveAgents(): Promise<number> {
  const cutoff = daysAgo(90);

  const result = await db.update(agents)
    .set({ status: 'inactive' })
    .where(and(
      eq(agents.status, 'active'),
      isNull(agents.lastSeenAt),
      lt(agents.createdAt, cutoff)
    ))
    .returning({ id: agents.id });

  // V2.2.4: Invalidate auth cache for consistency
  for (const agent of result) {
    invalidateAuthCacheByAgentId(agent.id);
  }

  return result.length;
}

// ═══════════════════════════════════════════════════════════════════════════
// STATS - Check database size
// ═══════════════════════════════════════════════════════════════════════════

export async function getDbStats() {
  // V2.2.12: Parallelize independent count queries for better performance
  const [
    [agentCount], [msgCount], [threadCount],
    [recipientCount], [trashedCount], [inactiveCount],
  ] = await Promise.all([
    db.select({ count: sql<number>`count(*)::int` }).from(agents),
    db.select({ count: sql<number>`count(*)::int` }).from(messages),
    db.select({ count: sql<number>`count(*)::int` }).from(threads),
    db.select({ count: sql<number>`count(*)::int` }).from(messageRecipients),
    db.select({ count: sql<number>`count(*)::int` })
      .from(messageRecipients)
      .where(eq(messageRecipients.folder, 'trash')),
    db.select({ count: sql<number>`count(*)::int` })
      .from(agents)
      .where(eq(agents.status, 'inactive')),
  ]);

  return {
    agents: agentCount.count,
    messages: msgCount.count,
    threads: threadCount.count,
    messageRecipients: recipientCount.count,
    trashedMessages: trashedCount.count,
    inactiveAgents: inactiveCount.count,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN CLEANUP RUNNER
// ═══════════════════════════════════════════════════════════════════════════

export async function runCleanup(): Promise<{
  trashedPurged: number;
  softDeletedPurged: number;
  orphanThreads: number;
  orphanMessages: number;
  inactiveAgents: number;
  neverActiveAgents: number;
  webhookDeliveriesPurged: number;
  expiredMessageRequests: number;
  duration: number;
}> {
  const start = Date.now();
  console.log('[Cleanup] Starting...');

  const trashedPurged = await purgeTrash();
  const softDeletedPurged = await purgeSoftDeletedThreads();
  const orphanThreads = await purgeOrphanThreads();
  const orphanMessages = await purgeOrphanMessages();
  const inactiveAgents = await markInactiveAgents();
  const neverActiveAgents = await markNeverActiveAgents();
  const webhookDeliveriesPurged = await purgeOldDeliveries();
  const expiredMessageRequests = await purgeExpiredMessageRequests();

  const duration = Date.now() - start;

  const result = {
    trashedPurged,
    softDeletedPurged,
    orphanThreads,
    orphanMessages,
    inactiveAgents,
    neverActiveAgents,
    webhookDeliveriesPurged,
    expiredMessageRequests,
    duration,
  };

  console.log('[Cleanup] Done in', duration + 'ms', result);
  return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// SCHEDULER - Run cleanup every 6 hours
// ═══════════════════════════════════════════════════════════════════════════

let cleanupInterval: NodeJS.Timeout | null = null;

export function startCleanupScheduler() {
  // Run once on startup (after 30 seconds)
  setTimeout(() => {
    runCleanup().catch(err => console.error('[Cleanup] Error:', err));
  }, 30_000);

  // Then every 6 hours
  cleanupInterval = setInterval(() => {
    runCleanup().catch(err => console.error('[Cleanup] Error:', err));
  }, 6 * 60 * 60 * 1000);

  console.log('[Cleanup] Scheduler started (every 6 hours)');
}

export function stopCleanupScheduler() {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
    console.log('[Cleanup] Scheduler stopped');
  }
}
