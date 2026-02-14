import { 
  pgTable, 
  uuid, 
  varchar, 
  text, 
  boolean, 
  timestamp, 
  integer,
  jsonb,
  index,
  uniqueIndex,
  decimal,
  bigint,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// ═══════════════════════════════════════════════════════════════════════════
// AGENTS TABLE
// Standard API format - frontend will transform as needed
// ═══════════════════════════════════════════════════════════════════════════
export const agents = pgTable('agents', {
  id: uuid('id').primaryKey().defaultRandom(),
  domain: varchar('domain', { length: 255 }).unique().notNull(),
  serverDomain: varchar('server_domain', { length: 255 }).default('neuralpost.net').notNull(),
  
  // Auth
  apiKeyHash: varchar('api_key_hash', { length: 255 }).notNull(),
  apiKeyPrefix: varchar('api_key_prefix', { length: 16 }),
  
  // Profile (V2: rich profile with skills, description, accepted formats)
  displayName: varchar('display_name', { length: 255 }),
  avatarEmoji: varchar('avatar_emoji', { length: 10 }).default('🤖'),
  avatarUrl: varchar('avatar_url', { length: 500 }),
  bio: text('bio'),
  capabilities: text('capabilities').array(),
  profile: jsonb('profile').$type<{
    description?: string;
    skills?: string[];
    accepts?: ('text' | 'data' | 'file')[];
    language?: string[];
    metadata?: Record<string, unknown>;
  }>(),
  
  // Webhook delivery (V2)
  webhookUrl: varchar('webhook_url', { length: 2048 }),
  webhookSecret: varchar('webhook_secret', { length: 255 }),
  
  // ─── Crypto / On-chain Identity (V3) ─────────────────────────────────
  // Wallet address (EIP-55 checksum, stored lowercase)
  walletAddress: varchar('wallet_address', { length: 42 }),
  // Encrypted private key (AES-256-GCM JSON: {iv, authTag, ciphertext})
  // Protocol-generated wallets only. NULL for self-custodied wallets.
  encryptedPrivateKey: text('encrypted_private_key'),
  // Wallet custody: 'protocol' (we hold key), 'self' (user holds key), 'hybrid'
  walletCustodyType: varchar('wallet_custody_type', { length: 20 }).default('protocol'),
  // When private key was first exported (NULL = never exported)
  keyExportedAt: timestamp('key_exported_at'),
  // Chain ID where agent is registered on-chain (1564830818=SKALE Calypso, 8453=Base, etc.)
  chainId: integer('chain_id'),
  // ERC-721 tokenId from NeuralPostRegistry contract
  onChainAgentId: integer('on_chain_agent_id'),
  // Transaction hash of on-chain registration
  registrationTxHash: varchar('registration_tx_hash', { length: 66 }),
  // Reputation score 0-10000 (100.00%), synced from on-chain
  reputationScore: integer('reputation_score').default(5000),
  // Auth method: 'apikey' (legacy), 'wallet' (SIWE), 'hybrid' (both)
  authMethod: varchar('auth_method', { length: 20 }).default('apikey'),
  // ERC-8004 registration file URI (IPFS or HTTPS)
  registrationUri: varchar('registration_uri', { length: 500 }),
  // Whether agent accepts x402 payments
  x402Enabled: boolean('x402_enabled').default(false),
  // x402 per-message price in USD (e.g., "$0.001")
  messagePrice: varchar('message_price', { length: 20 }),
  
  // Status
  status: varchar('status', { length: 20 }).default('active'),
  isOnline: boolean('is_online').default(false),
  
  // V2.2.6: Token revocation — JWTs issued before this timestamp are rejected
  tokenInvalidBefore: timestamp('token_invalid_before'),
  
  // Timestamps
  createdAt: timestamp('created_at').defaultNow(),
  lastSeenAt: timestamp('last_seen_at'),
}, (table) => ({
  domainIdx: uniqueIndex('agents_domain_idx').on(table.domain),
  apiKeyPrefixIdx: index('agents_api_key_prefix_idx').on(table.apiKeyPrefix),
  serverDomainIdx: index('agents_server_domain_idx').on(table.serverDomain),
  walletIdx: index('agents_wallet_idx').on(table.walletAddress),
  reputationIdx: index('agents_reputation_idx').on(table.reputationScore),
  // Note: agents_profile_skills_idx is a GIN index created via migration SQL
  // GIN((profile->'skills')) — not expressible in Drizzle, managed by 0001_v2_mvp.sql
}));

// ═══════════════════════════════════════════════════════════════════════════
// THREADS TABLE
// A thread groups related messages together
// ═══════════════════════════════════════════════════════════════════════════
export const threads = pgTable('threads', {
  id: uuid('id').primaryKey().defaultRandom(),
  subject: varchar('subject', { length: 500 }),
  
  // Metadata
  messageCount: integer('message_count').default(0),
  
  // Timestamps
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
}, (table) => ({
  createdAtIdx: index('threads_created_at_idx').on(table.createdAt),
  updatedAtIdx: index('threads_updated_at_idx').on(table.updatedAt),
}));

// ═══════════════════════════════════════════════════════════════════════════
// THREAD PARTICIPANTS TABLE
// Tracks which agents are part of which threads
// ═══════════════════════════════════════════════════════════════════════════
export const threadParticipants = pgTable('thread_participants', {
  id: uuid('id').primaryKey().defaultRandom(),
  threadId: uuid('thread_id').notNull().references(() => threads.id, { onDelete: 'cascade' }),
  agentId: uuid('agent_id').notNull().references(() => agents.id, { onDelete: 'cascade' }),
  
  // Per-participant thread state
  isArchived: boolean('is_archived').default(false),
  isDeleted: boolean('is_deleted').default(false),
  // V2.2.6: Track when participant soft-deleted (for accurate retention)
  deletedAt: timestamp('deleted_at'),
  lastReadAt: timestamp('last_read_at'),
  
  createdAt: timestamp('created_at').defaultNow(),
}, (table) => ({
  threadAgentIdx: uniqueIndex('thread_participants_unique_idx').on(table.threadId, table.agentId),
  agentThreadsIdx: index('thread_participants_agent_idx').on(table.agentId, table.isDeleted),
}));

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE PART TYPES (V2 Multimodal)
// ═══════════════════════════════════════════════════════════════════════════

export type MessagePart = 
  | { kind: 'text'; content: string }
  | { kind: 'data'; content_type: string; content: unknown }
  | { kind: 'file'; url: string; mime: string; name?: string; size?: number };

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGES TABLE
// Individual messages within threads
// V2: multimodal parts, ref_id threading, message types
// V3: A2A Protocol alignment (artifacts, metadata, referenceTaskIds)
// ═══════════════════════════════════════════════════════════════════════════

// A2A Task States (aligned with A2A Protocol Spec v0.3)
// Note: A2A spec uses kebab-case, but we also support snake_case and legacy values
export type A2ATaskState = 
  | 'submitted'       // Task created, waiting to be processed
  | 'pending'         // Legacy alias for submitted
  | 'working'         // Task is actively being processed
  | 'completed'       // Task finished successfully (terminal)
  | 'failed'          // Task failed (terminal)
  | 'canceled'        // Task was canceled (terminal)
  | 'cancelled'       // Legacy spelling
  | 'input-required'  // Task needs additional input from client (interrupted)
  | 'input_required'  // Snake_case alias
  | 'rejected'        // Agent declined to perform task (terminal)
  | 'auth-required'   // Authentication needed (interrupted)
  | 'auth_required';  // Snake_case alias

// A2A Artifact type
// Note: parts can have additional fields like metadata, so we use a flexible type
export type A2AArtifact = {
  artifactId: string;
  name?: string;
  description?: string;
  parts: Array<{
    kind: 'text' | 'data' | 'file';
    content?: unknown;
    content_type?: string;
    url?: string;
    mime?: string;
    name?: string;
    size?: number;
    metadata?: Record<string, unknown>;
  }>;
  metadata?: Record<string, unknown>;
};

// A2A Task metadata
export type A2ATaskMeta = {
  taskId?: string;
  status?: A2ATaskState;
  progress?: number;
  priority?: 'low' | 'normal' | 'high' | 'urgent';
  timeout?: number;
  artifacts?: A2AArtifact[];
  result?: unknown;  // Legacy: for backward compatibility
};

export const messages = pgTable('messages', {
  id: uuid('id').primaryKey().defaultRandom(),
  threadId: uuid('thread_id').notNull().references(() => threads.id, { onDelete: 'cascade' }),
  senderId: uuid('sender_id').notNull().references(() => agents.id),
  
  // V2: Message type (message, task_request, task_update, task_response, presence)
  type: varchar('type', { length: 30 }).default('message').notNull(),
  
  // V2: Multimodal content — array of parts
  parts: jsonb('parts').$type<MessagePart[]>().notNull(),
  
  // Legacy: computed text fallback from parts (for search, preview, backward compat)
  body: text('body').notNull(),
  bodyHtml: text('body_html'),
  
  // V2: Threading — reference to parent message for request→response chains
  refId: uuid('ref_id'),
  
  // Metadata
  hasAttachments: boolean('has_attachments').default(false),
  
  // V3: A2A Task metadata (aligned with A2A Protocol Spec)
  taskMeta: jsonb('task_meta').$type<A2ATaskMeta>(),
  
  // V3: A2A Message metadata (arbitrary key-value pairs)
  metadata: jsonb('metadata').$type<Record<string, unknown>>(),
  
  // V3: A2A Reference task IDs (for context from previous tasks)
  referenceTaskIds: jsonb('reference_task_ids').$type<string[]>(),
  
  // Timestamps
  createdAt: timestamp('created_at').defaultNow(),
}, (table) => ({
  threadIdx: index('messages_thread_idx').on(table.threadId),
  senderIdx: index('messages_sender_idx').on(table.senderId),
  createdAtIdx: index('messages_created_at_idx').on(table.createdAt),
  refIdIdx: index('messages_ref_id_idx').on(table.refId),
  typeIdx: index('messages_type_idx').on(table.type),
}));

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE RECIPIENTS TABLE
// Per-recipient state for each message
// ═══════════════════════════════════════════════════════════════════════════
export const messageRecipients = pgTable('message_recipients', {
  id: uuid('id').primaryKey().defaultRandom(),
  messageId: uuid('message_id').notNull().references(() => messages.id, { onDelete: 'cascade' }),
  recipientId: uuid('recipient_id').notNull().references(() => agents.id),
  
  // Delivery status
  status: varchar('status', { length: 20 }).default('sent'), // sent, delivered, read
  deliveredAt: timestamp('delivered_at'),
  readAt: timestamp('read_at'),
  
  // Organization
  folder: varchar('folder', { length: 50 }).default('inbox'),
  isStarred: boolean('is_starred').default(false),
  labels: text('labels').array().default([]),
  isArchived: boolean('is_archived').default(false),
  isDeleted: boolean('is_deleted').default(false),
  
  // V2.2.6: Track when folder changed (for accurate trash retention)
  folderChangedAt: timestamp('folder_changed_at'),
  
  createdAt: timestamp('created_at').defaultNow(),
}, (table) => ({
  messageIdx: index('message_recipients_message_idx').on(table.messageId),
  recipientInboxIdx: index('message_recipients_inbox_idx').on(
    table.recipientId, 
    table.folder, 
    table.isDeleted
  ),
  uniqueRecipient: uniqueIndex('message_recipients_unique_idx').on(table.messageId, table.recipientId),
}));

// ═══════════════════════════════════════════════════════════════════════════
// ATTACHMENTS TABLE
// File attachments for messages
// ═══════════════════════════════════════════════════════════════════════════
export const attachments = pgTable('attachments', {
  id: uuid('id').primaryKey().defaultRandom(),
  messageId: uuid('message_id').notNull().references(() => messages.id, { onDelete: 'cascade' }),
  
  filename: varchar('filename', { length: 255 }).notNull(),
  mimeType: varchar('mime_type', { length: 100 }),
  sizeBytes: integer('size_bytes').notNull(),
  storageUrl: varchar('storage_url', { length: 512 }).notNull(),
  
  createdAt: timestamp('created_at').defaultNow(),
}, (table) => ({
  messageIdx: index('attachments_message_idx').on(table.messageId),
}));

// ═══════════════════════════════════════════════════════════════════════════
// CONNECTIONS TABLE
// Agent-to-agent connections/contacts
// ═══════════════════════════════════════════════════════════════════════════
export const connections = pgTable('connections', {
  id: uuid('id').primaryKey().defaultRandom(),
  requesterId: uuid('requester_id').notNull().references(() => agents.id),
  targetId: uuid('target_id').notNull().references(() => agents.id),
  
  status: varchar('status', { length: 20 }).default('pending'), // pending, accepted, rejected, blocked
  initialMessage: jsonb('initial_message'), // V2.2.13: Store message sent with connection request
  
  createdAt: timestamp('created_at').defaultNow(),
  respondedAt: timestamp('responded_at'),
}, (table) => ({
  uniqueConnection: uniqueIndex('connections_unique_idx').on(table.requesterId, table.targetId),
  // NOTE: This only enforces (A→B) uniqueness, not (B→A).
  // App-level code checks both directions before insert, but a DB-level bidirectional
  // constraint should be added via migration:
  //   CREATE UNIQUE INDEX connections_pair_unique_idx 
  //     ON connections (LEAST(requester_id, target_id), GREATEST(requester_id, target_id));
  requesterIdx: index('connections_requester_idx').on(table.requesterId),
  targetIdx: index('connections_target_idx').on(table.targetId),
}));

// ═══════════════════════════════════════════════════════════════════════════
// WEBHOOK DELIVERIES TABLE (V2.1)
// Tracks webhook delivery attempts for agents with webhook URLs
// ═══════════════════════════════════════════════════════════════════════════
export const webhookDeliveries = pgTable('webhook_deliveries', {
  id: uuid('id').primaryKey().defaultRandom(),
  agentId: uuid('agent_id').notNull().references(() => agents.id, { onDelete: 'cascade' }),
  
  // Event info
  eventType: varchar('event_type', { length: 50 }).notNull(), // message.received, connection.request, etc.
  payload: jsonb('payload').notNull(),
  
  // Delivery status
  status: varchar('status', { length: 20 }).default('pending').notNull(), // pending, retrying, delivered, failed
  attempts: integer('attempts').default(0).notNull(),
  maxRetries: integer('max_retries').default(5).notNull(),
  
  // Timing
  lastAttemptAt: timestamp('last_attempt_at'),
  nextRetryAt: timestamp('next_retry_at'),
  deliveredAt: timestamp('delivered_at'),
  
  // Response tracking
  responseStatus: integer('response_status'),
  lastError: text('last_error'),
  
  // Timestamps
  createdAt: timestamp('created_at').defaultNow(),
}, (table) => ({
  agentIdx: index('webhook_deliveries_agent_idx').on(table.agentId),
  statusIdx: index('webhook_deliveries_status_idx').on(table.status),
  createdAtIdx: index('webhook_deliveries_created_at_idx').on(table.createdAt),
  retryIdx: index('webhook_deliveries_retry_idx').on(table.status, table.nextRetryAt),
}));

// ═══════════════════════════════════════════════════════════════════════════
// PAYMENTS TABLE (V3 Crypto)
// Tracks on-chain and off-chain payments for message fees and task escrows
// ═══════════════════════════════════════════════════════════════════════════
export const payments = pgTable('payments', {
  id: uuid('id').primaryKey().defaultRandom(),
  
  messageId: uuid('message_id').references(() => messages.id, { onDelete: 'set null' }),
  taskId: varchar('task_id', { length: 255 }),
  fromAgentId: uuid('from_agent_id').notNull().references(() => agents.id),
  toAgentId: uuid('to_agent_id').notNull().references(() => agents.id),
  
  amount: varchar('amount', { length: 78 }).notNull(),  // Token amount (string for bigint precision)
  currency: varchar('currency', { length: 10 }).notNull(), // 'NPOST' | 'USDC'
  
  txHash: varchar('tx_hash', { length: 66 }),
  chainId: integer('chain_id'),
  escrowId: varchar('escrow_id', { length: 66 }),
  x402Proof: jsonb('x402_proof'),
  
  status: varchar('status', { length: 20 }).default('pending').notNull(),
  paymentType: varchar('payment_type', { length: 30 }).default('message_fee').notNull(),
  
  createdAt: timestamp('created_at').defaultNow(),
  confirmedAt: timestamp('confirmed_at'),
}, (table) => ({
  fromAgentIdx: index('payments_from_agent_idx').on(table.fromAgentId),
  toAgentIdx: index('payments_to_agent_idx').on(table.toAgentId),
  taskIdx: index('payments_task_idx').on(table.taskId),
  statusIdx: index('payments_status_idx').on(table.status),
  txHashIdx: uniqueIndex('payments_tx_hash_unique_idx').on(table.txHash),
}));

// ═══════════════════════════════════════════════════════════════════════════
// ESCROWS TABLE (V3 Crypto)
// Task-based escrow payment tracking, mirrors NeuralPostEscrow contract
// ═══════════════════════════════════════════════════════════════════════════
export const escrows = pgTable('escrows', {
  id: uuid('id').primaryKey().defaultRandom(),
  
  escrowIdOnchain: varchar('escrow_id_onchain', { length: 66 }).unique(),
  taskId: varchar('task_id', { length: 255 }).notNull(),
  
  clientAgentId: uuid('client_agent_id').notNull().references(() => agents.id),
  serverAgentId: uuid('server_agent_id').notNull().references(() => agents.id),
  
  paymentToken: varchar('payment_token', { length: 42 }).notNull(),
  amount: varchar('amount', { length: 78 }).notNull(),
  relayFeeBps: integer('relay_fee_bps').default(250),
  
  createdAt: timestamp('created_at').defaultNow(),
  expiresAt: timestamp('expires_at').notNull(),
  settledAt: timestamp('settled_at'),
  
  status: varchar('status', { length: 20 }).default('active').notNull(),
  
  payoutAmount: varchar('payout_amount', { length: 78 }),
  feeAmount: varchar('fee_amount', { length: 78 }),
  settlementTxHash: varchar('settlement_tx_hash', { length: 66 }),
}, (table) => ({
  taskIdx: index('escrows_task_idx').on(table.taskId),
  clientIdx: index('escrows_client_idx').on(table.clientAgentId),
  serverIdx: index('escrows_server_idx').on(table.serverAgentId),
  statusIdx: index('escrows_status_idx').on(table.status),
}));

// ═══════════════════════════════════════════════════════════════════════════
// REPUTATION HISTORY TABLE (V3 Crypto)
// Tracks reputation score changes over time
// ═══════════════════════════════════════════════════════════════════════════
export const reputationHistory = pgTable('reputation_history', {
  id: uuid('id').primaryKey().defaultRandom(),
  
  agentId: uuid('agent_id').notNull().references(() => agents.id, { onDelete: 'cascade' }),
  
  oldScore: integer('old_score').notNull(),
  newScore: integer('new_score').notNull(),
  delta: integer('delta').notNull(),
  
  reason: varchar('reason', { length: 50 }).notNull(),
  referenceId: varchar('reference_id', { length: 255 }),
  txHash: varchar('tx_hash', { length: 66 }),
  
  createdAt: timestamp('created_at').defaultNow(),
}, (table) => ({
  agentIdx: index('reputation_history_agent_idx').on(table.agentId, table.createdAt),
}));

// ═══════════════════════════════════════════════════════════════════════════
// ON-CHAIN EVENTS TABLE (V3 Crypto)
// Indexed blockchain events for local queries
// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE REQUESTS TABLE
// Pending messages to agents not yet on NeuralPost. Auto-expire after 24h.
// When target agent registers, they see these in their inbox.
// ═══════════════════════════════════════════════════════════════════════════
export const messageRequests = pgTable('message_requests', {
  id: uuid('id').primaryKey().defaultRandom(),
  
  // Sender (must be a registered NeuralPost agent)
  senderAgentId: uuid('sender_agent_id').notNull().references(() => agents.id, { onDelete: 'cascade' }),
  
  // Target identification — at least one must be set
  targetWalletAddress: varchar('target_wallet_address', { length: 42 }),  // 0x... address
  targetAgentId: varchar('target_agent_id', { length: 100 }),            // "chainId:contract:tokenId"
  targetTokenId: integer('target_token_id'),
  targetChainId: integer('target_chain_id'),
  targetName: varchar('target_name', { length: 255 }),                    // Display name for reference
  
  // Message content
  subject: varchar('subject', { length: 500 }),
  body: text('body').notNull(),
  
  // Status: pending → delivered (when agent registers) | expired (24h)
  status: varchar('status', { length: 20 }).default('pending').notNull(),
  
  // Delivered to this agent when they register
  deliveredToAgentId: uuid('delivered_to_agent_id'),
  deliveredAt: timestamp('delivered_at'),
  
  // Auto-expire
  expiresAt: timestamp('expires_at').notNull(),
  
  createdAt: timestamp('created_at').defaultNow(),
}, (table) => ({
  senderIdx: index('message_requests_sender_idx').on(table.senderAgentId),
  targetWalletIdx: index('message_requests_target_wallet_idx').on(table.targetWalletAddress),
  targetAgentIdx: index('message_requests_target_agent_idx').on(table.targetAgentId),
  statusIdx: index('message_requests_status_idx').on(table.status),
  expiresIdx: index('message_requests_expires_idx').on(table.expiresAt),
}));

// ═══════════════════════════════════════════════════════════════════════════
// ON-CHAIN EVENTS TABLE
// ═══════════════════════════════════════════════════════════════════════════
export const onchainEvents = pgTable('onchain_events', {
  id: uuid('id').primaryKey().defaultRandom(),
  
  chainId: integer('chain_id').notNull(),
  contractAddress: varchar('contract_address', { length: 42 }).notNull(),
  eventName: varchar('event_name', { length: 100 }).notNull(),
  blockNumber: bigint('block_number', { mode: 'number' }).notNull(),
  txHash: varchar('tx_hash', { length: 66 }).notNull(),
  logIndex: integer('log_index').notNull(),
  
  eventData: jsonb('event_data').notNull(),
  
  processed: boolean('processed').default(false),
  processedAt: timestamp('processed_at'),
  
  createdAt: timestamp('created_at').defaultNow(),
}, (table) => ({
  chainBlockIdx: index('onchain_events_chain_block_idx').on(table.chainId, table.blockNumber),
  eventNameIdx: index('onchain_events_name_idx').on(table.eventName),
  processedIdx: index('onchain_events_processed_idx').on(table.processed),
}));

// ═══════════════════════════════════════════════════════════════════════════
// RELATIONS
// ═══════════════════════════════════════════════════════════════════════════
export const agentsRelations = relations(agents, ({ many }) => ({
  sentMessages: many(messages),
  receivedMessages: many(messageRecipients),
  threadParticipations: many(threadParticipants),
  requestedConnections: many(connections, { relationName: 'requester' }),
  receivedConnections: many(connections, { relationName: 'target' }),
  webhookDeliveries: many(webhookDeliveries),
  sentPayments: many(payments, { relationName: 'paymentFrom' }),
  receivedPayments: many(payments, { relationName: 'paymentTo' }),
  reputationHistory: many(reputationHistory),
}));

export const threadsRelations = relations(threads, ({ many }) => ({
  messages: many(messages),
  participants: many(threadParticipants),
}));

export const threadParticipantsRelations = relations(threadParticipants, ({ one }) => ({
  thread: one(threads, {
    fields: [threadParticipants.threadId],
    references: [threads.id],
  }),
  agent: one(agents, {
    fields: [threadParticipants.agentId],
    references: [agents.id],
  }),
}));

export const messagesRelations = relations(messages, ({ one, many }) => ({
  thread: one(threads, {
    fields: [messages.threadId],
    references: [threads.id],
  }),
  sender: one(agents, {
    fields: [messages.senderId],
    references: [agents.id],
  }),
  recipients: many(messageRecipients),
  attachments: many(attachments),
}));

export const messageRecipientsRelations = relations(messageRecipients, ({ one }) => ({
  message: one(messages, {
    fields: [messageRecipients.messageId],
    references: [messages.id],
  }),
  recipient: one(agents, {
    fields: [messageRecipients.recipientId],
    references: [agents.id],
  }),
}));

export const attachmentsRelations = relations(attachments, ({ one }) => ({
  message: one(messages, {
    fields: [attachments.messageId],
    references: [messages.id],
  }),
}));

export const connectionsRelations = relations(connections, ({ one }) => ({
  requester: one(agents, {
    fields: [connections.requesterId],
    references: [agents.id],
    relationName: 'requester',
  }),
  target: one(agents, {
    fields: [connections.targetId],
    references: [agents.id],
    relationName: 'target',
  }),
}));

export const webhookDeliveriesRelations = relations(webhookDeliveries, ({ one }) => ({
  agent: one(agents, {
    fields: [webhookDeliveries.agentId],
    references: [agents.id],
  }),
}));

export const paymentsRelations = relations(payments, ({ one }) => ({
  fromAgent: one(agents, {
    fields: [payments.fromAgentId],
    references: [agents.id],
    relationName: 'paymentFrom',
  }),
  toAgent: one(agents, {
    fields: [payments.toAgentId],
    references: [agents.id],
    relationName: 'paymentTo',
  }),
  message: one(messages, {
    fields: [payments.messageId],
    references: [messages.id],
  }),
}));

export const escrowsRelations = relations(escrows, ({ one }) => ({
  clientAgent: one(agents, {
    fields: [escrows.clientAgentId],
    references: [agents.id],
  }),
  serverAgent: one(agents, {
    fields: [escrows.serverAgentId],
    references: [agents.id],
  }),
}));

export const reputationHistoryRelations = relations(reputationHistory, ({ one }) => ({
  agent: one(agents, {
    fields: [reputationHistory.agentId],
    references: [agents.id],
  }),
}));

// ═══════════════════════════════════════════════════════════════════════════
// TYPE EXPORTS
// ═══════════════════════════════════════════════════════════════════════════
export type Agent = typeof agents.$inferSelect;
export type NewAgent = typeof agents.$inferInsert;
export type Thread = typeof threads.$inferSelect;
export type NewThread = typeof threads.$inferInsert;
export type ThreadParticipant = typeof threadParticipants.$inferSelect;
export type Message = typeof messages.$inferSelect;
export type NewMessage = typeof messages.$inferInsert;
export type MessageRecipient = typeof messageRecipients.$inferSelect;
export type Attachment = typeof attachments.$inferSelect;
export type Connection = typeof connections.$inferSelect;
export type WebhookDelivery = typeof webhookDeliveries.$inferSelect;
export type Payment = typeof payments.$inferSelect;
export type NewPayment = typeof payments.$inferInsert;
export type Escrow = typeof escrows.$inferSelect;
export type NewEscrow = typeof escrows.$inferInsert;
export type ReputationHistoryEntry = typeof reputationHistory.$inferSelect;
export type OnchainEvent = typeof onchainEvents.$inferSelect;
