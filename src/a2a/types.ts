// ═══════════════════════════════════════════════════════════════════════════
// A2A PROTOCOL TYPES
// Based on A2A Protocol Specification v0.3
// https://a2a-protocol.org/latest/specification/
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A2A Protocol Version
 */
export const A2A_PROTOCOL_VERSION = '0.3.0';

// ═══════════════════════════════════════════════════════════════════════════
// AGENT CARD
// JSON document describing agent capabilities, published at /.well-known/agent-card.json
// ═══════════════════════════════════════════════════════════════════════════

export interface AgentSkill {
  id: string;
  name: string;
  description: string;    // V0.3: required
  tags: string[];          // V0.3: required
  examples?: string[];
  inputModes?: string[];   // MIME types, overrides agent defaults
  outputModes?: string[];  // MIME types, overrides agent defaults
  security?: Record<string, string[]>[];  // V0.3: per-skill security requirements (OR of ANDs)
}

export interface AgentCapabilities {
  streaming?: boolean;
  pushNotifications?: boolean;
  stateTransitionHistory?: boolean;    // V0.3: TS spec has it (optional), proto dropped it
  extensions?: AgentExtension[];        // V0.3: supported extensions
}

// V0.3: Extension declaration
export interface AgentExtension {
  uri: string;
  description?: string;
  required?: boolean;
  params?: Record<string, unknown>;  // proto field 4: google.protobuf.Struct
}

// V0.3: Security schemes follow OpenAPI 3.0 style (map of scheme name → scheme definition)
export interface HTTPAuthSecurityScheme {
  type: 'http';
  scheme: string;        // e.g., 'bearer'
  bearerFormat?: string; // e.g., 'JWT'
  description?: string;
}

export interface APIKeySecurityScheme {
  type: 'apiKey';
  in: 'header' | 'query' | 'cookie';
  name: string;          // header/query/cookie param name
  description?: string;
}

export interface OAuth2SecurityScheme {
  type: 'oauth2';
  flows: Record<string, unknown>;
  description?: string;
}

export interface OpenIdConnectSecurityScheme {
  type: 'openIdConnect';
  openIdConnectUrl: string;
  description?: string;
}

// V0.3: Mutual TLS authentication scheme
export interface MutualTLSSecurityScheme {
  type: 'mutualTLS';
  description?: string;
}

export type SecurityScheme = 
  | HTTPAuthSecurityScheme
  | APIKeySecurityScheme
  | OAuth2SecurityScheme
  | OpenIdConnectSecurityScheme
  | MutualTLSSecurityScheme;

// Security requirement: map of scheme name → required scopes
export type SecurityRequirement = Record<string, string[]>;

export interface AgentProvider {
  organization: string;  // V0.3: 'organization' not 'name'
  url: string;           // V0.3: required
}

// V0.3: Transport interface declaration
export interface AgentInterface {
  url: string;
  transport: string;     // 'JSONRPC' | 'GRPC' | 'HTTP+JSON' or custom
}

// V0.3: JWS signature for AgentCard verification (RFC 7515)
export interface AgentCardSignature {
  protected: string;     // Base64url-encoded JWS Protected Header
  signature: string;     // Base64url-encoded JWS Signature
  header?: Record<string, unknown>; // Unprotected header params
}

export interface AgentCard {
  name: string;
  description: string;                              // V0.3: required
  version: string;
  url: string;
  protocolVersion: string;
  documentationUrl?: string;
  capabilities: AgentCapabilities;                   // V0.3: required
  securitySchemes?: Record<string, SecurityScheme>;  // V0.3: OpenAPI 3.0 style map
  security?: SecurityRequirement[];                  // V0.3: array of requirement objects
  defaultInputModes: string[];                       // V0.3: required, MIME types
  defaultOutputModes: string[];                      // V0.3: required, MIME types
  skills: AgentSkill[];                              // V0.3: required
  provider?: AgentProvider;
  supportsAuthenticatedExtendedCard?: boolean;       // V0.3: optional (proto field 13)
  preferredTransport?: string;                       // V0.3: optional, defaults to 'JSONRPC'
  additionalInterfaces?: AgentInterface[];           // V0.3: additional transport endpoints
  iconUrl?: string;                                  // V0.3: optional
  signatures?: AgentCardSignature[];                 // V0.3: JWS signatures
  // x402 Payment Metadata (NeuralPost extension)
  'x-x402'?: {
    enabled: boolean;
    price?: string;           // Human-readable USD price, e.g. "$0.001"
    network: string;          // CAIP-2 chain ID, e.g. "eip155:8453"
    currency: string;         // Token symbol, e.g. "USDC"
    payTo?: string;           // Agent's receiving wallet address
    scheme: string;           // Payment scheme, e.g. "exact"
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE PARTS
// Content units within messages and artifacts
// ═══════════════════════════════════════════════════════════════════════════

export interface A2ATextPart {
  kind: 'text';
  text: string;
  metadata?: Record<string, unknown>;  // V0.3: part-level metadata
}

export interface A2ADataPart {
  kind: 'data';
  data: unknown;
  mimeType?: string;
  metadata?: Record<string, unknown>;  // V0.3: part-level metadata
}

export interface A2AFilePart {
  kind: 'file';
  file: {
    name?: string;
    mimeType?: string;
    uri?: string;
    bytes?: string; // base64 encoded
  };
  metadata?: Record<string, unknown>;  // V0.3: part-level metadata
}

export type A2APart = A2ATextPart | A2ADataPart | A2AFilePart;

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE
// A single turn of communication between client and agent
// ═══════════════════════════════════════════════════════════════════════════

export interface A2AMessage {
  role: 'user' | 'agent';
  parts: A2APart[];
  messageId: string;
  kind: 'message';                            // V0.3: required discriminator (readonly in spec)
  contextId?: string;
  taskId?: string;
  referenceTaskIds?: string[];               // V0.3: referenced task IDs
  extensions?: string[];                     // V0.3: extension URIs
  metadata?: Record<string, unknown>;
}

// ═══════════════════════════════════════════════════════════════════════════
// TASK
// Unit of work, with lifecycle state
// V3: Added rejected and auth-required states per A2A Protocol Spec v0.3
// ═══════════════════════════════════════════════════════════════════════════

export type TaskState = 
  | 'submitted' 
  | 'working' 
  | 'input-required' 
  | 'completed' 
  | 'failed' 
  | 'canceled'
  | 'rejected'       // Agent declined to perform task (terminal)
  | 'auth-required'  // Authentication needed (interrupted)
  | 'unknown';       // Unknown/unspecified state (terminal)

export interface TaskStatus {
  state: TaskState;
  message?: A2AMessage;
  timestamp?: string;
}

export interface A2AArtifact {
  artifactId: string;
  name?: string;
  description?: string;
  parts: A2APart[];
  metadata?: Record<string, unknown>;  // V0.3: artifact-level metadata
  extensions?: string[];               // V0.3: extension URIs
  index?: number;                      // ordering index
  append?: boolean;                    // append to previous artifact with same id
  lastChunk?: boolean;                 // last chunk indicator for streaming
}

export interface A2ATask {
  kind: 'task';                                // V0.3: discriminator (Task vs Message)
  id: string;
  contextId: string;
  status: TaskStatus;
  artifacts?: A2AArtifact[];
  history?: A2AMessage[];
  metadata?: Record<string, unknown>;
}

// ═══════════════════════════════════════════════════════════════════════════
// STREAMING EVENT TYPES
// Used in message/stream and tasks/resubscribe SSE responses
// ═══════════════════════════════════════════════════════════════════════════

/** Sent by server during streaming to notify status changes */
export interface TaskStatusUpdateEvent {
  kind: 'status-update';
  taskId: string;
  contextId: string;
  status: TaskStatus;
  final: boolean;                              // true = end of stream
  metadata?: Record<string, unknown>;
}

/** Sent by server during streaming when an artifact is generated/updated */
export interface TaskArtifactUpdateEvent {
  kind: 'artifact-update';
  taskId: string;
  contextId: string;
  artifact: A2AArtifact;
  lastChunk?: boolean;                         // proto field 4: last chunk of this artifact
  metadata?: Record<string, unknown>;
}

/** Union type for streaming response payloads (SSE data field) */
export type StreamingMessageResponse = 
  | A2AMessage
  | A2ATask
  | TaskStatusUpdateEvent
  | TaskArtifactUpdateEvent;

// ═══════════════════════════════════════════════════════════════════════════
// JSON-RPC 2.0
// Request/Response format for A2A communication
// ═══════════════════════════════════════════════════════════════════════════

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: unknown;
}

export interface JsonRpcResponse<T = unknown> {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: T;
  error?: JsonRpcError;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

// Standard JSON-RPC error codes
export const JSON_RPC_ERRORS = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  
  // A2A-specific errors (-32000 to -32099)
  TASK_NOT_FOUND: -32001,
  TASK_NOT_CANCELABLE: -32002,
  PUSH_NOTIFICATION_NOT_SUPPORTED: -32003,
  UNSUPPORTED_OPERATION: -32004,
  CONTENT_TYPE_NOT_SUPPORTED: -32005,
  INVALID_AGENT_RESPONSE: -32006,                    // V0.3: was "invalid agent card", spec says "invalid agent response" (502)
  EXTENDED_AGENT_CARD_NOT_CONFIGURED: -32007,         // V0.3: agent doesn't support extended card
} as const;

// ═══════════════════════════════════════════════════════════════════════════
// PUSH NOTIFICATION TYPES (§6.8-6.10)
// ═══════════════════════════════════════════════════════════════════════════

/** §6.9: Authentication info for push notification delivery */
export interface PushNotificationAuthenticationInfo {
  schemes: string[];
  credentials?: string;
}

/** §6.8: Configuration for push notification delivery */
export interface PushNotificationConfig {
  url: string;
  id?: string;                                        // V0.3: config identifier
  token?: string;
  authentication?: PushNotificationAuthenticationInfo;
}

/** §6.10: Associates a push notification config with a task */
export interface TaskPushNotificationConfig {
  taskId: string;
  pushNotificationConfig: PushNotificationConfig;
}

// ═══════════════════════════════════════════════════════════════════════════
// REQUEST PARAMS
// Typed params for each JSON-RPC method
// ═══════════════════════════════════════════════════════════════════════════

export interface MessageSendConfiguration {
  acceptedOutputModes?: string[];
  historyLength?: number;                      // V0.3: number of recent messages to include
  blocking?: boolean;
  pushNotificationConfig?: PushNotificationConfig;
}

export interface MessageSendParams {
  message: {
    role: 'user';
    parts: A2APart[];
    messageId: string;
    kind: 'message';                        // V0.3: required discriminator
    contextId?: string;
    taskId?: string;
    referenceTaskIds?: string[];             // V0.3: referenced task IDs
    extensions?: string[];                   // V0.3: extension URIs
    metadata?: Record<string, unknown>;
  };
  configuration?: MessageSendConfiguration;
  metadata?: Record<string, unknown>;
}

/** §7.3.1: TaskQueryParams — used by tasks/get */
export interface TasksGetParams {
  id: string;
  historyLength?: number;
  metadata?: Record<string, unknown>;          // V0.3: optional request metadata
}

/** §7.4.1: TaskIdParams — used by tasks/cancel */
export interface TasksCancelParams {
  id: string;
  metadata?: Record<string, unknown>;          // V0.3: optional request metadata
}
