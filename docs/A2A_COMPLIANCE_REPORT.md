# A2A Protocol v0.3.0 Compliance Report

## Executive Summary

NeuralPost's webhook implementation has been audited and updated to fully comply with **A2A Protocol Specification v0.3.0** from the [official specification](https://a2a-protocol.org/v0.3.0/specification/).

## ✅ VERIFICATION COMPLETE (February 6, 2026)

All types verified against official A2A v0.3.0 specification.

---

## 🔴 Critical Issues Fixed

### 1. Part Format (CRITICAL FIX)

**Before (Non-Compliant):**
```typescript
// Missing `kind` discriminator - INVALID
{ text: "Hello" }
{ url: "...", filename: "...", mediaType: "..." }
{ data: {...} }
```

**After (A2A v0.3.0 Compliant):**
```typescript
// TextPart
{ kind: "text", text: "Hello", metadata?: {...} }

// FilePart - nested file object with uri/bytes
{ 
  kind: "file", 
  file: { uri: "https://...", name: "doc.pdf", mimeType: "application/pdf" },
  metadata?: {...}
}

// DataPart
{ kind: "data", data: { foo: "bar" }, metadata?: {...} }
```

### 2. TaskState Enum Case (CRITICAL FIX)

**Before (Non-Compliant):**
```typescript
type TaskState = 'input_required' | 'auth_required' | ...
```

**After (A2A v0.3.0 Compliant - kebab-case):**
```typescript
type TaskState = 
  | 'submitted' 
  | 'working' 
  | 'input-required'   // ← kebab-case
  | 'completed' 
  | 'canceled' 
  | 'failed' 
  | 'rejected' 
  | 'auth-required'    // ← kebab-case
```

### 3. Message/Task Discriminators (CRITICAL FIX)

**Before (Non-Compliant):**
```typescript
// Missing `kind` discriminator
{ messageId: "...", contextId: "...", role: "user", parts: [...] }
{ id: "...", contextId: "...", status: {...} }
```

**After (A2A v0.3.0 Compliant):**
```typescript
// Message with kind discriminator
{ 
  kind: "message",  // REQUIRED
  messageId: "...", 
  contextId: "...", 
  role: "user", 
  parts: [...],
  extensions?: string[]
}

// Task with kind discriminator
{ 
  kind: "task",  // REQUIRED
  id: "...", 
  contextId: "...", 
  status: {...},
  artifacts?: [...],
  history?: [...],
  metadata?: {...}
}
```

### 4. Webhook Response Format (STRUCTURAL FIX)

**Before (Non-Compliant):**
```typescript
// Used method + params pattern (old A2A draft)
{
  jsonrpc: "2.0",
  method: "message/send",
  params: { task?: Task, message?: Message }
}
```

**After (A2A v0.3.0 Compliant - JSON-RPC 2.0 Response):**
```typescript
// Standard JSON-RPC response with result
{
  jsonrpc: "2.0",
  id: "request-uuid",
  result: Task | Message | TaskStatusUpdateEvent | TaskArtifactUpdateEvent
}
```

---

## ✅ Already Compliant Components

| Component | Status | Notes |
|-----------|--------|-------|
| JSON-RPC 2.0 wrapper | ✅ OK | `jsonrpc: "2.0"` |
| Message core fields | ✅ OK | `messageId`, `contextId`, `taskId`, `role`, `parts` |
| Task core fields | ✅ OK | `id`, `contextId`, `status`, `artifacts`, `history` |
| TaskStatus fields | ✅ OK | `state`, `message`, `timestamp` |
| Artifact fields | ✅ OK | `artifactId`, `name`, `description`, `parts` |
| Reference task IDs | ✅ OK | `referenceTaskIds` array |
| Metadata support | ✅ OK | Optional metadata on all objects |

---

## 📝 New Type Definitions

File: `src/services/webhook.ts`

```typescript
// File content types
interface A2AFileWithUri {
  uri: string;
  name?: string;
  mimeType?: string;
}

interface A2AFileWithBytes {
  bytes: string;  // base64 encoded
  name?: string;
  mimeType?: string;
}

// Part types with kind discriminators
interface A2ATextPart {
  kind: 'text';
  text: string;
  metadata?: Record<string, unknown>;
}

interface A2AFilePart {
  kind: 'file';
  file: A2AFileWithUri | A2AFileWithBytes;
  metadata?: Record<string, unknown>;
}

interface A2ADataPart {
  kind: 'data';
  data: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

type A2APart = A2ATextPart | A2AFilePart | A2ADataPart;

// TaskState with kebab-case
type A2ATaskState = 
  | 'submitted' | 'working' | 'input-required' | 'completed' 
  | 'canceled' | 'failed' | 'rejected' | 'auth-required';

// Message with kind discriminator
interface A2AMessage {
  kind: 'message';
  messageId: string;
  contextId: string;
  taskId?: string;
  role: 'user' | 'agent';
  parts: A2APart[];
  metadata?: Record<string, unknown>;
  referenceTaskIds?: string[];
  extensions?: string[];
}

// Task with kind discriminator
interface A2ATask {
  kind: 'task';
  id: string;
  contextId: string;
  status: A2ATaskStatus;
  artifacts?: A2AArtifact[];
  history?: A2AMessage[];
  metadata?: Record<string, unknown>;
}

// Event types
interface A2ATaskStatusUpdateEvent {
  kind: 'status-update';
  taskId: string;
  contextId: string;
  status: A2ATaskStatus;
  final: boolean;
  metadata?: Record<string, unknown>;
}

interface A2ATaskArtifactUpdateEvent {
  kind: 'artifact-update';
  taskId: string;
  contextId: string;
  artifact: A2AArtifact;
  append?: boolean;
  lastChunk?: boolean;
  metadata?: Record<string, unknown>;
}

// JSON-RPC Response
interface A2AStreamResponse {
  jsonrpc: '2.0';
  id?: string | number | null;
  result: A2ATask | A2AMessage | A2ATaskStatusUpdateEvent | A2ATaskArtifactUpdateEvent;
}
```

---

## 📦 Example Webhook Payloads

### Simple Message
```json
{
  "jsonrpc": "2.0",
  "id": "msg-uuid-123",
  "result": {
    "kind": "message",
    "messageId": "msg-uuid-123",
    "contextId": "ctx-uuid-456",
    "role": "user",
    "parts": [
      { "kind": "text", "text": "Hello, agent!" }
    ]
  }
}
```

### Task with Artifacts
```json
{
  "jsonrpc": "2.0",
  "id": "task-uuid-789",
  "result": {
    "kind": "task",
    "id": "task-uuid-789",
    "contextId": "ctx-uuid-456",
    "status": {
      "state": "completed",
      "timestamp": "2024-01-15T10:30:00Z"
    },
    "artifacts": [
      {
        "artifactId": "art-001",
        "name": "report.pdf",
        "parts": [
          {
            "kind": "file",
            "file": {
              "uri": "https://cdn.example.com/report.pdf",
              "name": "report.pdf",
              "mimeType": "application/pdf"
            }
          }
        ]
      }
    ],
    "history": [
      {
        "kind": "message",
        "messageId": "msg-001",
        "contextId": "ctx-uuid-456",
        "role": "user",
        "parts": [{ "kind": "text", "text": "Generate a report" }]
      }
    ]
  }
}
```

### Task Status Update Event
```json
{
  "jsonrpc": "2.0",
  "id": "event-001",
  "result": {
    "kind": "status-update",
    "taskId": "task-uuid-789",
    "contextId": "ctx-uuid-456",
    "status": {
      "state": "working",
      "timestamp": "2024-01-15T10:25:00Z"
    },
    "final": false
  }
}
```

---

## 🔗 References

- [A2A Protocol Specification v0.3.0](https://a2a-protocol.org/v0.3.0/specification/)
- [A2A Protocol GitHub](https://github.com/a2aproject/A2A)
- [A2A Protocol Definition (Proto)](https://a2a-protocol.org/latest/definitions/)
- [Official A2A JavaScript SDK](https://github.com/a2aproject/a2a-js)

---

## 📅 Audit Date

**February 6, 2026**

## ✍️ Status

**COMPLIANT** with A2A Protocol v0.3.0

---

## ✅ Final Verification Checklist

| Component | Spec Requirement | Implementation | Status |
|-----------|-----------------|----------------|--------|
| **TaskState** | kebab-case lowercase (`submitted`, `working`, `input-required`, `completed`, `canceled`, `failed`, `rejected`, `auth-required`) | ✅ Correct | ✅ PASS |
| **Role** | lowercase (`user`, `agent`) | ✅ Correct | ✅ PASS |
| **Part discriminator** | `kind` field required (`text`, `file`, `data`) | ✅ Present | ✅ PASS |
| **TextPart** | `{ kind: "text", text: "...", metadata?: {...} }` | ✅ Correct | ✅ PASS |
| **FilePart** | `{ kind: "file", file: { uri/bytes, name?, mimeType? }, metadata?: {...} }` | ✅ Correct | ✅ PASS |
| **DataPart** | `{ kind: "data", data: {...}, metadata?: {...} }` | ✅ Correct | ✅ PASS |
| **FileWithUri** | `{ uri: "...", name?: "...", mimeType?: "..." }` | ✅ Correct | ✅ PASS |
| **FileWithBytes** | `{ bytes: "base64...", name?: "...", mimeType?: "..." }` | ✅ Correct | ✅ PASS |
| **Message** | `kind: "message"` discriminator + `messageId`, `contextId`, `role`, `parts` | ✅ Correct | ✅ PASS |
| **Task** | `kind: "task"` discriminator + `id`, `contextId`, `status` | ✅ Correct | ✅ PASS |
| **TaskStatus** | `state` (TaskState) + optional `message`, `timestamp` | ✅ Correct | ✅ PASS |
| **Artifact** | `artifactId`, `parts[]`, optional `name`, `description`, `extensions`, `metadata` | ✅ Correct | ✅ PASS |
| **TaskStatusUpdateEvent** | `kind: "status-update"` + `taskId`, `contextId`, `status`, `final` | ✅ Correct | ✅ PASS |
| **TaskArtifactUpdateEvent** | `kind: "artifact-update"` + `taskId`, `contextId`, `artifact`, optional `append`, `lastChunk` | ✅ Correct | ✅ PASS |
| **JSON-RPC Response** | `{ jsonrpc: "2.0", id?: ..., result: ... }` | ✅ Correct | ✅ PASS |
| **Content-Type** | `application/json` for JSON-RPC payloads | ✅ Correct | ✅ PASS |

## 📝 Notes

1. **Version Compatibility**: This implementation targets A2A v0.3.0 (latest released version as of February 2026)
2. **RC v1.0 Changes**: The upcoming v1.0 RC will remove `kind` discriminators from Task/Message objects. Current implementation will need update when v1.0 is released.
3. **Transport**: Uses JSON-RPC 2.0 over HTTPS (one of three supported transports)
4. **Push Notifications**: Webhook delivery uses JSON-RPC response format as per spec
