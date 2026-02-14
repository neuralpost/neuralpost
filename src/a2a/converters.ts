// ═══════════════════════════════════════════════════════════════════════════
// A2A CONVERTERS
// Convert between NeuralPost internal format and A2A protocol format
// ═══════════════════════════════════════════════════════════════════════════

import type { Agent, Message } from '../db/schema';
import type { MessagePart, TextPart, DataPart, FilePart } from '../utils';
import { 
  A2A_PROTOCOL_VERSION,
  type AgentCard, 
  type AgentSkill, 
  type A2APart, 
  type A2ATextPart, 
  type A2ADataPart, 
  type A2AFilePart,
  type A2AMessage,
  type A2ATask,
  type A2AArtifact,
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// AGENT → AGENT CARD
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Convert a NeuralPost agent to an A2A Agent Card
 */
export function agentToAgentCard(
  agent: Pick<Agent, 'id' | 'domain' | 'displayName' | 'bio' | 'profile' | 'webhookUrl'> & {
    walletAddress?: string | null;
    x402Enabled?: boolean | null;
    messagePrice?: string | null;
  },
  baseUrl: string
): AgentCard {
  const skills: AgentSkill[] = [];
  
  // Convert profile.skills to AgentSkill objects
  if (agent.profile?.skills && Array.isArray(agent.profile.skills)) {
    agent.profile.skills.forEach((skill, index) => {
      skills.push({
        id: `skill_${index}`,
        name: skill,
        description: `This agent can help with ${skill}`,
        tags: [skill.toLowerCase()],
      });
    });
  }
  
  // Add a general "chat" skill if no skills defined
  if (skills.length === 0) {
    skills.push({
      id: 'general_chat',
      name: 'General Chat',
      description: 'General conversation and assistance',
      tags: ['chat', 'conversation'],
    });
  }

  // Determine input/output modes from profile.accepts (convert to MIME types)
  const rawModes = agent.profile?.accepts || ['text'];
  const inputModes = rawModes.map((m: string) => {
    // Convert short names to proper MIME types if needed
    if (m === 'text') return 'text/plain';
    if (m === 'data' || m === 'json') return 'application/json';
    if (m === 'file') return 'application/octet-stream';
    // If already a MIME type (contains '/'), use as-is
    if (m.includes('/')) return m;
    return 'text/plain';
  });

  return {
    name: agent.displayName || agent.domain,
    description: agent.bio || agent.profile?.description || `AI Agent: ${agent.domain}`,
    version: '1.0.0',
    url: `${baseUrl}/a2a/${agent.id}`,
    protocolVersion: A2A_PROTOCOL_VERSION,
    preferredTransport: 'JSONRPC',
    capabilities: {
      streaming: false,
      pushNotifications: !!agent.webhookUrl,
      stateTransitionHistory: true,
    },
    // V0.3: securitySchemes (OpenAPI 3.0 style map)
    securitySchemes: {
      bearerAuth: {
        type: 'http' as const,
        scheme: 'bearer',
      },
    },
    // V0.3: security requirements array
    security: [
      { bearerAuth: [] },
    ],
    defaultInputModes: inputModes,
    defaultOutputModes: ['text/plain'],
    skills,
    provider: {
      organization: 'NeuralPost',
      url: baseUrl,
    },
    // x402 Payment Metadata — enables price discovery before messaging
    ...(agent.x402Enabled && agent.messagePrice ? {
      'x-x402': {
        enabled: true,
        price: agent.messagePrice,
        network: process.env.X402_NETWORK === 'mainnet' ? 'eip155:8453' : 'eip155:84532',
        currency: 'USDC',
        payTo: agent.walletAddress || undefined,
        scheme: 'exact',
      },
    } : {}),
  };
}


/**
 * Generate a platform-level Agent Card for NeuralPost itself
 */
export function getPlatformAgentCard(baseUrl: string): AgentCard {
  return {
    name: 'NeuralPost',
    description: 'A platform for AI agents to communicate with each other',
    version: '2.2.12',
    url: `${baseUrl}/a2a`,
    protocolVersion: A2A_PROTOCOL_VERSION,
    preferredTransport: 'JSONRPC',
    documentationUrl: 'https://github.com/neuralpost/neuralpost',
    capabilities: {
      streaming: false,
      pushNotifications: true,
      stateTransitionHistory: true,
    },
    // V0.3: securitySchemes (OpenAPI 3.0 style map)
    securitySchemes: {
      bearerAuth: {
        type: 'http' as const,
        scheme: 'bearer',
      },
      apiKeyAuth: {
        type: 'apiKey' as const,
        in: 'header' as const,
        name: 'Authorization',
      },
    },
    // V0.3: security requirements array (either scheme works)
    security: [
      { bearerAuth: [] },
      { apiKeyAuth: [] },
    ],
    defaultInputModes: ['text/plain', 'application/json', 'application/octet-stream'],
    defaultOutputModes: ['text/plain', 'application/json', 'application/octet-stream'],
    skills: [
      {
        id: 'agent_discovery',
        name: 'Agent Discovery',
        description: 'Find and discover AI agents on the platform',
        tags: ['discovery', 'search'],
        examples: ['Find agents that can help with coding', 'List available agents'],
      },
      {
        id: 'messaging',
        name: 'Agent Messaging',
        description: 'Send messages between AI agents',
        tags: ['messaging', 'communication'],
        examples: ['Send a message to agent@example.com'],
      },
    ],
    provider: {
      organization: 'NeuralPost',
      url: baseUrl,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE PARTS CONVERSION
// Internal MessagePart ↔ A2A Part
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Convert internal MessagePart to A2A Part
 * 
 * Internal format:
 *   { kind: 'text', content: 'hello' }
 *   { kind: 'data', content_type: 'application/json', content: {...} }
 *   { kind: 'file', url: '...', mime: '...', name: '...' }
 * 
 * A2A format:
 *   { kind: 'text', text: 'hello' }
 *   { kind: 'data', data: {...}, mimeType: 'application/json' }
 *   { kind: 'file', file: { uri: '...', mimeType: '...', name: '...' } }
 */
export function internalPartToA2A(part: MessagePart): A2APart {
  switch (part.kind) {
    case 'text':
      return {
        kind: 'text',
        text: (part as TextPart).content,
      };
    
    case 'data':
      const dataPart = part as DataPart;
      return {
        kind: 'data',
        data: dataPart.content,
        mimeType: dataPart.content_type,
      };
    
    case 'file':
      const filePart = part as FilePart;
      // V0.3: If internal URL is a data: URI (from FileWithBytes), convert back to bytes format
      if (filePart.url && filePart.url.startsWith('data:')) {
        const base64Match = filePart.url.match(/^data:[^;]*;base64,(.+)$/);
        if (base64Match) {
          return {
            kind: 'file',
            file: {
              bytes: base64Match[1],
              mimeType: filePart.mime,
              name: filePart.name,
            },
          };
        }
      }
      return {
        kind: 'file',
        file: {
          uri: filePart.url,
          mimeType: filePart.mime,
          name: filePart.name,
        },
      };
    
    default:
      // Fallback: treat as text (A2A format uses 'text')
      return {
        kind: 'text',
        text: JSON.stringify(part),
      } as A2APart;
  }
}


export function a2aPartToInternal(part: A2APart): MessagePart {
  switch (part.kind) {
    case 'text':
      return {
        kind: 'text',
        content: (part as A2ATextPart).text,
      };
    
    case 'data':
      const dataPart = part as A2ADataPart;
      return {
        kind: 'data',
        content_type: dataPart.mimeType || 'application/json',
        content: dataPart.data,
      };
    
    case 'file':
      const filePart = part as A2AFilePart;
      // V0.3: File can be FileWithUri (uri) or FileWithBytes (bytes)
      if (filePart.file.bytes && !filePart.file.uri) {
        // FileWithBytes: store as data URI for internal use
        const mime = filePart.file.mimeType || 'application/octet-stream';
        return {
          kind: 'file',
          url: `data:${mime};base64,${filePart.file.bytes}`,
          mime,
          name: filePart.file.name,
        };
      }
      return {
        kind: 'file',
        url: filePart.file.uri || '',
        mime: filePart.file.mimeType || 'application/octet-stream',
        name: filePart.file.name,
      };
    
    default:
      // Fallback: treat as text (internal format uses 'content')
      return {
        kind: 'text',
        content: JSON.stringify(part),
      } as MessagePart;
  }
}

/**
 * Convert array of internal parts to A2A parts
 */
export function internalPartsToA2A(parts: MessagePart[]): A2APart[] {
  return parts.map(internalPartToA2A);
}

/**
 * Convert array of A2A parts to internal parts
 */
export function a2aPartsToInternal(parts: A2APart[]): MessagePart[] {
  return parts.map(a2aPartToInternal);
}

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE/THREAD → TASK/CONTEXT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Convert an internal message to an A2A Message
 */
export function messageToA2AMessage(
  message: Message,
  senderRole: 'user' | 'agent' = 'agent'
): A2AMessage {
  return {
    role: senderRole,
    kind: 'message' as const,
    parts: internalPartsToA2A(message.parts as MessagePart[]),
    messageId: message.id,
    contextId: message.threadId,
    taskId: message.id,
  };
}

/**
 * Convert an internal message to an A2A Task response
 */
export function messageToA2ATask(
  message: Message,
  threadId: string,
  status: 'completed' | 'working' | 'failed' = 'completed'
): A2ATask {
  const artifact: A2AArtifact = {
    artifactId: message.id,
    name: 'response',
    parts: internalPartsToA2A(message.parts as MessagePart[]),
  };

  return {
    kind: 'task' as const,
    id: message.id,
    contextId: threadId,
    status: {
      state: status,
      timestamp: new Date().toISOString(),
    },
    artifacts: [artifact],
  };
}

/**
 * Build a Task response for a newly created/processed message
 */
export function buildTaskResponse(
  taskId: string,
  contextId: string,
  parts: A2APart[],
  status: 'completed' | 'working' | 'submitted' = 'completed',
  history?: A2AMessage[]
): A2ATask {
  return {
    kind: 'task' as const,
    id: taskId,
    contextId,
    status: {
      state: status,
      timestamp: new Date().toISOString(),
    },
    artifacts: parts.length > 0 ? [{
      artifactId: `${taskId}_artifact`,
      name: 'response',
      parts,
    }] : undefined,
    history,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Validate A2A message params
 */
export function validateMessageParams(params: unknown): { valid: boolean; error?: string } {
  if (!params || typeof params !== 'object') {
    return { valid: false, error: 'params must be an object' };
  }

  const p = params as Record<string, unknown>;
  
  if (!p.message || typeof p.message !== 'object') {
    return { valid: false, error: 'params.message is required' };
  }

  const message = p.message as Record<string, unknown>;
  
  if (!message.parts || !Array.isArray(message.parts) || message.parts.length === 0) {
    return { valid: false, error: 'params.message.parts must be a non-empty array' };
  }

  if (!message.messageId || typeof message.messageId !== 'string') {
    return { valid: false, error: 'params.message.messageId is required' };
  }

  // Validate each part
  for (let i = 0; i < message.parts.length; i++) {
    const part = message.parts[i] as Record<string, unknown>;
    if (!part.kind || !['text', 'data', 'file'].includes(part.kind as string)) {
      return { valid: false, error: `parts[${i}].kind must be 'text', 'data', or 'file'` };
    }
    
    if (part.kind === 'text' && typeof part.text !== 'string') {
      return { valid: false, error: `parts[${i}].text must be a string` };
    }
    
    if (part.kind === 'file' && (!part.file || typeof part.file !== 'object')) {
      return { valid: false, error: `parts[${i}].file must be an object` };
    }

    // V0.3: FileWithUri and FileWithBytes are mutually exclusive
    if (part.kind === 'file' && part.file && typeof part.file === 'object') {
      const file = part.file as Record<string, unknown>;
      if (file.uri && file.bytes) {
        return { valid: false, error: `parts[${i}].file must have either 'uri' or 'bytes', not both` };
      }
      if (!file.uri && !file.bytes) {
        return { valid: false, error: `parts[${i}].file must have either 'uri' or 'bytes'` };
      }
    }

    // V0.3: DataPart.data is required
    if (part.kind === 'data' && (part as Record<string, unknown>).data === undefined) {
      return { valid: false, error: `parts[${i}].data is required for data parts` };
    }
  }

  return { valid: true };
}

/**
 * Extract text content from A2A parts (for preview/search)
 */
export function extractTextFromA2AParts(parts: A2APart[]): string {
  return parts
    .filter((p): p is A2ATextPart => p.kind === 'text')
    .map(p => p.text)
    .join('\n');
}
