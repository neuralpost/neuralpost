// ═══════════════════════════════════════════════════════════════════════════
// NEURALPOST BLOCKCHAIN SERVICE
// SIWE auth, ERC-8004 registration, multi-chain (SKALE + L2s)
// ═══════════════════════════════════════════════════════════════════════════

import { createHash, randomBytes } from 'crypto';
import { verifyMessage, getAddress } from 'ethers';
import {
  CHAIN_CONFIGS, PRIMARY_CHAIN,
  type SupportedChainId, type ChainConfig,
  type OnChainAgentIdentity, type ERC8004RegistrationFile,
  type PaymentProof, type EscrowInfo,
} from './types';

const BLOCKCHAIN_ENABLED = process.env.BLOCKCHAIN_ENABLED === 'true';

// ─── SIWE Nonce Store ────────────────────────────────────────────────────

interface SIWENonce { nonce: string; createdAt: number; expiresAt: number; }
const nonceStore = new Map<string, SIWENonce>();
const NONCE_TTL = 5 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of nonceStore) {
    if (now > val.expiresAt) nonceStore.delete(key);
  }
}, 10 * 60 * 1000).unref();

export function generateSIWENonce(): { nonce: string; expiresAt: number } {
  const nonce = randomBytes(16).toString('hex');
  const expiresAt = Date.now() + NONCE_TTL;
  nonceStore.set(nonce, { nonce, createdAt: Date.now(), expiresAt });
  if (nonceStore.size > 10000) {
    const first = nonceStore.keys().next().value;
    if (first) nonceStore.delete(first);
  }
  return { nonce, expiresAt };
}

export function consumeSIWENonce(nonce: string): boolean {
  const stored = nonceStore.get(nonce);
  if (!stored || Date.now() > stored.expiresAt) { nonceStore.delete(nonce); return false; }
  nonceStore.delete(nonce);
  return true;
}

// ─── SIWE Message Parsing & Verification ─────────────────────────────────

export function parseSIWEMessage(message: string): {
  domain: string; address: string; statement: string;
  uri: string; version: string; chainId: number;
  nonce: string; issuedAt: string;
} | null {
  try {
    const lines = message.split('\n');
    const domainMatch = lines[0]?.match(/^(.+) wants you to sign in with your Ethereum account:$/);
    if (!domainMatch) return null;
    const address = lines[1]?.trim();
    if (!address?.match(/^0x[a-fA-F0-9]{40}$/)) return null;

    const fields: Record<string, string> = {};
    let statement = '', inStatement = false;
    for (let i = 2; i < lines.length; i++) {
      const line = lines[i];
      if (!line && !inStatement) { inStatement = true; continue; }
      const kv = line.match(/^([A-Za-z\s]+):\s*(.+)$/);
      if (kv) { inStatement = false; fields[kv[1].trim().toLowerCase()] = kv[2].trim(); }
      else if (inStatement && line) { statement += (statement ? '\n' : '') + line; }
    }

    return {
      domain: domainMatch[1], address, statement,
      uri: fields['uri'] || '', version: fields['version'] || '1',
      chainId: parseInt(fields['chain id'] || '1', 10),
      nonce: fields['nonce'] || '', issuedAt: fields['issued at'] || '',
    };
  } catch { return null; }
}

export async function verifySIWESignature(
  message: string, signature: string
): Promise<{ valid: boolean; address: string; chainId: number } | null> {
  const parsed = parseSIWEMessage(message);
  if (!parsed) return null;
  if (!consumeSIWENonce(parsed.nonce)) return null;
  const issuedAt = new Date(parsed.issuedAt).getTime();
  if (Date.now() - issuedAt > NONCE_TTL) return null;

  // Validate signature format (65 bytes = 130 hex chars + 0x prefix)
  if (!signature.match(/^0x[a-fA-F0-9]{130}$/)) return null;

  try {
    // Recover signer address from signature using ethers.js (Keccak-256 + secp256k1 ecrecover)
    const recoveredAddress = verifyMessage(message, signature);

    // Compare recovered address with claimed address (case-insensitive, then checksum)
    const recoveredChecksum = getAddress(recoveredAddress);
    const claimedChecksum = getAddress(parsed.address);

    if (recoveredChecksum !== claimedChecksum) {
      return null; // Signature doesn't match claimed address
    }

    return { valid: true, address: recoveredChecksum, chainId: parsed.chainId };
  } catch {
    // Invalid signature (malformed, wrong recovery id, etc.)
    return null;
  }
}

// ─── ERC-8004 Registration File ──────────────────────────────────────────

export function generateRegistrationFile(params: {
  agentId: number;
  domain: string;
  displayName: string;
  description?: string;
  avatarUrl?: string;
  skills?: string[];
  chainId: SupportedChainId;
  registryAddress: string;
  ownerAddress: string;
  a2aEndpoint: string;
  webhookUrl?: string;
}): ERC8004RegistrationFile {
  const services: ERC8004RegistrationFile['services'] = [
    { name: 'A2A', endpoint: `${params.a2aEndpoint}/.well-known/agent-card.json`, version: '0.3.0', skills: params.skills },
    { name: 'web', endpoint: params.a2aEndpoint },
  ];
  if (params.webhookUrl) services.push({ name: 'webhook', endpoint: params.webhookUrl });

  return {
    type: 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1',
    name: params.displayName || params.domain,
    description: params.description || `NeuralPost agent: ${params.domain}`,
    image: params.avatarUrl,
    services,
    x402Support: true,
    active: true,
    registrations: [{
      agentId: params.agentId,
      agentRegistry: `eip155:${params.chainId}:${params.registryAddress}`,
      owner: params.ownerAddress,
      createdAt: new Date().toISOString(),
    }],
  };
}

// ─── On-chain Queries (stubs) ────────────────────────────────────────────

export async function getOnChainAgent(
  walletAddress: string, chainId: SupportedChainId = PRIMARY_CHAIN
): Promise<OnChainAgentIdentity | null> {
  if (!BLOCKCHAIN_ENABLED) return null;
  return null;
}

export async function getOnChainReputation(
  agentId: number, chainId: SupportedChainId = PRIMARY_CHAIN
): Promise<number | null> {
  if (!BLOCKCHAIN_ENABLED) return null;
  return null;
}

export async function verifyPaymentProof(proof: PaymentProof): Promise<boolean> {
  if (!BLOCKCHAIN_ENABLED) return false;
  return false;
}

export async function getEscrowForTask(
  taskId: string, chainId: SupportedChainId = PRIMARY_CHAIN
): Promise<EscrowInfo | null> {
  if (!BLOCKCHAIN_ENABLED) return null;
  return null;
}

// ─── Utilities ───────────────────────────────────────────────────────────

export function taskIdToBytes32(taskId: string): string {
  return '0x' + createHash('sha256').update(taskId).digest('hex');
}

export function getChainConfig(chainId: SupportedChainId): ChainConfig {
  return CHAIN_CONFIGS[chainId];
}

export function isValidEthAddress(address: string): boolean {
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return false;
  try {
    // getAddress() validates checksum (EIP-55) and throws on invalid
    getAddress(address);
    return true;
  } catch {
    return false;
  }
}

export function getGlobalAgentId(chainId: SupportedChainId, agentId: number): string {
  return `eip155:${chainId}:${CHAIN_CONFIGS[chainId].contracts.registry}:${agentId}`;
}

export function getBlockchainStatus() {
  const chains = Object.values(CHAIN_CONFIGS)
    .filter(c => !c.isTestnet || process.env.NODE_ENV !== 'production')
    .map(c => ({ chainId: c.chainId, name: c.name, family: c.family, isTestnet: c.isTestnet, zeroGas: c.zeroGas }));

  return {
    enabled: BLOCKCHAIN_ENABLED,
    primaryChain: CHAIN_CONFIGS[PRIMARY_CHAIN].name,
    primaryChainId: PRIMARY_CHAIN,
    paymentToken: 'USDC',
    nativeToken: null,
    custodialWallets: true,
    sponsoredMints: process.env.SPONSOR_MINTS === 'true',
    supportedChains: chains,
    contracts: BLOCKCHAIN_ENABLED ? {
      registry: CHAIN_CONFIGS[PRIMARY_CHAIN].contracts.registry,
      escrow: CHAIN_CONFIGS[PRIMARY_CHAIN].contracts.escrow,
    } : null,
  };
}
