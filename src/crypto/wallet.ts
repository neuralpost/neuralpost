// ═══════════════════════════════════════════════════════════════════════════
// NEURALPOST CUSTODIAL WALLET SERVICE
//
// Every agent gets a protocol-generated wallet on registration.
// Private keys encrypted at rest (AES-256-GCM), exportable anytime.
//
// Security model:
//   - Master key from env: WALLET_ENCRYPTION_KEY (32-byte hex)
//   - Each key encrypted with unique IV
//   - Agent can export private key → becomes "self-custodied"
//   - Wallet works the same regardless of custody type
//
// Chain priority:
//   1. SKALE Calypso (zero gas — sponsored mints free)
//   2. Base (x402 payments, USDC)
//   3. Other L2s (Arbitrum, Optimism)
//   4. Ethereum (high gas, only for canonical ERC-8004)
// ═══════════════════════════════════════════════════════════════════════════

import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { Wallet, computeAddress } from 'ethers';
import type { EncryptedKeyData, WalletExportResult, CustodialWallet } from './types';
import { PRIMARY_CHAIN } from './types';

// ─── Master Key Management ───────────────────────────────────────────────

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;          // 96-bit IV for GCM
const AUTH_TAG_LENGTH = 16;    // 128-bit auth tag

function getMasterKey(): Buffer {
  const keyHex = process.env.WALLET_ENCRYPTION_KEY;
  if (!keyHex || keyHex.length !== 64) {
    throw new Error(
      'WALLET_ENCRYPTION_KEY must be a 64-char hex string (32 bytes). ' +
      'Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
    );
  }
  return Buffer.from(keyHex, 'hex');
}

// ─── Encryption / Decryption ─────────────────────────────────────────────

export function encryptPrivateKey(privateKey: string): EncryptedKeyData {
  const masterKey = getMasterKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, masterKey, iv, { authTagLength: AUTH_TAG_LENGTH });

  // Strip 0x prefix for encryption
  const keyBytes = privateKey.startsWith('0x') ? privateKey.slice(2) : privateKey;
  let encrypted = cipher.update(keyBytes, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const authTag = cipher.getAuthTag();

  return {
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted,
    algorithm: ALGORITHM,
  };
}

export function decryptPrivateKey(data: EncryptedKeyData): string {
  const masterKey = getMasterKey();
  const iv = Buffer.from(data.iv, 'base64');
  const authTag = Buffer.from(data.authTag, 'base64');
  const decipher = createDecipheriv(ALGORITHM, masterKey, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(data.ciphertext, 'base64', 'utf8');
  decrypted += decipher.final('utf8');

  return '0x' + decrypted;
}

// ─── Wallet Generation ───────────────────────────────────────────────────
//
// Generates Ethereum-compatible wallet using ethers.js.
// Uses Keccak-256 for correct address derivation (NOT SHA-256 or SHA3-256).
// Private key → secp256k1 public key → Keccak-256 → last 20 bytes = address
//
// ethers.Wallet.createRandom() handles all of this correctly:
//   - Cryptographically secure random private key
//   - secp256k1 public key derivation
//   - Keccak-256 address derivation with EIP-55 checksum

export function generateWallet(): {
  address: string;
  privateKey: string;
  encryptedKey: EncryptedKeyData;
} {
  // ethers.js handles: random key → secp256k1 → keccak256 → EIP-55 checksum
  const wallet = Wallet.createRandom();
  const address = wallet.address;   // EIP-55 checksummed, keccak256-derived
  const privateKey = wallet.privateKey; // 0x-prefixed hex

  // Encrypt private key for storage
  const encryptedKey = encryptPrivateKey(privateKey);

  return { address, privateKey, encryptedKey };
}

// ─── Wallet Export ───────────────────────────────────────────────────────

export function exportWallet(encryptedKeyJson: string): WalletExportResult {
  const data: EncryptedKeyData = JSON.parse(encryptedKeyJson);
  const privateKey = decryptPrivateKey(data);

  // Derive address using ethers.js (correct Keccak-256 derivation)
  const address = computeAddress(privateKey);

  return {
    address,
    privateKey,
    warning:
      'WARNING: This is your private key. Anyone with this key has full control of your wallet. ' +
      'Store it securely. NeuralPost will no longer be responsible for this wallet once exported. ' +
      'Import this key into MetaMask or any Ethereum-compatible wallet.',
  };
}

// ─── Wallet Info (without exposing private key) ──────────────────────────

export function getWalletInfo(
  address: string,
  custodyType: string,
  createdAt: string,
  exportedAt: string | null,
  chainId: number | null,
): CustodialWallet {
  return {
    address,
    custodyType: (custodyType || 'protocol') as CustodialWallet['custodyType'],
    createdAt,
    exportedAt: exportedAt || undefined,
    chainIds: chainId ? [chainId] : [PRIMARY_CHAIN as number],
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────

/**
 * Generate a master encryption key (run once during setup)
 */
export function generateMasterKey(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Validate that a hex string is a valid private key format
 */
export function isValidPrivateKey(key: string): boolean {
  const hex = key.startsWith('0x') ? key.slice(2) : key;
  return /^[a-fA-F0-9]{64}$/.test(hex);
}
