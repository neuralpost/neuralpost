// ═══════════════════════════════════════════════════════════════════════════
// NEURALPOST CRYPTO TYPES
// Multi-chain: Base Sepolia (primary) + SKALE + Ethereum L2s + Ethereum
// ERC-8004 (Trustless Agents) compliant — official contract addresses
// Custodial wallets with private key export
// ═══════════════════════════════════════════════════════════════════════════

// ─── Chain IDs ───────────────────────────────────────────────────────────

export type SupportedChainId =
  // SKALE Mainnet Hubs
  | 1564830818    // Calypso (NFTs — future, needs DEPLOYER_ROLE)
  | 2046399126    // Europa (DeFi/Liquidity)
  | 1482601649    // Nebula (Gaming)
  | 1350216234    // Titan (Multi-use)
  // SKALE on Base (zero gas + x402 + BITE encryption)
  | 1187947933    // SKALE Base Mainnet (CREDIT chain)
  // Ethereum L2s
  | 8453          // Base
  | 42161         // Arbitrum One
  | 10            // Optimism
  // Ethereum
  | 1             // Ethereum Mainnet
  // Testnets
  | 103698795     // BITE V2 Sandbox (x402 + encrypted txs)
  | 324705682     // SKALE Base Sepolia (permissionless testnet)
  | 974399131     // SKALE Calypso Testnet
  | 84532         // Base Sepolia (ERC-8004 deployed here)
  | 421614        // Arbitrum Sepolia
  | 11155420      // Optimism Sepolia
  | 11155111;     // Ethereum Sepolia

export type ChainFamily = 'skale' | 'ethereum-l2' | 'ethereum';

export interface ChainConfig {
  chainId: SupportedChainId;
  name: string;
  family: ChainFamily;
  rpcUrl: string;
  wsUrl?: string;
  blockExplorer: string;
  contracts: {
    identityRegistry: string;    // ERC-8004 Identity Registry (ERC-721)
    reputationRegistry: string;  // ERC-8004 Reputation Registry
    escrow: string;
    usdc: string;
  };
  isTestnet: boolean;
  zeroGas: boolean;         // SKALE = true (no gas cost)
  nativeCurrency: string;   // sFUEL for SKALE, ETH for others
}

// ─── ERC-8004 Official Contract Addresses ───────────────────────────────
// Source: https://github.com/erc-8004/erc-8004-contracts (curated by 8004 team)
// Deterministic CREATE2 deployment: SAME addresses on ALL mainnets, SAME on ALL testnets
// Verified from official README (Feb 2026 — deployed on 20+ chains)

export const ERC8004_CONTRACTS = {
  // ALL mainnets (ETH, Base, Arbitrum, Optimism, Polygon, Scroll, Monad, BSC, etc.)
  mainnet: {
    identityRegistry: '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432',
    reputationRegistry: '0x8004BAa17C55a88189AE136b182e5fdA19dE9b63',
  },
  // ALL testnets (ETH Sepolia, Base Sepolia, Arbitrum Testnet, Polygon Amoy, etc.)
  testnet: {
    identityRegistry: '0x8004A818BFB912233c491871b3d84c89A494BD9e',
    reputationRegistry: '0x8004B663056A597Dffe9eCcC1965A193B7388713',
  },
} as const;

// ─── SKALE Chains (Zero Gas — future deployment, needs DEPLOYER_ROLE) ───

export const SKALE_CALYPSO: ChainConfig = {
  chainId: 1564830818,
  name: 'SKALE Calypso',
  family: 'skale',
  rpcUrl: process.env.SKALE_CALYPSO_RPC || 'https://mainnet.skalenodes.com/v1/honorable-steel-rasalhague',
  wsUrl: 'wss://mainnet.skalenodes.com/v1/ws/honorable-steel-rasalhague',
  blockExplorer: 'https://honorable-steel-rasalhague.explorer.mainnet.skalenodes.com',
  contracts: {
    identityRegistry: process.env.SKALE_IDENTITY_REGISTRY || '',
    reputationRegistry: process.env.SKALE_REPUTATION_REGISTRY || '',
    escrow: process.env.SKALE_ESCROW || '',
    usdc: '',  // USDC bridged via IMA
  },
  isTestnet: false,
  zeroGas: true,
  nativeCurrency: 'sFUEL',
};

export const SKALE_EUROPA: ChainConfig = {
  chainId: 2046399126,
  name: 'SKALE Europa',
  family: 'skale',
  rpcUrl: process.env.SKALE_EUROPA_RPC || 'https://mainnet.skalenodes.com/v1/elated-tan-skat',
  wsUrl: 'wss://mainnet.skalenodes.com/v1/ws/elated-tan-skat',
  blockExplorer: 'https://elated-tan-skat.explorer.mainnet.skalenodes.com',
  contracts: { identityRegistry: '', reputationRegistry: '', escrow: '', usdc: '' },
  isTestnet: false,
  zeroGas: true,
  nativeCurrency: 'sFUEL',
};

export const SKALE_NEBULA: ChainConfig = {
  chainId: 1482601649,
  name: 'SKALE Nebula',
  family: 'skale',
  rpcUrl: process.env.SKALE_NEBULA_RPC || 'https://mainnet.skalenodes.com/v1/green-giddy-denebola',
  blockExplorer: 'https://green-giddy-denebola.explorer.mainnet.skalenodes.com',
  contracts: { identityRegistry: '', reputationRegistry: '', escrow: '', usdc: '' },
  isTestnet: false,
  zeroGas: true,
  nativeCurrency: 'sFUEL',
};

export const SKALE_TITAN: ChainConfig = {
  chainId: 1350216234,
  name: 'SKALE Titan',
  family: 'skale',
  rpcUrl: process.env.SKALE_TITAN_RPC || 'https://mainnet.skalenodes.com/v1/parallel-stormy-spica',
  blockExplorer: 'https://parallel-stormy-spica.explorer.mainnet.skalenodes.com',
  contracts: { identityRegistry: '', reputationRegistry: '', escrow: '', usdc: '' },
  isTestnet: false,
  zeroGas: true,
  nativeCurrency: 'sFUEL',
};

// ─── SKALE on Base (Zero Gas + x402 + BITE encryption) ──────────────────

export const SKALE_BASE_MAINNET: ChainConfig = {
  chainId: 1187947933,
  name: 'SKALE Base',
  family: 'skale',
  rpcUrl: process.env.SKALE_BASE_RPC || 'https://skale-base.skalenodes.com/v1/base',
  wsUrl: 'wss://skale-base.skalenodes.com/v1/ws/base',
  blockExplorer: 'https://skale-base-explorer.skalenodes.com',
  contracts: {
    // ERC-8004 — to be deployed via CREATE2 (canonical factory available)
    identityRegistry: process.env.SKALE_BASE_IDENTITY_REGISTRY || '',
    reputationRegistry: process.env.SKALE_BASE_REPUTATION_REGISTRY || '',
    escrow: '',
    usdc: '0x85889c8c714505E0c94b30fcfcF64fE3Ac8FCb20',  // USDC.e bridged from Base
  },
  isTestnet: false,
  zeroGas: true,
  nativeCurrency: 'CREDIT',
};

// ─── Ethereum L2 Chains ──────────────────────────────────────────────────

export const BASE_MAINNET: ChainConfig = {
  chainId: 8453,
  name: 'Base',
  family: 'ethereum-l2',
  rpcUrl: process.env.BASE_RPC_URL || 'https://mainnet.base.org',
  blockExplorer: 'https://basescan.org',
  contracts: {
    // Official ERC-8004 contracts — same mainnet addresses on ALL mainnets (CREATE2)
    identityRegistry: ERC8004_CONTRACTS.mainnet.identityRegistry,
    reputationRegistry: ERC8004_CONTRACTS.mainnet.reputationRegistry,
    escrow: process.env.BASE_ESCROW || '',
    usdc: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  },
  isTestnet: false,
  zeroGas: false,
  nativeCurrency: 'ETH',
};

export const ARBITRUM_ONE: ChainConfig = {
  chainId: 42161,
  name: 'Arbitrum One',
  family: 'ethereum-l2',
  rpcUrl: process.env.ARBITRUM_RPC_URL || 'https://arb1.arbitrum.io/rpc',
  blockExplorer: 'https://arbiscan.io',
  contracts: {
    // Official ERC-8004 contracts — same mainnet addresses on ALL mainnets (CREATE2)
    identityRegistry: ERC8004_CONTRACTS.mainnet.identityRegistry,
    reputationRegistry: ERC8004_CONTRACTS.mainnet.reputationRegistry,
    escrow: process.env.ARB_ESCROW || '',
    usdc: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831',
  },
  isTestnet: false,
  zeroGas: false,
  nativeCurrency: 'ETH',
};

export const OPTIMISM: ChainConfig = {
  chainId: 10,
  name: 'Optimism',
  family: 'ethereum-l2',
  rpcUrl: process.env.OPTIMISM_RPC_URL || 'https://mainnet.optimism.io',
  blockExplorer: 'https://optimistic.etherscan.io',
  contracts: {
    // Official ERC-8004 contracts — same mainnet addresses on ALL mainnets (CREATE2)
    identityRegistry: ERC8004_CONTRACTS.mainnet.identityRegistry,
    reputationRegistry: ERC8004_CONTRACTS.mainnet.reputationRegistry,
    escrow: process.env.OP_ESCROW || '',
    usdc: '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85',
  },
  isTestnet: false,
  zeroGas: false,
  nativeCurrency: 'ETH',
};

// ─── Ethereum Mainnet ────────────────────────────────────────────────────

export const ETHEREUM_MAINNET: ChainConfig = {
  chainId: 1,
  name: 'Ethereum',
  family: 'ethereum',
  rpcUrl: process.env.ETH_RPC_URL || '',
  blockExplorer: 'https://etherscan.io',
  contracts: {
    // Official ERC-8004 contracts — same mainnet addresses on ALL mainnets (CREATE2)
    identityRegistry: ERC8004_CONTRACTS.mainnet.identityRegistry,
    reputationRegistry: ERC8004_CONTRACTS.mainnet.reputationRegistry,
    escrow: '',
    usdc: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
  },
  isTestnet: false,
  zeroGas: false,
  nativeCurrency: 'ETH',
};

// ─── Testnets ────────────────────────────────────────────────────────────

// ── SKALE Network Chains (SKALE Network) ──────────────
// Source: docs.skale.space — SKALE Network Guide
// Both are zero-gas, permissionless testnets with x402 + BITE support

export const BITE_V2_SANDBOX: ChainConfig = {
  chainId: 103698795,
  name: 'BITE V2 Sandbox',
  family: 'skale',
  rpcUrl: process.env.BITE_V2_RPC || 'https://base-sepolia-testnet.skalenodes.com/v1/bite-v2-sandbox',
  blockExplorer: 'https://base-sepolia-testnet-explorer.skalenodes.com:10032',
  contracts: {
    // Deploy ERC-8004 here — EVM version Istanbul required
    identityRegistry: process.env.BITE_IDENTITY_REGISTRY || '',
    reputationRegistry: process.env.BITE_REPUTATION_REGISTRY || '',
    escrow: '',
    usdc: '0xc4083B1E81ceb461Ccef3FDa8A9F24F0d764B6D8',  // USDC on BITE V2
  },
  isTestnet: true,
  zeroGas: true,
  nativeCurrency: 'sFUEL',
};

export const SKALE_BASE_SEPOLIA: ChainConfig = {
  chainId: 324705682,
  name: 'SKALE Base Sepolia',
  family: 'skale',
  rpcUrl: process.env.SKALE_BASE_SEPOLIA_RPC || 'https://base-sepolia-testnet.skalenodes.com/v1/jubilant-horrible-ancha',
  blockExplorer: 'https://base-sepolia-testnet-explorer.skalenodes.com',
  contracts: {
    // Deploy ERC-8004 here — permissionless, CREATE2Factory available
    identityRegistry: process.env.SKALE_BASE_SEP_IDENTITY_REGISTRY || '',
    reputationRegistry: process.env.SKALE_BASE_SEP_REPUTATION_REGISTRY || '',
    escrow: '',
    usdc: '0x2e08028E3C4c2356572E096d8EF835cD5C6030bD',  // Bridged USDC from Base Sepolia
  },
  isTestnet: true,
  zeroGas: true,
  nativeCurrency: 'CREDIT',
};

export const SKALE_CALYPSO_TESTNET: ChainConfig = {
  chainId: 974399131,
  name: 'SKALE Calypso Testnet',
  family: 'skale',
  rpcUrl: process.env.SKALE_TESTNET_RPC || 'https://testnet.skalenodes.com/v1/giant-half-dual-testnet',
  blockExplorer: 'https://giant-half-dual-testnet.explorer.testnet.skalenodes.com',
  contracts: {
    identityRegistry: '',
    reputationRegistry: '',
    escrow: '',
    usdc: '',
  },
  isTestnet: true,
  zeroGas: true,
  nativeCurrency: 'sFUEL',
};

export const BASE_SEPOLIA: ChainConfig = {
  chainId: 84532,
  name: 'Base Sepolia',
  family: 'ethereum-l2',
  rpcUrl: process.env.BASE_SEPOLIA_RPC || 'https://sepolia.base.org',
  blockExplorer: 'https://sepolia.basescan.org',
  contracts: {
    // Official ERC-8004 contracts — same testnet addresses on ALL testnets (CREATE2)
    identityRegistry: ERC8004_CONTRACTS.testnet.identityRegistry,
    reputationRegistry: ERC8004_CONTRACTS.testnet.reputationRegistry,
    escrow: '',
    usdc: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
  },
  isTestnet: true,
  zeroGas: false,
  nativeCurrency: 'ETH',
};

export const ARBITRUM_SEPOLIA: ChainConfig = {
  chainId: 421614,
  name: 'Arbitrum Sepolia',
  family: 'ethereum-l2',
  rpcUrl: process.env.ARB_SEPOLIA_RPC || 'https://sepolia-rollup.arbitrum.io/rpc',
  blockExplorer: 'https://sepolia.arbiscan.io',
  contracts: {
    // Official ERC-8004 contracts — same testnet addresses on ALL testnets (CREATE2)
    identityRegistry: ERC8004_CONTRACTS.testnet.identityRegistry,
    reputationRegistry: ERC8004_CONTRACTS.testnet.reputationRegistry,
    escrow: '',
    usdc: '',
  },
  isTestnet: true,
  zeroGas: false,
  nativeCurrency: 'ETH',
};

export const OPTIMISM_SEPOLIA: ChainConfig = {
  chainId: 11155420,
  name: 'Optimism Sepolia',
  family: 'ethereum-l2',
  rpcUrl: process.env.OP_SEPOLIA_RPC || 'https://sepolia.optimism.io',
  blockExplorer: 'https://sepolia-optimistic.etherscan.io',
  contracts: {
    // Official ERC-8004 contracts — same testnet addresses on ALL testnets (CREATE2)
    identityRegistry: ERC8004_CONTRACTS.testnet.identityRegistry,
    reputationRegistry: ERC8004_CONTRACTS.testnet.reputationRegistry,
    escrow: '',
    usdc: '',
  },
  isTestnet: true,
  zeroGas: false,
  nativeCurrency: 'ETH',
};

export const ETHEREUM_SEPOLIA: ChainConfig = {
  chainId: 11155111,
  name: 'Ethereum Sepolia',
  family: 'ethereum',
  rpcUrl: process.env.SEPOLIA_RPC_URL || '',
  blockExplorer: 'https://sepolia.etherscan.io',
  contracts: {
    // Official ERC-8004 contracts — same testnet addresses on ALL testnets (CREATE2)
    identityRegistry: ERC8004_CONTRACTS.testnet.identityRegistry,
    reputationRegistry: ERC8004_CONTRACTS.testnet.reputationRegistry,
    escrow: '',
    usdc: '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238',
  },
  isTestnet: true,
  zeroGas: false,
  nativeCurrency: 'ETH',
};

// ─── Chain Registry ──────────────────────────────────────────────────────

export const CHAIN_CONFIGS: Record<number, ChainConfig> = {
  // SKALE
  1564830818: SKALE_CALYPSO,
  2046399126: SKALE_EUROPA,
  1482601649: SKALE_NEBULA,
  1350216234: SKALE_TITAN,
  1187947933: SKALE_BASE_MAINNET,
  // L2s
  8453: BASE_MAINNET,
  42161: ARBITRUM_ONE,
  10: OPTIMISM,
  // Ethereum
  1: ETHEREUM_MAINNET,
  // Testnets — SKALE Network
  103698795: BITE_V2_SANDBOX,
  324705682: SKALE_BASE_SEPOLIA,
  974399131: SKALE_CALYPSO_TESTNET,
  // Testnets — L2
  84532: BASE_SEPOLIA,
  421614: ARBITRUM_SEPOLIA,
  11155420: OPTIMISM_SEPOLIA,
  11155111: ETHEREUM_SEPOLIA,
};

// Primary chain for ERC-8004 mint (Base Sepolia — official ERC-8004 contracts deployed)
export const PRIMARY_CHAIN: SupportedChainId = 84532;
// Fallback L2 for USDC payments
export const PAYMENT_CHAIN: SupportedChainId = 8453;

// ─── SKALE Network Config ─────────────────────────────────────────────
// Primary: BITE V2 Sandbox (x402 + BITE encryption, zero gas)
// Fallback: SKALE Base Sepolia (permissionless, zero gas, more facilitators)
export const SKALE_MINT_CHAIN: SupportedChainId = 103698795;  // BITE V2 Sandbox
export const SKALE_PAYMENT_CHAIN: SupportedChainId = 324705682;  // SKALE Base Sepolia

// Kobaru facilitator for SKALE x402 payments (recommended)
export const SKALE_FACILITATOR_URL = 'https://gateway.kobaru.io';

// x402 payment tokens on SKALE
export const SKALE_PAYMENT_TOKENS = {
  // BITE V2 Sandbox
  biteUsdc: '0xc4083B1E81ceb461Ccef3FDa8A9F24F0d764B6D8',
  // SKALE Base Sepolia
  axiosUsd: '0x61a26022927096f444994dA1e53F0FD9487EAfcf',       // Axios USD (6 decimals)
  bridgedUsdc: '0x2e08028E3C4c2356572E096d8EF835cD5C6030bD',    // Bridged USDC (6 decimals)
  // SKALE Base Mainnet
  mainnetUsdc: '0x85889c8c714505E0c94b30fcfcF64fE3Ac8FCb20',    // USDC.e bridged from Base
} as const;

// ─── Custodial Wallet Types ──────────────────────────────────────────────

export type WalletCustodyType = 'protocol' | 'self' | 'hybrid';

export interface CustodialWallet {
  address: string;
  custodyType: WalletCustodyType;
  createdAt: string;
  exportedAt?: string;     // When private key was first exported
  chainIds: number[];      // Chains this wallet is active on
}

export interface WalletExportResult {
  address: string;
  privateKey: string;      // Hex, 0x-prefixed
  warning: string;
}

export interface EncryptedKeyData {
  iv: string;              // Base64
  authTag: string;         // Base64
  ciphertext: string;      // Base64
  algorithm: 'aes-256-gcm';
}

// ─── Sponsored Mint Types ────────────────────────────────────────────────

export interface SponsoredMintRequest {
  agentId: string;         // NeuralPost agent UUID
  domain: string;
  walletAddress: string;
  registrationURI: string;
  chainId: SupportedChainId;
}

export interface SponsoredMintResult {
  success: boolean;
  tokenId?: number;
  txHash?: string;
  chainId: SupportedChainId;
  error?: string;
}

// ─── SIWE Types ──────────────────────────────────────────────────────────

export interface SIWEMessage {
  domain: string;
  address: string;
  statement: string;
  uri: string;
  version: string;
  chainId: number;
  nonce: string;
  issuedAt: string;
  expirationTime?: string;
}

export interface SIWEVerifyResult {
  valid: boolean;
  address: string;
  chainId: number;
}

// ─── On-chain Agent Identity ─────────────────────────────────────────────

export interface OnChainAgentIdentity {
  agentId: number;
  walletAddress: string;
  chainId: SupportedChainId;
  registryAddress: string;
  registrationURI: string;
  reputationScore: number;
  registrationTxHash: string;
  active: boolean;
}

// ─── ERC-8004 Registration File ──────────────────────────────────────────
// Per official spec: https://eips.ethereum.org/EIPS/eip-8004

export interface ERC8004RegistrationFile {
  type: 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1';
  name: string;
  description: string;
  image?: string;
  services: ERC8004Service[];              // Official spec field name is 'services'
  x402Support: boolean;                     // Official spec includes this
  active: boolean;                          // Official spec includes this
  registrations?: ERC8004Registration[];    // Cross-chain registrations
  supportedTrust?: string[];                // e.g. ['reputation', 'crypto-economic', 'tee-attestation']
}

export interface ERC8004Service {
  name: 'A2A' | 'MCP' | 'web' | 'OASF' | 'ENS' | 'DID' | 'email' | 'webhook' | string;
  endpoint: string;
  version?: string;
  skills?: string[];
  domains?: string[];
}

export interface ERC8004Registration {
  agentId: number;
  agentRegistry: string;   // e.g. 'eip155:84532:0x8004A818...' (testnet) or 'eip155:8453:0x8004A169...' (mainnet)
  owner?: string;
  createdAt?: string;
}

// ─── Payment Types (x402 / USDC) ────────────────────────────────────────

// ─── x402 Protocol v2 Types (per x402-specification-v2.md + @x402/core SDK) ──
// Source: github.com/coinbase/x402/specs/x402-specification-v2.md
//         github.com/coinbase/x402/typescript/packages/core/src/types/
// These types are transport-agnostic and scheme-agnostic.

// CAIP-2 Network identifier (enforces colon-separated format at compile time)
// Examples: "eip155:8453" (Base), "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" (Solana mainnet)
export type X402Network = `${string}:${string}`;

export interface X402ResourceInfo {
  url: string;                              // URL of the protected resource
  description?: string;                     // Human-readable description (spec: Optional, SDK: required)
  mimeType?: string;                        // MIME type of expected response (spec: Optional, SDK: required)
}

export interface X402PaymentRequirements {
  scheme: 'exact' | string;                 // Payment scheme (e.g. "exact")
  network: X402Network;                     // CAIP-2 format (e.g. "eip155:8453")
  amount: string;                           // Required payment in atomic token units
  asset: string;                            // Token contract address or ISO 4217 code
  payTo: string;                            // Recipient wallet address
  maxTimeoutSeconds: number;                // Max time for payment completion
  extra?: {                                 // Scheme-specific info (spec: Optional)
    name?: string;                          // e.g. "USDC"
    version?: string;                       // e.g. "2"
    // EVM: { name, version, assetTransferMethod? }
    // SVM: { feePayer: string }
    // Sui: { gasStation?: string }
    // Stellar: { areFeesSponsored: boolean }
    // Hedera: { feePayer: string }
    // Aptos: { sponsored?: boolean }
    // Algorand: { feePayer?: string }
    [key: string]: unknown;
  };
}

export interface X402PaymentRequired {
  x402Version: number;                      // Protocol version (currently 2; SDK uses number not literal)
  error?: string;                           // Human-readable error message
  resource: X402ResourceInfo;
  accepts: X402PaymentRequirements[];       // Acceptable payment methods
  extensions?: Record<string, unknown>;
}

// ─── EVM-specific payload (EIP-3009 transferWithAuthorization) ──────────
export interface X402EVMAuthorization {
  from: string;                             // Payer's wallet address
  to: string;                               // Recipient wallet address
  value: string;                            // Payment amount in atomic units
  validAfter: string;                       // Unix timestamp
  validBefore: string;                      // Unix timestamp
  nonce: string;                            // 32-byte random nonce (EIP-3009)
}

export interface X402EVMPayload {
  signature: string;                        // EIP-712 signature
  authorization: X402EVMAuthorization;      // EIP-3009 authorization
}

// ─── SVM-specific payload (Solana TransferChecked) ─────────────────────
export interface X402SVMPayload {
  transaction: string;                      // Base64-encoded partially-signed versioned Solana tx
}

// ─── Generic PaymentPayload (transport + scheme agnostic) ──────────────
export interface X402PaymentPayload {
  x402Version: number;                      // Protocol version (SDK: number, not literal 2)
  resource?: X402ResourceInfo;
  accepted: X402PaymentRequirements;        // The chosen payment method
  payload: Record<string, unknown>;         // Scheme-specific — generic per official SDK
  // EVM exact:    { signature, authorization }
  // SVM exact:    { transaction }
  // Sui exact:    { signature, transaction }
  // Stellar:      { transaction }
  // Hedera:       { transaction }
  // Aptos:        { transaction }
  // Algorand:     { paymentIndex, paymentGroup }
  extensions?: Record<string, unknown>;
}

// Helper: Narrow PaymentPayload to EVM-specific shape
export interface X402EVMPaymentPayload extends Omit<X402PaymentPayload, 'payload'> {
  payload: X402EVMPayload;
}

export interface X402SettlementResponse {
  success: boolean;
  errorReason?: string;                     // Error code if success=false
  errorMessage?: string;                    // Human-readable error detail (per SDK)
  transaction: string;                      // Tx hash (empty string if failed)
  network: X402Network;                     // CAIP-2 format
  payer?: string;                           // Payer wallet address
  extensions?: Record<string, unknown>;
}

export interface X402VerifyResponse {
  isValid: boolean;
  invalidReason?: string;                   // Error code if isValid=false
  invalidMessage?: string;                  // Human-readable error detail (per SDK)
  payer?: string;
  extensions?: Record<string, unknown>;     // Extension data (per SDK)
}

// ─── x402 Transport Constants ───────────────────────────────────────────
// HTTP: PAYMENT-REQUIRED / PAYMENT-SIGNATURE / PAYMENT-RESPONSE headers (v2)
// MCP:  _meta["x402/payment"] / _meta["x402/payment-response"]
// A2A:  metadata x402.payment.status / x402.payment.payload / x402.payment.receipts
export const X402_TRANSPORT = {
  http: {
    headers: {
      paymentRequired: 'PAYMENT-REQUIRED',    // Server → Client (base64)
      paymentSignature: 'PAYMENT-SIGNATURE',  // Client → Server (base64)
      paymentResponse: 'PAYMENT-RESPONSE',    // Server → Client (base64)
    },
  },
  mcp: {
    metaKeys: {
      payment: 'x402/payment',               // Client → Server
      paymentResponse: 'x402/payment-response', // Server → Client
    },
  },
  a2a: {
    metadataKeys: {
      status: 'x402.payment.status',
      required: 'x402.payment.required',
      payload: 'x402.payment.payload',
      receipts: 'x402.payment.receipts',
      error: 'x402.payment.error',
    },
    statusValues: ['payment-required', 'payment-rejected', 'payment-submitted',
                   'payment-verified', 'payment-completed', 'payment-failed'] as const,
  },
  facilitator: {
    cdpUrl: 'https://x402.org/facilitator',   // Coinbase CDP facilitator (testnet)
    kobaruUrl: 'https://gateway.kobaru.io',    // Kobaru facilitator (SKALE — recommended)
    endpoints: {
      verify: '/verify',
      settle: '/settle',
      supported: '/supported',
    },
  },
} as const;

// ─── Legacy Payment Types ───────────────────────────────────────────────

export interface PaymentProof {
  txHash: string;
  chainId: SupportedChainId;
  fromAddress: string;
  toAddress: string;
  amount: string;
  token: string;
  timestamp: string;
}

export interface EscrowInfo {
  escrowId: string;
  taskId: string;
  clientAgent: string;
  serverAgent: string;
  token: string;
  amount: string;
  feeBps: number;
  createdAt: number;
  expiresAt: number;
  status: 'Active' | 'Completed' | 'Failed' | 'Canceled' | 'Expired' | 'Disputed';
}

// ─── ERC-8004 Official Contract ABIs ────────────────────────────────────
// Source: https://eips.ethereum.org/EIPS/eip-8004 + erc-8004/erc-8004-contracts

// Identity Registry (ERC-721 based — IdentityRegistryUpgradeable.sol)
export const IDENTITY_REGISTRY_ABI = [
  // Registration functions (3 overloads)
  'function register(string agentURI, tuple(string metadataKey, bytes metadataValue)[] metadata) external returns (uint256)',
  'function register(string agentURI) external returns (uint256)',
  'function register() external returns (uint256)',
  // URI management
  'function setAgentURI(uint256 agentId, string newURI) external',
  // On-chain metadata (spec extension)
  'function getMetadata(uint256 agentId, string metadataKey) external view returns (bytes)',
  'function setMetadata(uint256 agentId, string metadataKey, bytes metadataValue) external',
  // Agent wallet (EIP-712 / ERC-1271 verified)
  'function setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes signature) external',
  'function getAgentWallet(uint256 agentId) external view returns (address)',
  'function unsetAgentWallet(uint256 agentId) external',
  // Authorization check (used by ReputationRegistry for self-feedback prevention)
  'function isAuthorizedOrOwner(address spender, uint256 agentId) external view returns (bool)',
  // Version
  'function getVersion() external pure returns (string)',
  // ERC-721 standard
  'function tokenURI(uint256 tokenId) view returns (string)',
  'function ownerOf(uint256 tokenId) view returns (address)',
  'function balanceOf(address owner) view returns (uint256)',
  'function transferFrom(address from, address to, uint256 tokenId) external',
  'function safeTransferFrom(address from, address to, uint256 tokenId) external',
  'function safeTransferFrom(address from, address to, uint256 tokenId, bytes data) external',
  'function approve(address to, uint256 tokenId) external',
  'function setApprovalForAll(address operator, bool approved) external',
  'function getApproved(uint256 tokenId) view returns (address)',
  'function isApprovedForAll(address owner, address operator) view returns (bool)',
  'function name() view returns (string)',
  'function symbol() view returns (string)',
  'function supportsInterface(bytes4 interfaceId) view returns (bool)',
  // Events (per spec)
  'event Registered(uint256 indexed agentId, string agentURI, address indexed owner)',
  'event URIUpdated(uint256 indexed agentId, string newURI, address indexed updatedBy)',
  'event MetadataSet(uint256 indexed agentId, string indexed indexedMetadataKey, string metadataKey, bytes metadataValue)',
  'event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)',
] as const;

// Reputation Registry (ReputationRegistryUpgradeable.sol)
// NOTE: tag1 and tag2 are STRING per spec, not bytes32
export const REPUTATION_REGISTRY_ABI = [
  'function giveFeedback(uint256 agentId, int128 value, uint8 valueDecimals, string tag1, string tag2, string endpoint, string feedbackURI, bytes32 feedbackHash) external',
  'function revokeFeedback(uint256 agentId, uint64 feedbackIndex) external',
  'function appendResponse(uint256 agentId, address clientAddress, uint64 feedbackIndex, string responseURI, bytes32 responseHash) external',
  'function getSummary(uint256 agentId, address[] clientAddresses, string tag1, string tag2) external view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals)',
  'function readFeedback(uint256 agentId, address clientAddress, uint64 feedbackIndex) external view returns (int128 value, uint8 valueDecimals, string tag1, string tag2, bool isRevoked)',
  'function readAllFeedback(uint256 agentId, address[] clientAddresses, string tag1, string tag2, bool includeRevoked) external view returns (address[] clients, uint64[] feedbackIndexes, int128[] values, uint8[] valueDecimals, string[] tag1s, string[] tag2s, bool[] revokedStatuses)',
  'function getResponseCount(uint256 agentId, address clientAddress, uint64 feedbackIndex, address[] responders) external view returns (uint64 count)',
  'function getClients(uint256 agentId) external view returns (address[])',
  'function getLastIndex(uint256 agentId, address clientAddress) external view returns (uint64)',
  'function getIdentityRegistry() view returns (address)',
  'function getVersion() external pure returns (string)',
  // Events (per spec)
  'event NewFeedback(uint256 indexed agentId, address indexed clientAddress, uint64 feedbackIndex, int128 value, uint8 valueDecimals, string indexed indexedTag1, string tag1, string tag2, string endpoint, string feedbackURI, bytes32 feedbackHash)',
  'event FeedbackRevoked(uint256 indexed agentId, address indexed clientAddress, uint64 indexed feedbackIndex)',
  'event ResponseAppended(uint256 indexed agentId, address indexed clientAddress, uint64 feedbackIndex, address indexed responder, string responseURI, bytes32 responseHash)',
] as const;

// LEGACY: Keep old name as alias for backward compatibility during migration
export const REGISTRY_ABI = IDENTITY_REGISTRY_ABI;

// Validation Registry (ValidationRegistryUpgradeable.sol)
// 3rd core ERC-8004 registry — for stake-secured re-execution, zkML, TEE oracles
// NOTE: Not yet deployed on public chains per official README (contract exists in repo)
export const VALIDATION_REGISTRY_ABI = [
  'function validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash) external',
  'function validationResponse(bytes32 requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag) external',
  'function getValidationStatus(bytes32 requestHash) external view returns (address validatorAddress, uint256 agentId, uint8 response, bytes32 responseHash, string tag, uint256 lastUpdate)',
  'function getSummary(uint256 agentId, address[] validatorAddresses, string tag) external view returns (uint64 count, uint8 avgResponse)',
  'function getAgentValidations(uint256 agentId) external view returns (bytes32[])',
  'function getValidatorRequests(address validatorAddress) external view returns (bytes32[])',
  'function getIdentityRegistry() view returns (address)',
  'function getVersion() external pure returns (string)',
  // Events
  'event ValidationRequest(address indexed validatorAddress, uint256 indexed agentId, string requestURI, bytes32 indexed requestHash)',
  'event ValidationResponse(address indexed validatorAddress, uint256 indexed agentId, bytes32 indexed requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag)',
] as const;

export const ESCROW_ABI = [
  'function createEscrow(bytes32 taskId, address serverAgent, address token, uint256 amount, uint256 duration) returns (bytes32)',
  'function completeEscrow(bytes32 escrowId)',
  'function refundEscrow(bytes32 escrowId, string reason)',
  'function reclaimExpired(bytes32 escrowId)',
  'function escrows(bytes32) view returns (bytes32 taskId, address clientAgent, address serverAgent, address token, uint256 amount, uint256 feeBps, uint256 createdAt, uint256 expiresAt, uint8 status)',
  'event EscrowCreated(bytes32 indexed escrowId, bytes32 indexed taskId, address client, address server, uint256 amount)',
  'event EscrowCompleted(bytes32 indexed escrowId, uint256 payout, uint256 fee)',
] as const;

export const ERC20_ABI = [
  'function balanceOf(address) view returns (uint256)',
  'function allowance(address,address) view returns (uint256)',
  'function approve(address,uint256) returns (bool)',
  'function transfer(address,uint256) returns (bool)',
  'function decimals() view returns (uint8)',
] as const;
