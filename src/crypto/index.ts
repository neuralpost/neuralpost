// Blockchain service
export {
  generateSIWENonce, consumeSIWENonce,
  parseSIWEMessage, verifySIWESignature,
  generateRegistrationFile,
  getOnChainAgent, getOnChainAgentById, getOnChainReputation,
  verifyPaymentProof, getEscrowForTask,
  taskIdToBytes32, getChainConfig,
  isValidEthAddress, getGlobalAgentId,
  getBlockchainStatus,
} from './blockchain';

// Custodial wallet service
export {
  generateWallet,
  encryptPrivateKey, decryptPrivateKey,
  exportWallet,
  getWalletInfo,
  generateMasterKey,
  isValidPrivateKey,
} from './wallet';

// Sponsored mint service
export {
  sponsoredMint,
  autoMintOnRegister,
  multiChainMint,
  distributeSFuel,
  getMintStatus, getMintStats,
  selectMintChain,
} from './sponsor';

// Types
export {
  type SupportedChainId, type ChainConfig, type ChainFamily,
  type CustodialWallet, type WalletCustodyType, type WalletExportResult, type EncryptedKeyData,
  type SponsoredMintRequest, type SponsoredMintResult,
  type OnChainAgentIdentity,
  type ERC8004RegistrationFile, type ERC8004Service, type ERC8004Registration,
  type PaymentProof, type EscrowInfo,
  type X402Network, type X402ResourceInfo, type X402PaymentRequirements, type X402PaymentRequired,
  type X402EVMAuthorization, type X402EVMPayload, type X402SVMPayload,
  type X402PaymentPayload, type X402EVMPaymentPayload,
  type X402SettlementResponse, type X402VerifyResponse,
  type SIWEMessage, type SIWEVerifyResult,
  CHAIN_CONFIGS, PRIMARY_CHAIN, PAYMENT_CHAIN,
  SKALE_MINT_CHAIN, SKALE_PAYMENT_CHAIN, SKALE_FACILITATOR_URL, SKALE_PAYMENT_TOKENS,
  ERC8004_CONTRACTS,
  SKALE_CALYPSO, SKALE_EUROPA, SKALE_NEBULA, SKALE_TITAN,
  SKALE_BASE_MAINNET, BITE_V2_SANDBOX, SKALE_BASE_SEPOLIA,
  BASE_MAINNET, BASE_SEPOLIA, ARBITRUM_ONE, OPTIMISM,
  ETHEREUM_MAINNET, ETHEREUM_SEPOLIA,
  IDENTITY_REGISTRY_ABI, REPUTATION_REGISTRY_ABI, VALIDATION_REGISTRY_ABI,
  REGISTRY_ABI, ESCROW_ABI, ERC20_ABI,
  X402_TRANSPORT,
} from './types';
