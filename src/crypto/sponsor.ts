// ═══════════════════════════════════════════════════════════════════════════
// NEURALPOST SPONSORED MINT SERVICE — ERC-8004 Compliant
//
// Auto-mints ERC-8004 Identity NFTs when agents register on NeuralPost.
//
// Strategy (SKALE):
//   1. SKALE chain (primary) — ZERO GAS, instant finality
//      → BITE V2 Sandbox (103698795) — primary chain
//      → SKALE Base Sepolia (324705682) — fallback
//   2. Base Sepolia (fallback) — official ERC-8004 CREATE2 addresses
//   3. Multi-chain: mint on SKALE + Base Sepolia for cross-chain identity
//
// Flow:
//   Agent registers → autoMintOnRegister() fires →
//     1. Sponsor calls register(agentURI) → NFT minted to sponsor
//     2. Sponsor calls transferFrom(sponsor, agentWallet, tokenId)
//     Both txs are FREE on SKALE (zero gas!)
//
// agentURI uses data: URI (base64 JSON) so no external hosting needed
// ═══════════════════════════════════════════════════════════════════════════

import { decryptPrivateKey } from './wallet';
import { db } from '../db';
import { agents } from '../db/schema';
import { eq, sql } from 'drizzle-orm';
import { JsonRpcProvider, Wallet, Contract, isError as isEthersError } from 'ethers';
import {
  CHAIN_CONFIGS, PRIMARY_CHAIN, SKALE_MINT_CHAIN, IDENTITY_REGISTRY_ABI,
  type SupportedChainId, type SponsoredMintRequest, type SponsoredMintResult,
} from './types';

const SPONSOR_ENABLED = process.env.SPONSOR_MINTS === 'true';
const SPONSOR_PRIVATE_KEY = process.env.SPONSOR_WALLET_KEY || '';

// ─── Provider Cache ─────────────────────────────────────────────────────

const providerCache = new Map<number, JsonRpcProvider>();

function getProvider(chainId: SupportedChainId): JsonRpcProvider {
  if (!providerCache.has(chainId)) {
    const chain = CHAIN_CONFIGS[chainId];
    if (!chain?.rpcUrl) throw new Error(`No RPC URL for chain ${chainId}`);
    providerCache.set(chainId, new JsonRpcProvider(chain.rpcUrl, {
      chainId: chain.chainId,
      name: chain.name,
    }));
  }
  return providerCache.get(chainId)!;
}

// ─── Mint Queue ─────────────────────────────────────────────────────────

interface MintJob {
  id: string;
  request: SponsoredMintRequest;
  status: 'queued' | 'pending' | 'confirmed' | 'failed';
  txHash?: string;
  tokenId?: number;
  error?: string;
  createdAt: number;
  updatedAt: number;
}

const mintQueue = new Map<string, MintJob>();

// ─── Build agentURI as data: URI (fully on-chain, no hosting needed) ────

function buildAgentDataURI(domain: string, registrationURI: string): string {
  const registrationFile = {
    type: 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1',
    name: domain.split('@')[0],
    description: `NeuralPost agent: ${domain}`,
    image: 'https://neuralpost.net/logo.png',
    services: [
      {
        name: 'A2A',
        endpoint: 'https://api.neuralpost.net/.well-known/agent-card.json',
        version: '0.3.0',
      },
      {
        name: 'web',
        endpoint: registrationURI,
      },
    ],
    x402Support: true,
    active: true,
    supportedTrust: ['reputation'],
  };

  const json = JSON.stringify(registrationFile);
  const base64 = Buffer.from(json).toString('base64');
  return `data:application/json;base64,${base64}`;
}

// ─── Auto-Mint on Agent Registration ────────────────────────────────────
//
// Main entry point: called when an agent registers on NeuralPost.
// Mints ERC-8004 identity NFT on the best available SKALE chain (zero gas).
// Falls back to Base Sepolia if SKALE contracts aren't deployed yet.

export async function autoMintOnRegister(params: {
  agentId: string;
  domain: string;
  walletAddress: string;
  registrationURI: string;
  preferredChain?: SupportedChainId;
}): Promise<SponsoredMintResult> {
  const chainId = params.preferredChain || selectMintChain();
  const chainName = CHAIN_CONFIGS[chainId]?.name || `chain ${chainId}`;

  console.log(`[AutoMint] Agent ${params.domain} registered → minting on ${chainName}`);

  return sponsoredMint({
    agentId: params.agentId,
    domain: params.domain,
    walletAddress: params.walletAddress,
    registrationURI: params.registrationURI,
    chainId,
  });
}

// ─── Multi-Chain Mint (SKALE + Base Sepolia) ────────────────────────────
//
// Mints on multiple chains for maximum discoverability.
// SKALE = free (zero gas), Base Sepolia = official ERC-8004 canonical addresses.

export async function multiChainMint(params: {
  agentId: string;
  domain: string;
  walletAddress: string;
  registrationURI: string;
}): Promise<{ results: SponsoredMintResult[]; successCount: number }> {
  const chains = getAvailableMintChains();

  console.log(`[MultiChainMint] Minting on ${chains.length} chains: ${chains.map(c => CHAIN_CONFIGS[c]?.name).join(', ')}`);

  const promises = chains.map(chainId =>
    sponsoredMint({
      agentId: params.agentId,
      domain: params.domain,
      walletAddress: params.walletAddress,
      registrationURI: params.registrationURI,
      chainId,
    }).catch(err => ({
      success: false as const,
      chainId,
      error: err.message,
    }))
  );

  const results = await Promise.all(promises);
  const successCount = results.filter(r => r.success).length;
  console.log(`[MultiChainMint] Complete: ${successCount}/${chains.length} chains`);

  return { results, successCount };
}

// ─── Sponsored Mint ──────────────────────────────────────────────────────

export async function sponsoredMint(
  request: SponsoredMintRequest
): Promise<SponsoredMintResult> {
  if (!SPONSOR_ENABLED) {
    console.log('[SponsoredMint] Disabled — set SPONSOR_MINTS=true');
    return { success: false, chainId: request.chainId, error: 'Sponsored mints disabled' };
  }

  const chain = CHAIN_CONFIGS[request.chainId];
  if (!chain) {
    return { success: false, chainId: request.chainId, error: `Unsupported chain: ${request.chainId}` };
  }
  if (!chain.contracts.identityRegistry) {
    return { success: false, chainId: request.chainId, error: `Identity Registry not deployed on ${chain.name}` };
  }

  const jobId = `mint_${request.agentId}_${Date.now()}`;
  const job: MintJob = { id: jobId, request, status: 'queued', createdAt: Date.now(), updatedAt: Date.now() };
  mintQueue.set(jobId, job);

  try {
    return await mintERC8004(job);
  } catch (err: any) {
    job.status = 'failed';
    job.error = err.message;
    job.updatedAt = Date.now();
    console.error(`[SponsoredMint] FAILED for ${request.domain}:`, err.message);
    return { success: false, chainId: request.chainId, error: err.message };
  }
}

// ─── ERC-8004 Mint (works on any EVM chain with deployed registry) ──────
//
// Pattern:
//   1. Sponsor calls IdentityRegistry.register(agentURI) → gets tokenId
//   2. Sponsor calls IdentityRegistry.transferFrom(sponsor, agentWallet, tokenId)
//   Total: 2 transactions, only sponsor needs gas

async function mintERC8004(job: MintJob): Promise<SponsoredMintResult> {
  const { request } = job;
  const chain = CHAIN_CONFIGS[request.chainId];

  if (!SPONSOR_PRIVATE_KEY) {
    return { success: false, chainId: request.chainId, error: 'SPONSOR_WALLET_KEY not configured' };
  }

  job.status = 'pending';
  job.updatedAt = Date.now();
  console.log(`[SponsoredMint] Minting ERC-8004 on ${chain.name} (${chain.zeroGas ? '⚡ ZERO GAS' : '💰 gas required'}) for ${request.domain}...`);

  const provider = getProvider(request.chainId);
  const sponsorWallet = new Wallet(SPONSOR_PRIVATE_KEY, provider);
  const registry = new Contract(
    chain.contracts.identityRegistry,
    IDENTITY_REGISTRY_ABI,
    sponsorWallet,
  );

  // Build agentURI — data: URI with base64-encoded registration JSON
  const agentURI = buildAgentDataURI(request.domain, request.registrationURI);

  try {
    // Step 1: Register agent (NFT minted to sponsor wallet as msg.sender)
    console.log(`[SponsoredMint] Step 1/2: Calling register()...`);
    const registerTx = await registry['register(string)'](agentURI);
    console.log(`[SponsoredMint] register() TX submitted: ${registerTx.hash}`);
    job.txHash = registerTx.hash;
    job.updatedAt = Date.now();

    const confirmations = chain.zeroGas ? 1 : 2;
    const receipt = await registerTx.wait(confirmations);
    if (!receipt || receipt.status === 0) throw new Error('Register transaction reverted');

    // Parse Registered event to get tokenId (agentId)
    let tokenId: number | undefined;
    for (const log of receipt.logs) {
      try {
        const parsed = registry.interface.parseLog({ topics: [...log.topics], data: log.data });
        if (parsed?.name === 'Registered') {
          tokenId = Number(parsed.args[0]);  // agentId
          break;
        }
        // Fallback: also check Transfer event (ERC-721 mint = Transfer from 0x0)
        if (parsed?.name === 'Transfer' && parsed.args[0] === '0x0000000000000000000000000000000000000000') {
          tokenId = Number(parsed.args[2]);  // tokenId
        }
      } catch {}
    }

    if (tokenId === undefined) throw new Error('Could not find tokenId in transaction logs');

    console.log(`[SponsoredMint] ✅ Registered! tokenId=${tokenId}`);

    // Step 2: Transfer NFT from sponsor → agent wallet (if different address)
    const sponsorAddress = await sponsorWallet.getAddress();
    if (request.walletAddress && request.walletAddress !== sponsorAddress.toLowerCase()) {
      console.log(`[SponsoredMint] Step 2/2: Transferring NFT #${tokenId} to ${request.walletAddress}...`);
      const transferTx = await registry.transferFrom(
        sponsorAddress,
        request.walletAddress,
        tokenId,
      );
      await transferTx.wait(confirmations);
      console.log(`[SponsoredMint] ✅ NFT transferred to agent wallet`);

      // Step 3: Set agentWallet metadata (cleared during transfer per ERC-8004 spec)
      try {
        const [agentRecord] = await db.select({ encryptedPrivateKey: agents.encryptedPrivateKey })
          .from(agents)
          .where(sql`LOWER(${agents.walletAddress}) = ${request.walletAddress.toLowerCase()}`)
          .limit(1);
        
        if (agentRecord?.encryptedPrivateKey) {
          // Protocol-custodied: server has key → send sFUEL + sign EIP-712 + call setAgentWallet
          const sfuelTx = await sponsorWallet.sendTransaction({ to: request.walletAddress, value: 1000000000000000n });
          await sfuelTx.wait(1);
          console.log('[SponsoredMint] Step 3: sent sFUEL to agent wallet');
          const privateKey = decryptPrivateKey(JSON.parse(agentRecord.encryptedPrivateKey));
          const agentSigner = new Wallet(privateKey, provider);
          const agentRegistry = new Contract(chain.contracts.identityRegistry, IDENTITY_REGISTRY_ABI, agentSigner);
          const deadline = Math.floor(Date.now() / 1000) + 300;
          const domain = { name: "ERC8004IdentityRegistry", version: "1", chainId: BigInt(chain.chainId), verifyingContract: chain.contracts.identityRegistry };
          const types = { AgentWalletSet: [{ name: "agentId", type: "uint256" },{ name: "newWallet", type: "address" },{ name: "owner", type: "address" },{ name: "deadline", type: "uint256" }] };
          const val = { agentId: BigInt(tokenId), newWallet: request.walletAddress, owner: request.walletAddress, deadline: BigInt(deadline) };
          const signature = await agentSigner.signTypedData(domain, types, val);
          const setTx = await agentRegistry.setAgentWallet(tokenId, request.walletAddress, deadline, signature, { gasLimit: 500000 });
          await setTx.wait(confirmations);
          console.log('[SponsoredMint] Step 3: agentWallet set on-chain ✅');
        } else {
          // Self-custodied: NFT ownership = wallet proof (no setAgentWallet needed)
          console.log('[SponsoredMint] Step 3: Self-custodied wallet — NFT ownership proves identity ✅');
        }
      } catch (e) { console.warn('[SponsoredMint] setAgentWallet failed (non-fatal):', (e as Error).message); }
    } else {
      console.log(`[SponsoredMint] Step 2/2: Skipped (sponsor IS agent wallet)`);
    }

    job.status = 'confirmed';
    job.tokenId = tokenId;
    job.updatedAt = Date.now();
    console.log(`[SponsoredMint] ✅ Complete! tokenId=${tokenId}, tx=${registerTx.hash}, chain=${chain.name}`);

    return { success: true, tokenId, txHash: registerTx.hash, chainId: request.chainId };
  } catch (err: any) {
    let errorMsg = err.message;
    if (isEthersError(err, 'CALL_EXCEPTION')) {
      errorMsg = `Contract call failed: ${err.reason || err.message}`;
    } else if (isEthersError(err, 'INSUFFICIENT_FUNDS')) {
      errorMsg = chain.zeroGas
        ? 'Sponsor needs sFUEL (free from SKALE faucet)'
        : 'Sponsor needs ETH for gas. Fund wallet on Base Sepolia faucet.';
    }
    throw new Error(errorMsg);
  }
}

// ─── sFUEL Distribution (SKALE only) ─────────────────────────────────────

export async function distributeSFuel(
  walletAddress: string,
  chainId: SupportedChainId = SKALE_MINT_CHAIN,
): Promise<{ success: boolean; txHash?: string; error?: string }> {
  const chain = CHAIN_CONFIGS[chainId];
  if (!chain?.zeroGas) return { success: false, error: 'sFUEL only on SKALE chains' };
  if (!SPONSOR_PRIVATE_KEY) return { success: false, error: 'Sponsor wallet not configured' };

  try {
    const provider = getProvider(chainId);
    const funder = new Wallet(SPONSOR_PRIVATE_KEY, provider);
    const tx = await funder.sendTransaction({ to: walletAddress, value: 10000000000000n });
    console.log(`[sFUEL] Sent to ${walletAddress} — tx: ${tx.hash}`);
    await tx.wait(1);
    return { success: true, txHash: tx.hash };
  } catch (err: any) {
    console.error(`[sFUEL] Distribution failed:`, err.message);
    return { success: false, error: err.message };
  }
}

// ─── Status ─────────────────────────────────────────────────────────────

export function getMintStatus(agentId: string): MintJob | null {
  for (const job of mintQueue.values()) {
    if (job.request.agentId === agentId) return job;
  }
  return null;
}

export function getMintStats() {
  let queued = 0, pending = 0, confirmed = 0, failed = 0;
  for (const job of mintQueue.values()) {
    switch (job.status) {
      case 'queued': queued++; break; case 'pending': pending++; break;
      case 'confirmed': confirmed++; break; case 'failed': failed++; break;
    }
  }
  return { queued, pending, confirmed, failed, total: mintQueue.size };
}

// ─── Chain Selection ─────────────────────────────────────────────────────

export function selectMintChain(): SupportedChainId {
  // Priority: SKALE (zero gas!) → Base Sepolia (official ERC-8004) → others

  // 1. SKALE chains first — ZERO GAS = free minting!
  const skaleChains: SupportedChainId[] = [
    103698795,   // BITE V2 Sandbox (production primary)
    324705682,   // SKALE Base Sepolia
    1187947933,  // SKALE Base Mainnet
  ];

  for (const chainId of skaleChains) {
    const chain = CHAIN_CONFIGS[chainId];
    if (chain?.contracts.identityRegistry) return chainId;
  }

  // 2. Base Sepolia — official ERC-8004 CREATE2 addresses
  const baseSepolia = CHAIN_CONFIGS[84532];
  if (baseSepolia?.contracts.identityRegistry) return 84532;

  // 3. Other testnets
  const ethSepolia = CHAIN_CONFIGS[11155111];
  if (ethSepolia?.contracts.identityRegistry) return 11155111;

  // 4. Mainnets
  const base = CHAIN_CONFIGS[8453];
  if (base?.contracts.identityRegistry) return 8453;

  const ethMainnet = CHAIN_CONFIGS[1];
  if (ethMainnet?.contracts.identityRegistry) return 1;

  // Fallback to Base Sepolia (always has contracts hardcoded)
  return 84532;
}

// ─── Get all chains with deployed ERC-8004 contracts ─────────────────────

function getAvailableMintChains(): SupportedChainId[] {
  const available: SupportedChainId[] = [];
  for (const [id, chain] of Object.entries(CHAIN_CONFIGS)) {
    if (chain.contracts.identityRegistry && chain.isTestnet) {
      available.push(Number(id) as SupportedChainId);
    }
  }
  // Prefer zero-gas chains first
  return available.sort((a, b) => {
    const aZero = CHAIN_CONFIGS[a]?.zeroGas ? 0 : 1;
    const bZero = CHAIN_CONFIGS[b]?.zeroGas ? 0 : 1;
    return aZero - bZero;
  });
}
