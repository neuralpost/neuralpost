#!/usr/bin/env npx tsx
// ═══════════════════════════════════════════════════════════════════════════
// DEPLOY ERC-8004 CONTRACTS ON SKALE — SKALE Network
//
// Deploys IdentityRegistry + ReputationRegistry on SKALE chains.
//
// Target chains:
//   1. BITE V2 Sandbox (103698795) — EVM Istanbul required
//   2. SKALE Base Sepolia (324705682) — permissionless
//
// Usage:
//   SPONSOR_WALLET_KEY=0x... npx tsx scripts/deploy-erc8004-skale.ts
//
// Notes:
//   - SKALE = zero gas, so deployment is FREE
//   - SKALE Base Sepolia has CREATE2Factory at canonical address
//   - BITE V2 Sandbox: compile with EVM Istanbul
//   - After deployment, update .env with contract addresses
// ═══════════════════════════════════════════════════════════════════════════

import { JsonRpcProvider, Wallet, ContractFactory, Contract } from 'ethers';

// ─── Config ─────────────────────────────────────────────────────────────

const DEPLOYER_KEY = process.env.SPONSOR_WALLET_KEY || process.env.DEPLOYER_KEY || '';

const CHAINS = [
  {
    name: 'BITE V2 Sandbox',
    chainId: 103698795,
    rpc: 'https://base-sepolia-testnet.skalenodes.com/v1/bite-v2-sandbox',
    explorer: 'https://base-sepolia-testnet-explorer.skalenodes.com:10032',
    evmNote: 'Compile with EVM Istanbul',
  },
  {
    name: 'SKALE Base Sepolia',
    chainId: 324705682,
    rpc: 'https://base-sepolia-testnet.skalenodes.com/v1/jubilant-horrible-ancha',
    explorer: 'https://base-sepolia-testnet-explorer.skalenodes.com',
    evmNote: 'Compile with EVM Shanghai or lower',
  },
];

// ─── ERC-8004 Contract Bytecode ─────────────────────────────────────────
// 
// Since we can't compile Solidity in this script, there are two approaches:
//
// OPTION A (Recommended): Use Foundry/Hardhat
//   1. Clone https://github.com/erc-8004/erc-8004-contracts
//   2. In foundry.toml, set evm_version = "istanbul" (for BITE V2)
//   3. forge script script/Deploy.s.sol --rpc-url $RPC --private-key $KEY --broadcast
//
// OPTION B: Check if CREATE2 addresses already work
//   The ERC-8004 team deploys to 20+ chains using CREATE2.
//   The canonical addresses MIGHT already be deployed on SKALE.
//   This script checks that first.

const ERC8004_ADDRESSES = {
  testnet: {
    identity: '0x8004A818BFB912233c491871b3d84c89A494BD9e',
    reputation: '0x8004B663056A597Dffe9eCcC1965A193B7388713',
  },
  mainnet: {
    identity: '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432',
    reputation: '0x8004BAa17C55a88189AE136b182e5fdA19dE9b63',
  },
};

// ─── Check & Deploy ─────────────────────────────────────────────────────

async function checkContractExists(provider: JsonRpcProvider, address: string): Promise<boolean> {
  const code = await provider.getCode(address);
  return code !== '0x' && code.length > 2;
}

async function main() {
  if (!DEPLOYER_KEY) {
    console.error('❌ Set SPONSOR_WALLET_KEY or DEPLOYER_KEY environment variable');
    console.error('   SPONSOR_WALLET_KEY=0x... npx tsx scripts/deploy-erc8004-skale.ts');
    process.exit(1);
  }

  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║  ERC-8004 Deployment Check — SKALE Network        ║');
  console.log('╚══════════════════════════════════════════════════════╝\n');

  const wallet = new Wallet(DEPLOYER_KEY);
  console.log(`Deployer: ${wallet.address}\n`);

  const envLines: string[] = [];

  for (const chain of CHAINS) {
    console.log(`\n━━━ ${chain.name} (${chain.chainId}) ━━━`);
    console.log(`RPC: ${chain.rpc}`);
    console.log(`Note: ${chain.evmNote}`);

    const provider = new JsonRpcProvider(chain.rpc, {
      chainId: chain.chainId,
      name: chain.name,
    });

    // Check deployer balance
    const connectedWallet = wallet.connect(provider);
    const balance = await provider.getBalance(wallet.address);
    console.log(`Balance: ${balance} wei (SKALE = zero gas, any balance works)`);

    // Check if canonical CREATE2 addresses already have code
    console.log('\nChecking canonical ERC-8004 CREATE2 addresses...');

    const identityExists = await checkContractExists(provider, ERC8004_ADDRESSES.testnet.identity);
    const reputationExists = await checkContractExists(provider, ERC8004_ADDRESSES.testnet.reputation);

    if (identityExists) {
      console.log(`  ✅ IdentityRegistry FOUND at ${ERC8004_ADDRESSES.testnet.identity}`);
    } else {
      console.log(`  ❌ IdentityRegistry NOT deployed at ${ERC8004_ADDRESSES.testnet.identity}`);
    }

    if (reputationExists) {
      console.log(`  ✅ ReputationRegistry FOUND at ${ERC8004_ADDRESSES.testnet.reputation}`);
    } else {
      console.log(`  ❌ ReputationRegistry NOT deployed at ${ERC8004_ADDRESSES.testnet.reputation}`);
    }

    // Also check mainnet addresses (some SKALE chains might use mainnet deployment)
    const identityMainnet = await checkContractExists(provider, ERC8004_ADDRESSES.mainnet.identity);
    const reputationMainnet = await checkContractExists(provider, ERC8004_ADDRESSES.mainnet.reputation);

    if (identityMainnet) {
      console.log(`  ✅ IdentityRegistry (mainnet addr) FOUND at ${ERC8004_ADDRESSES.mainnet.identity}`);
    }
    if (reputationMainnet) {
      console.log(`  ✅ ReputationRegistry (mainnet addr) FOUND at ${ERC8004_ADDRESSES.mainnet.reputation}`);
    }

    // Determine which addresses to use
    let identityAddr = '';
    let reputationAddr = '';

    if (identityExists) {
      identityAddr = ERC8004_ADDRESSES.testnet.identity;
      reputationAddr = reputationExists ? ERC8004_ADDRESSES.testnet.reputation : '';
    } else if (identityMainnet) {
      identityAddr = ERC8004_ADDRESSES.mainnet.identity;
      reputationAddr = reputationMainnet ? ERC8004_ADDRESSES.mainnet.reputation : '';
    }

    if (identityAddr) {
      console.log(`\n  🎉 Contracts already deployed! Using existing addresses.`);
    } else {
      console.log(`\n  ⚠️  Contracts not found. Deploy manually with Foundry:`);
      console.log(`     1. git clone https://github.com/erc-8004/erc-8004-contracts`);
      console.log(`     2. cd erc-8004-contracts`);
      if (chain.chainId === 103698795) {
        console.log(`     3. In foundry.toml: evm_version = "istanbul"`);
      } else {
        console.log(`     3. In foundry.toml: evm_version = "shanghai"`);
      }
      console.log(`     4. forge script script/Deploy.s.sol \\`);
      console.log(`          --rpc-url ${chain.rpc} \\`);
      console.log(`          --private-key $DEPLOYER_KEY --broadcast`);
      console.log(`     5. Copy deployed addresses to .env`);
    }

    // Generate .env lines
    const prefix = chain.chainId === 103698795 ? 'BITE' : 'SKALE_BASE_SEP';
    if (identityAddr) {
      envLines.push(`${prefix}_IDENTITY_REGISTRY=${identityAddr}`);
      if (reputationAddr) envLines.push(`${prefix}_REPUTATION_REGISTRY=${reputationAddr}`);
    } else {
      envLines.push(`# ${prefix}_IDENTITY_REGISTRY=<deploy first>`);
      envLines.push(`# ${prefix}_REPUTATION_REGISTRY=<deploy first>`);
    }
  }

  // Print .env snippet
  console.log('\n\n╔══════════════════════════════════════════════════════╗');
  console.log('║  .env Configuration                                  ║');
  console.log('╚══════════════════════════════════════════════════════╝\n');
  console.log('# SKALE Network — ERC-8004 Contract Addresses');
  for (const line of envLines) {
    console.log(line);
  }
  console.log('');
  console.log('# SKALE Network — Sponsor Wallet');
  console.log('SPONSOR_MINTS=true');
  console.log(`SPONSOR_WALLET_KEY=${DEPLOYER_KEY.substring(0, 6)}...`);
  console.log('');
  console.log('# Kobaru Facilitator (x402 payments on SKALE)');
  console.log('FACILITATOR_URL=https://gateway.kobaru.io');
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
