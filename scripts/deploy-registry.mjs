#!/usr/bin/env node
/**
 * ═══════════════════════════════════════════════════════════════════════════
 * DEPLOY AGENTREGISTRY TO SKALE CALYPSO
 *
 * Prerequisites:
 *   1. npm install solc ethers
 *   2. Set DEPLOY_PRIVATE_KEY env var (deployer wallet with sFUEL)
 *   3. (Optional) Set SKALE_RPC_URL to override default
 *
 * Usage:
 *   node scripts/deploy-registry.mjs
 *   node scripts/deploy-registry.mjs --testnet   (deploy to SKALE testnet)
 *
 * After deploy:
 *   1. Copy the registry address to .env as SKALE_REGISTRY=0x...
 *   2. Add sponsor wallet: SPONSOR_WALLET_KEY=0x... (can be same as deployer)
 *   3. Set BLOCKCHAIN_ENABLED=true and SPONSOR_MINTS=true
 *
 * SKALE gas: $0 (zero gas, but needs sFUEL — free from faucet)
 * Get sFUEL: https://sfuel.skale.network/ or Ruby Exchange faucet
 * ═══════════════════════════════════════════════════════════════════════════
 */

import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─── Config ─────────────────────────────────────────────────────────────

const isTestnet = process.argv.includes('--testnet');

const CHAINS = {
  mainnet: {
    name: 'SKALE Calypso',
    chainId: 1564830818,
    rpc: process.env.SKALE_RPC_URL || 'https://mainnet.skalenodes.com/v1/honorable-steel-rasalhague',
    explorer: 'https://honorable-steel-rasalhague.explorer.mainnet.skalenodes.com',
  },
  testnet: {
    name: 'SKALE Calypso Testnet',
    chainId: 974399131,
    rpc: process.env.SKALE_TESTNET_RPC || 'https://testnet.skalenodes.com/v1/giant-half-dual-testnet',
    explorer: 'https://giant-half-dual-testnet.explorer.testnet.skalenodes.com',
  },
};

const chain = isTestnet ? CHAINS.testnet : CHAINS.mainnet;

// ─── Compile ────────────────────────────────────────────────────────────

async function compile() {
  console.log('📦 Compiling AgentRegistry.sol...');

  // Dynamic import solc
  const solc = (await import('solc')).default;

  const contractPath = resolve(__dirname, '..', 'contracts', 'AgentRegistry.sol');
  const source = readFileSync(contractPath, 'utf8');

  const input = JSON.stringify({
    language: 'Solidity',
    sources: { 'AgentRegistry.sol': { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      outputSelection: {
        '*': { '*': ['abi', 'evm.bytecode.object'] },
      },
    },
  });

  const output = JSON.parse(solc.compile(input));

  // Check for errors
  if (output.errors) {
    const errors = output.errors.filter(e => e.severity === 'error');
    if (errors.length > 0) {
      console.error('❌ Compilation errors:');
      errors.forEach(e => console.error(e.formattedMessage));
      process.exit(1);
    }
    // Print warnings
    output.errors.filter(e => e.severity === 'warning').forEach(e => {
      console.warn('⚠️', e.message);
    });
  }

  const contract = output.contracts['AgentRegistry.sol']['AgentRegistry'];
  console.log('✅ Compiled successfully');
  return {
    abi: contract.abi,
    bytecode: '0x' + contract.evm.bytecode.object,
  };
}

// ─── Deploy ─────────────────────────────────────────────────────────────

async function deploy() {
  const { ethers } = await import('ethers');

  const privateKey = process.env.DEPLOY_PRIVATE_KEY;
  if (!privateKey) {
    console.error('❌ Set DEPLOY_PRIVATE_KEY env var');
    console.error('   Generate: node -e "console.log(require(\'ethers\').Wallet.createRandom().privateKey)"');
    process.exit(1);
  }

  console.log(`\n🔗 Connecting to ${chain.name} (chainId: ${chain.chainId})...`);
  console.log(`   RPC: ${chain.rpc}`);

  const provider = new ethers.JsonRpcProvider(chain.rpc, {
    chainId: chain.chainId,
    name: chain.name,
  });

  const wallet = new ethers.Wallet(privateKey, provider);
  const address = wallet.address;

  console.log(`   Deployer: ${address}`);

  // Check sFUEL balance
  const balance = await provider.getBalance(address);
  console.log(`   sFUEL balance: ${ethers.formatEther(balance)}`);

  if (balance === 0n) {
    console.error('❌ No sFUEL! Get free sFUEL from:');
    console.error('   https://sfuel.skale.network/');
    console.error('   https://ruby.exchange/faucet.html');
    process.exit(1);
  }

  // Compile contract
  const { abi, bytecode } = await compile();

  // Deploy
  console.log('\n🚀 Deploying AgentRegistry...');
  const factory = new ethers.ContractFactory(abi, bytecode, wallet);

  const contract = await factory.deploy();
  console.log(`   TX hash: ${contract.deploymentTransaction().hash}`);
  console.log('   Waiting for confirmation...');

  await contract.waitForDeployment();
  const contractAddress = await contract.getAddress();

  console.log(`\n✅ AgentRegistry deployed!`);
  console.log(`   Address: ${contractAddress}`);
  console.log(`   Explorer: ${chain.explorer}/address/${contractAddress}`);

  // Verify admin
  const adminAddr = await contract.admin();
  console.log(`   Admin: ${adminAddr}`);
  console.log(`   Is sponsor: ${await contract.sponsors(adminAddr)}`);

  // Output env vars
  console.log('\n═══════════════════════════════════════════════════════════');
  console.log('Add to .env:');
  console.log('═══════════════════════════════════════════════════════════');
  if (isTestnet) {
    console.log(`SKALE_TESTNET_REGISTRY=${contractAddress}`);
  } else {
    console.log(`SKALE_REGISTRY=${contractAddress}`);
  }
  console.log(`SPONSOR_WALLET_KEY=${privateKey}`);
  console.log(`BLOCKCHAIN_ENABLED=true`);
  console.log(`SPONSOR_MINTS=true`);
  console.log('═══════════════════════════════════════════════════════════');

  // Save ABI for reference
  const { writeFileSync } = await import('fs');
  writeFileSync(
    resolve(__dirname, '..', 'contracts', 'AgentRegistry.abi.json'),
    JSON.stringify(abi, null, 2)
  );
  console.log('\n📄 ABI saved to contracts/AgentRegistry.abi.json');

  return contractAddress;
}

// ─── Run ────────────────────────────────────────────────────────────────

deploy().catch(err => {
  console.error('❌ Deploy failed:', err.message);
  process.exit(1);
});
