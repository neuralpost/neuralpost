#!/bin/bash

# ═══════════════════════════════════════════════════════════════
# NeuralPost — Generate Production .env
# Creates .env.production with cryptographically secure secrets
# Usage: ./scripts/gen-env.sh
# ═══════════════════════════════════════════════════════════════

set -e

OUTPUT=".env.production"

if [ -f "$OUTPUT" ]; then
  echo "⚠️  $OUTPUT already exists."
  read -p "Overwrite? (y/N) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
  fi
fi

# Generate secrets
JWT_SECRET=$(openssl rand -base64 48 | tr -d '\n')
ADMIN_KEY=$(openssl rand -base64 24 | tr -d '\n')
WEBHOOK_KEY=$(openssl rand -hex 32)
WALLET_KEY=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -base64 18 | tr -d '\n')

cat > "$OUTPUT" << EOF
# ═══════════════════════════════════════════════════════════════
# NeuralPost v2.2.12 — Production Environment
# Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
# ═══════════════════════════════════════════════════════════════

NODE_ENV=production
PORT=3000

# Database
DB_USER=postgres
DB_PASSWORD=${DB_PASSWORD}
DB_NAME=neuralpost
DATABASE_URL=postgresql://postgres:${DB_PASSWORD}@db:5432/neuralpost

# Auth
JWT_SECRET=${JWT_SECRET}
ADMIN_KEY=${ADMIN_KEY}

# Encryption
WEBHOOK_ENCRYPTION_KEY=${WEBHOOK_KEY}
WALLET_ENCRYPTION_KEY=${WALLET_KEY}

# Security
TRUST_PROXY=true

# x402 (off by default — enable when ready)
X402_ENABLED=false
X402_NETWORK=testnet

# Blockchain (off by default)
BLOCKCHAIN_ENABLED=false

# 8004scan (optional)
# ERC8004SCAN_API_KEY=
EOF

echo "✅ Generated $OUTPUT"
echo ""
echo "Secrets:"
echo "  JWT_SECRET:            ${JWT_SECRET:0:12}..."
echo "  ADMIN_KEY:             ${ADMIN_KEY:0:12}..."
echo "  WEBHOOK_ENCRYPTION_KEY: ${WEBHOOK_KEY:0:12}..."
echo "  WALLET_ENCRYPTION_KEY:  ${WALLET_KEY:0:12}..."
echo "  DB_PASSWORD:           ${DB_PASSWORD:0:8}..."
echo ""
echo "⚠️  Save these securely. This file contains production secrets."
echo ""
echo "Deploy with:"
echo "  docker compose -f docker-compose.prod.yml --env-file .env.production up -d"
