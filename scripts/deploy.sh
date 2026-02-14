#!/bin/bash

# ═══════════════════════════════════════════════════════════════
# NeuralPost — Deploy to GCP Cloud Run
# Usage: ./scripts/deploy.sh [--build-only] [--migrate]
# ═══════════════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── Configuration (edit these) ───────────────────────────────
GCP_PROJECT="${GCP_PROJECT:-your-project-id}"
GCP_REGION="${GCP_REGION:-asia-southeast1}"
SERVICE_NAME="neuralpost-api"
REPO_NAME="neuralpost"
CLOUD_SQL_CONNECTION="${CLOUD_SQL_CONNECTION:-}"
# ──────────────────────────────────────────────────────────────

# Get version from package.json
VERSION=$(node -p "require('./package.json').version")
IMAGE="${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/${REPO_NAME}/api:v${VERSION}"
IMAGE_LATEST="${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/${REPO_NAME}/api:latest"

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  NeuralPost Deploy — v${VERSION}                            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}Project:${NC}  $GCP_PROJECT"
echo -e "${YELLOW}Region:${NC}   $GCP_REGION"
echo -e "${YELLOW}Image:${NC}    $IMAGE"
echo ""

# ─── Pre-flight checks ───────────────────────────────────────

# Check gcloud auth
if ! gcloud auth print-identity-token &>/dev/null; then
  echo -e "${RED}✗ Not authenticated. Run: gcloud auth login${NC}"
  exit 1
fi
echo -e "${GREEN}✓ GCP authenticated${NC}"

# Check project
gcloud config set project $GCP_PROJECT --quiet
echo -e "${GREEN}✓ Project: $GCP_PROJECT${NC}"

# ─── Build ────────────────────────────────────────────────────

echo ""
echo -e "${YELLOW}Building TypeScript...${NC}"
npm run build
echo -e "${GREEN}✓ Build complete${NC}"

echo ""
echo -e "${YELLOW}Building Docker image via Cloud Build...${NC}"
gcloud builds submit \
  --tag $IMAGE \
  --quiet \
  .

# Also tag as latest
echo -e "${YELLOW}Tagging as latest...${NC}"
gcloud artifacts docker tags add $IMAGE $IMAGE_LATEST --quiet 2>/dev/null || true
echo -e "${GREEN}✓ Image pushed: $IMAGE${NC}"

if [ "$1" = "--build-only" ]; then
  echo -e "${GREEN}Build complete. Skipping deploy (--build-only).${NC}"
  exit 0
fi

# ─── Migrate (optional) ──────────────────────────────────────

if [ "$1" = "--migrate" ] || [ "$2" = "--migrate" ]; then
  echo ""
  echo -e "${YELLOW}Running database migrations...${NC}"
  echo -e "${CYAN}Make sure cloud-sql-proxy is running locally.${NC}"
  npm run db:migrate
  echo -e "${GREEN}✓ Migrations complete${NC}"
fi

# ─── Deploy ───────────────────────────────────────────────────

echo ""
echo -e "${YELLOW}Deploying to Cloud Run...${NC}"

DEPLOY_ARGS=(
  --image=$IMAGE
  --platform=managed
  --region=$GCP_REGION
  --quiet
)

# Add Cloud SQL if configured
if [ -n "$CLOUD_SQL_CONNECTION" ]; then
  DEPLOY_ARGS+=(--add-cloudsql-instances=$CLOUD_SQL_CONNECTION)
fi

gcloud run deploy $SERVICE_NAME "${DEPLOY_ARGS[@]}"

# ─── Done ─────────────────────────────────────────────────────

API_URL=$(gcloud run services describe $SERVICE_NAME \
  --region=$GCP_REGION \
  --format='value(status.url)' 2>/dev/null)

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✓ Deployed successfully!                                ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}URL:${NC}     $API_URL"
echo -e "${YELLOW}Version:${NC} v${VERSION}"
echo -e "${YELLOW}Health:${NC}  $API_URL/health"
echo ""

# Quick health check
echo -e "${YELLOW}Running health check...${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/health" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
  echo -e "${GREEN}✓ Health check passed (HTTP $HTTP_CODE)${NC}"
else
  echo -e "${RED}✗ Health check failed (HTTP $HTTP_CODE) — check logs:${NC}"
  echo -e "  gcloud run services logs read $SERVICE_NAME --region=$GCP_REGION"
fi
