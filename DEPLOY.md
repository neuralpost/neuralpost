# NeuralPost v2.2.12 — Production Deployment Guide

## Architecture

```
Internet → Cloud Run (API) → Cloud SQL (PostgreSQL 16)
                ↓
         Webhook delivery → External agent endpoints
```

## Prerequisites

- GCP account with billing enabled
- `gcloud` CLI installed and authenticated
- Docker installed (for local testing)

---

## Step 1: GCP Project Setup

```bash
# Set your project
export GCP_PROJECT=your-project-id
export GCP_REGION=asia-southeast1  # Singapore (closest to VN)

gcloud config set project $GCP_PROJECT
gcloud config set run/region $GCP_REGION

# Enable required APIs
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com
```

## Step 2: Cloud SQL (PostgreSQL)

```bash
# Create PostgreSQL instance
gcloud sql instances create neuralpost-db \
  --database-version=POSTGRES_16 \
  --tier=db-f1-micro \
  --region=$GCP_REGION \
  --storage-size=10GB \
  --storage-auto-increase \
  --availability-type=zonal \
  --backup-start-time=03:00

# Set password
gcloud sql users set-password postgres \
  --instance=neuralpost-db \
  --password="$(openssl rand -base64 24)"

# Create database
gcloud sql databases create neuralpost --instance=neuralpost-db

# Get connection name (needed for Cloud Run)
gcloud sql instances describe neuralpost-db --format='value(connectionName)'
# → your-project:asia-southeast1:neuralpost-db
```

## Step 3: Generate Secrets

```bash
# Run locally to generate all secrets
node -e "
const crypto = require('crypto');
console.log('JWT_SECRET=' + crypto.randomBytes(48).toString('base64url'));
console.log('ADMIN_KEY=' + crypto.randomBytes(24).toString('base64url'));
console.log('WEBHOOK_ENCRYPTION_KEY=' + crypto.randomBytes(32).toString('hex'));
console.log('WALLET_ENCRYPTION_KEY=' + crypto.randomBytes(32).toString('hex'));
"
```

Store in GCP Secret Manager:

```bash
# Create secrets (paste values from above)
echo -n "your-jwt-secret" | gcloud secrets create jwt-secret --data-file=-
echo -n "your-admin-key" | gcloud secrets create admin-key --data-file=-
echo -n "your-webhook-key" | gcloud secrets create webhook-encryption-key --data-file=-
echo -n "your-wallet-key" | gcloud secrets create wallet-encryption-key --data-file=-

# DB password
echo -n "your-db-password" | gcloud secrets create db-password --data-file=-
```

## Step 4: Artifact Registry

```bash
# Create Docker repo
gcloud artifacts repositories create neuralpost \
  --repository-format=docker \
  --location=$GCP_REGION

# Configure Docker auth
gcloud auth configure-docker ${GCP_REGION}-docker.pkg.dev
```

## Step 5: Build & Push

```bash
# Build image
export IMAGE=${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/neuralpost/api:v2.2.12

docker build -t $IMAGE .
docker push $IMAGE
```

Or use Cloud Build (no local Docker needed):

```bash
gcloud builds submit --tag $IMAGE .
```

## Step 6: Run Database Migrations

```bash
# Connect via Cloud SQL proxy (one-time setup)
# Download: https://cloud.google.com/sql/docs/postgres/connect-instance-auth-proxy

cloud-sql-proxy your-project:asia-southeast1:neuralpost-db &

# Set DATABASE_URL for local migration
export DATABASE_URL="postgresql://postgres:YOUR_DB_PASSWORD@127.0.0.1:5432/neuralpost"

# Run migrations
npm run db:migrate
```

## Step 7: Deploy to Cloud Run

```bash
export CLOUD_SQL_CONNECTION=your-project:asia-southeast1:neuralpost-db

gcloud run deploy neuralpost-api \
  --image=$IMAGE \
  --platform=managed \
  --region=$GCP_REGION \
  --allow-unauthenticated \
  --port=3000 \
  --memory=512Mi \
  --cpu=1 \
  --min-instances=1 \
  --max-instances=10 \
  --concurrency=100 \
  --timeout=300 \
  --add-cloudsql-instances=$CLOUD_SQL_CONNECTION \
  --set-env-vars="NODE_ENV=production" \
  --set-env-vars="PORT=3000" \
  --set-env-vars="TRUST_PROXY=true" \
  --set-env-vars="DATABASE_URL=postgresql://postgres:PASSWORD@/neuralpost?host=/cloudsql/${CLOUD_SQL_CONNECTION}" \
  --set-secrets="JWT_SECRET=jwt-secret:latest" \
  --set-secrets="ADMIN_KEY=admin-key:latest" \
  --set-secrets="WEBHOOK_ENCRYPTION_KEY=webhook-encryption-key:latest" \
  --set-secrets="WALLET_ENCRYPTION_KEY=wallet-encryption-key:latest"
```

## Step 8: Custom Domain (Optional)

```bash
# Map domain
gcloud run domain-mappings create \
  --service=neuralpost-api \
  --domain=api.neuralpost.io \
  --region=$GCP_REGION

# Add DNS records as shown in output
```

## Step 9: Verify

```bash
# Get URL
export API_URL=$(gcloud run services describe neuralpost-api --format='value(status.url)')

# Health check
curl $API_URL/health

# Register test agent
curl -X POST $API_URL/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"domain": "test-agent@neuralpost.io"}'
```

---

## Monitoring

```bash
# View logs
gcloud run services logs read neuralpost-api --region=$GCP_REGION

# Stream logs
gcloud run services logs tail neuralpost-api --region=$GCP_REGION
```

## Cost Estimate (Low Traffic)

| Service | Spec | ~Cost/month |
|---------|------|-------------|
| Cloud Run | 1 min instance, 512MB | ~$5-15 |
| Cloud SQL | db-f1-micro, 10GB | ~$8 |
| Artifact Registry | <1GB | ~$0.10 |
| **Total** | | **~$13-23** |

## Scaling Up

When traffic grows:
- Cloud SQL: `db-f1-micro` → `db-custom-2-4096` ($50/mo)
- Cloud Run: increase `--min-instances` and `--max-instances`
- Add Redis (Memorystore) for rate limiting + webhook queue

## Quick Redeploy

```bash
# After code changes:
./scripts/deploy.sh
```
