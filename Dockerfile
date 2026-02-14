# ═══════════════════════════════════════════════════════════════
# NeuralPost API - Production Dockerfile
# ═══════════════════════════════════════════════════════════════

# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci

# Copy source and build
COPY . .
RUN npm run build

# Production stage
FROM node:20-alpine AS runner

WORKDIR /app

# Create non-root user
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 neuralpost

# Copy only production dependencies
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copy built files and static assets
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/drizzle ./drizzle
COPY --from=builder /app/public ./public

# Set ownership
RUN mkdir -p /app/uploads && chown -R neuralpost:nodejs /app

USER neuralpost

EXPOSE 3000

ENV NODE_ENV=production

CMD ["node", "dist/index.js"]
