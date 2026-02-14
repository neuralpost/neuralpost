#!/bin/bash

# ═══════════════════════════════════════════════════════════════
# NeuralPost Database Setup Script
# ═══════════════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║     █████╗  ██████╗ ███████╗███╗   ██╗████████╗              ║"
echo "║    ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝              ║"
echo "║    ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║                 ║"
echo "║    ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║                 ║"
echo "║    ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║                 ║"
echo "║    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝                 ║"
echo "║                                                               ║"
echo "║    Database Setup Script                                      ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Load .env if exists
if [ -f .env ]; then
    echo -e "${YELLOW}Loading .env file...${NC}"
    export $(cat .env | grep -v '^#' | xargs)
fi

# Default values
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_USER=${DB_USER:-postgres}
DB_PASSWORD=${DB_PASSWORD:-postgres}
DB_NAME=${DB_NAME:-neuralpost}

echo ""
echo -e "${YELLOW}Database Configuration:${NC}"
echo "  Host: $DB_HOST"
echo "  Port: $DB_PORT"
echo "  User: $DB_USER"
echo "  Database: $DB_NAME"
echo ""

# Check if PostgreSQL is running
echo -e "${YELLOW}Checking PostgreSQL connection...${NC}"
if ! PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -c '\q' 2>/dev/null; then
    echo -e "${RED}Error: Cannot connect to PostgreSQL${NC}"
    echo "Please ensure PostgreSQL is running and credentials are correct."
    exit 1
fi
echo -e "${GREEN}✓ PostgreSQL is running${NC}"

# Create database if not exists
echo -e "${YELLOW}Creating database '$DB_NAME' if not exists...${NC}"
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -tc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1 || \
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -c "CREATE DATABASE $DB_NAME"
echo -e "${GREEN}✓ Database ready${NC}"

# Run migrations
echo -e "${YELLOW}Running database migrations...${NC}"
npm run db:migrate
echo -e "${GREEN}✓ Migrations complete${NC}"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Database setup complete!${NC}"
echo ""
echo -e "Run ${YELLOW}npm run dev${NC} to start the server"
echo -e "Run ${YELLOW}npm run db:studio${NC} to open Drizzle Studio"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
