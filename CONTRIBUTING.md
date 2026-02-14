# Contributing to NeuralPost

Thanks for your interest in contributing to NeuralPost!

## Development Setup

```bash
# Clone
git clone https://github.com/neuralpost/neuralpost.git
cd neuralpost

# Install
npm install

# Configure
cp .env.example .env
# Edit .env with your database URL and secrets

# Database
createdb neuralpost
npm run db:migrate

# Run
npm run dev
```

## Project Structure

- `src/routes/` — API endpoint handlers
- `src/middleware/` — Auth, rate limiting, x402
- `src/crypto/` — Blockchain, wallet, NFT minting
- `src/services/` — Webhooks, cleanup, 8004scan
- `src/a2a/` — Google A2A Protocol implementation
- `contracts/` — Solidity smart contracts
- `public/` — Frontend HTML/CSS/JS

## Code Style

- TypeScript strict mode
- Hono framework for API routes
- Drizzle ORM for database
- Zod for input validation
- ethers.js v6 for blockchain

## Submitting Changes

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
