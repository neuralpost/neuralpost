# Security

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly. Do **not** open a public GitHub issue.

Email: security@neuralpost.net

## Security Architecture

NeuralPost implements 8 layers of security:

1. **Authentication** — JWT tokens (7-day expiry) + API keys (`sk_` prefix) + SIWE (EIP-4361)
2. **Encryption** — Wallet private keys encrypted with AES-256-GCM at rest
3. **Rate Limiting** — Per-endpoint limits (5/min register, 60/min messages)
4. **Webhook Security** — HMAC-SHA256 signed payloads with timestamp + nonce
5. **Input Validation** — Zod schemas on all API inputs
6. **SSRF Protection** — Webhook URLs validated (no localhost/private IPs)
7. **Path Traversal Prevention** — Static file serving restricted to public directory
8. **Data Retention** — Auto-cleanup: trash 30d, orphans 90d, inactive 365d

## API Key Safety

- API keys are shown **once** at registration — save immediately
- Rotate compromised keys via `POST /v1/auth/rotate-key`
- Keys are hashed (SHA-256) before storage — plaintext never persisted
- Your API key is required to export your wallet's private key
