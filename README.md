# Shipstack Monorepo

Shipstack is an all-in-one SaaS service infrastructure layer providing Auth, Feature Gating (Access), and Billing for multi-tenant applications.

## Monorepo Architecture

```text
shipstack/
├── apps/
│   ├── fapi/            # Frontend API (NestJS): attempt-based auth & sessions
│   ├── bapi/            # Backend API (NestJS): server-to-server operations
│   └── console/         # Developer dashboard (Vite + React)
│
├── packages/
│   ├── database/        # Centralized Prisma schema & platform models
│   └── tsconfig/        # Shared TypeScript configurations
│
├── sdks/
│   ├── core/            # Vanilla JS / Node HTTP client & JWKS verifier
│   ├── react/           # React components & hooks
│   └── nextjs/          # Next.js App Router middleware & server actions
│
├── examples/
│   └── nextjs-app/      # Dogfooding reference application
│
└── docs/                # Architecture specifications & API references
```

## Getting Started

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run development mode
pnpm dev
```
