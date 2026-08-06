# Shipstack

Shipstack is multi-tenant SaaS infrastructure: auth, feature access, and billing, as three separate services that share one set of tenant environments.

This repository currently contains the **Auth** service, built as a NestJS app with its own database schema, and the design record behind it. Access and Billing are planned, not built.

## Status

| Part | State |
| :--- | :--- |
| **Auth service** (`apps/auth`) | Working. 41 unit tests and 73 end-to-end tests pass. |
| Email + password sign-up and sign-in | Working, with optional email verification and a leaked-password check. |
| Email code (one-time password) | Working. Codes are hashed, expire after 10 minutes, and lock after 5 failed attempts. |
| Google OAuth | Working. PKCE and state checks, with a tenant-domain handoff. |
| Sessions, token rotation, JWKS | Working. Access tokens are RS256 JWTs verified by public key. |
| Dev-browser flow | Working in development environments only. Refused in production. |
| Microsoft OAuth | Removed. Out of scope for v1. |
| Magic link, passkeys, MFA | Out of scope for v1. The state model reserves room for them. |
| Access (features, quotas, usage) | Planned. Not in this repo. |
| Billing (plans, subscriptions) | Planned. Not in this repo. |
| Event delivery (outbox relay) | Events are written to an outbox table. The relay that publishes them is not built yet. |
| SDKs (React, Next.js, backend) | Frozen. They will be rebuilt against the documented contract. |

## How the auth flow works

Sign-in and sign-up are **attempts**, following Clerk's model. An attempt moves through explicit states, and every auth method uses the same state machine.

```text
POST /api/v1/auth/client/sign_ins                  -> NEEDS_FIRST_FACTOR (or COMPLETE, for password)
POST /api/v1/auth/client/sign_ins/:id/prepare_first_factor   (sends the email code, or returns the OAuth URL)
POST /api/v1/auth/client/sign_ins/:id/attempt_first_factor   (submits the code)
GET  /api/v1/auth/client/sign_ins/:id              -> COMPLETE, with an access token
```

Google OAuth goes through the same attempt. The browser is sent to Google, Google calls back to `/api/v1/auth/oauth_callback`, and the callback hands off to the tenant's own domain with a short-lived handshake token. The app redeems that token to set its session cookies.

**Client identity.** Each browser has a *client*, which holds a rotating token. Every request resolves the client from exactly one of three places: the `__client` cookie, a signed `x-shipstack-client` header (backend-proxy mode), or a `__shipstack_db_jwt` pointer (development only). The request body is never trusted for identity.

**Tokens.** Access tokens are RS256 JWTs signed with the environment's private key and published at `/.well-known/jwks.json`. Any service can verify them locally, so checking a session never has to call Auth. Each session also has its own expiry, which is checked independently of the token's `exp`.

**Environments.** Every request resolves to one environment, from the Host header's project slug. A project has two environments. Development is created with the project. Production is meant to be created by the developer on purpose, once they're ready to go live (D13). That creation path is not built yet. Public keys use `pk_test_` for development and `pk_live_` for production.

## Design decisions

The reasoning is recorded in [`docs/`](docs/):

- [`docs/decisions.md`](docs/decisions.md): the decision log, D1 to D15. Each entry states what was decided and why.
- [`docs/auth-contract.md`](docs/auth-contract.md): the auth contract. Routes, attempt states, client identity, tokens, and what leaves Auth.
- [`docs/port-inventory.md`](docs/port-inventory.md): how the Auth code was split out of the earlier monolith, module by module.

The main choices:

- **Each product owns its own tables.** Auth never writes to plans, quotas, or subscriptions. Billing and Access own those (D1).
- **Plans are looked up by identity, not stored in the token.** A product reads the identity's plan from a cache kept current by events. Auth has no plan concepts at all (D12).
- **Usage is never cached.** Quota counters are requested from Access on each use (D10).
- **Bitfield permissions are planned for RBAC**, not for plans. The per-tenant permission registry is still to be designed (D11).

## Bugs found while porting

Porting the code and running its tests against a real database turned up three problems:

1. **The rotated client cookie was never sent to the browser after an OAuth sign-in.** The handshake rotated the client token on the server, but the cookies it returned left out `__client`. The browser then presented the old token on its next request, which triggered replay detection. Fixed in `createHandshakeForAttempt`.
2. **Local development hosts were rejected.** The `.stack.shipstack.development` suffix was in the docs and in the tests, but not in the code. The suffix list now lives in one module, `src/common/hosted-domains.ts`, which both the host parser and the key decoder read.
3. **Two copies of the domain list could drift apart.** They're now one.

## Running it locally

Requirements: Node 20+, pnpm, and Docker.

```bash
pnpm install
cd apps/auth
cp .env.example .env                # fill in the values
pnpm prisma:generate                # generate the Prisma clients
pnpm start:dev                      # http://localhost:9001, Swagger at /api/v1/docs
```

`.env` needs `PLATFORM_DATABASE_URL`, `CONSOLE_DATABASE_URL` (read-only), `ENCRYPTION_KEY` (64 hex characters), and `CLIENT_COOKIE_SECRET`. Email is sent through SMTP when `SMTP_HOST` is set. Without it, emails are written to the log.

## Testing

```bash
cd apps/auth
pnpm test              # 41 unit tests
pnpm test:db           # start a throwaway Postgres on :5433 and load the schemas
cp e2e/.env.test.example e2e/.env.test   # then fill in the values
pnpm test:e2e          # 73 end-to-end tests against a real database
```

The end-to-end tests run the real NestJS app over HTTP against a real Postgres. They cover sign-up, sign-in, email codes, OAuth (with the provider mocked by `nock`), sessions, token expiry, the dev-browser gate, backend-proxy auth, and error shapes.

Because Auth reads environment data that Console owns, the e2e harness loads a copy of Console's schema (`apps/auth/e2e/support/console-fixture.prisma`) to stand in for it. The Auth app itself never imports that copy.

## Known limits

- **The outbox relay is not running.** `identity.created` and other events are written in the same transaction as the change, but nothing publishes them yet.
- **Auth reads Console's tables directly** through a read-only grant. The planned replacement is a published view, so Console can change its tables without breaking Auth.
- **Password reset and email verification** are implemented, but the email path is only tested against a fake mail service.
- **No rate limiting.** It's deliberately out of v1, and it matters before any production use.
- **Google is the only OAuth provider.** Adding another means a new strategy class and a case in the default-credentials lookup. The attempt flow itself doesn't change.

## Repository layout

```text
apps/auth/            Auth service (NestJS, Prisma, Postgres)
  prisma/             platform.prisma (Auth-owned tables), console.prisma (read model)
  src/                modules/auth (attempts, sessions, OAuth), core/, common/
  e2e/                end-to-end suite and harness
docs/                 decision log, auth contract, port inventory
```

Everything else in the earlier monorepo (quotas, subscriptions, the Next.js SDKs, the Go self-hosted build, the console) stays in the source repository. It's intentionally not in this one.
