import { ForbiddenException } from '@nestjs/common';
import type { Environment } from '@/generated/console/client';

// Copied verbatim from apps/platform-api/src/common/direct-mode-guard.ts per
// the migration plan's explicit instruction ("This must be preserved in
// FAPI's version of these routes — copy it verbatim"). Only the Environment
// import path differs (FAPI's generated console client, not platform-api's
// combined generated/prisma client) since FAPI reads Environment from the
// console schema directly rather than through platform-api's merged client.
//
// Direct/frontend-only mode's __client cookie can only be first-party
// (SameSite=Lax/Strict, reliable in Safari and hardened Chrome) when the
// browser and platform-api share a registrable domain — which requires a
// verified custom domain. Environment has no such field yet (that's the real
// scope of AUTH_STATUS.md item 5: DNS verification, TLS automation, Host-
// based routing). Until it exists, a PRODUCTION-type environment cannot
// support direct mode at all — not a degraded SameSite=None fallback, an
// outright block. This mirrors Clerk's own instance model: a Clerk
// *production* instance is required to have a custom domain as a
// precondition of being production, full stop; there is no supported
// "production instance, no custom domain yet" state.
//
// DEVELOPMENT-type environments are unaffected — they're expected to run
// cross-site against stack.shipstack.run by design (same as Clerk's
// *.clerk.accounts.dev dev instances), and rely on the dev-only querystring
// relay (see dev-client-relay.ts) instead of a same-site cookie.
export function assertDirectModeAllowed(environment: Pick<Environment, 'type'>): void {
  if (environment.type === 'PRODUCTION') {
    throw new ForbiddenException(
      'Direct/frontend-only auth mode requires a verified custom domain on production environments (not yet supported — see AUTH_STATUS.md item 5). Use backend-proxy mode (backendUrl) for production, or a development environment for now.',
    );
  }
}
