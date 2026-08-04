// Mirrors Clerk's actual FAPI behavior: the browser never sends an explicit
// publishableKey on any request (confirmed against clerk-javascript-reference's
// packages/clerk-js/src/core/fapiClient.ts — it uses the key-derived hostname
// purely to build the request URL, never attaches the key itself anywhere).
// The per-project subdomain IS the identity signal server-side, same as it
// already is for DNS/Traefik routing purposes — this just makes FAPI actually
// use it, instead of requiring a redundant explicit ?publishableKey= on top.
//
// Two suffixes are recognized, matching apps/console-api/src/common/utils/
// slug.ts's encoder exactly — this file must stay in lockstep with that one.
// Domain is shared across ShipStack's future product lines (auth, access,
// billing), not auth-specific — no "auth." segment.
import { HOSTED_AUTH_DOMAIN_SUFFIXES } from './hosted-domains';

/**
 * Extracts the project slug from a request's Host header, if it matches the
 * per-project wildcard pattern (<slug>.stack.shipstack.{run|development}).
 * Returns null for any other host.
 */
export function resolveSlugFromHost(hostHeader: string | undefined): string | null {
  if (!hostHeader) return null
  const host = hostHeader.split(':')[0] // strip port, if present (e.g. local dev)
  const suffix = HOSTED_AUTH_DOMAIN_SUFFIXES.find(s => host.endsWith(s))
  if (!suffix) return null
  const slug = host.slice(0, -suffix.length)
  // Guard against a bare ".stack.shipstack.run" (empty slug) or a slug
  // containing another dot (shouldn't happen given the guard-rail slug
  // generator in console-api, but never trust request-derived input).
  if (!slug || slug.includes('.')) return null
  return slug
}
