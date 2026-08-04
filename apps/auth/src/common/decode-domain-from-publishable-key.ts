// Mirrors sdks/backend/src/fapi-url.ts's decodeFapiUrlFromPublishableKey and
// apps/console-api/src/common/utils/slug.ts's decodePublishableKey exactly —
// same base64url payload shape, same two known suffixes. Duplicated here
// (not cross-imported — separate deployable services, matching the
// established "duplicate now, don't extract" pattern used elsewhere in this
// migration, e.g. identity-token.service.ts's own doc comment) because FAPI
// needs this specifically for OAuthCallbackController: Google's OAuth
// redirect_uri is one FIXED host (lcl.shared.dev.shipstack.run locally,
// an equivalent fixed host in prod — Google will never accept a wildcard),
// so the incoming request's own Host header is NEVER the tenant's real
// domain on this one route. The publishableKey (reachable via the pending
// SignInAttempt's environmentId) already encodes that real domain, so this
// decodes it directly instead of trusting/guessing from the request.
import { HOSTED_AUTH_DOMAIN_SUFFIXES } from './hosted-domains';

function base64UrlDecode(input: string): string {
  return Buffer.from(input, 'base64url').toString('utf-8')
}

/**
 * Decodes a tenant's real hosted-auth domain (e.g.
 * "fast-flash-7178.stack.dev.shipstack.run") from its publishableKey.
 * Always HTTPS — both known suffixes now serve real TLS (see
 * local-dns/traefik/ for the local dev Cloudflare Origin CA cert; this
 * decoder no longer branches on suffix to pick http vs https, matching the
 * SDK-side decoder's own post-migration simplification).
 * Throws on malformed input — a key that fails to decode here is a real
 * configuration problem (wrong/malformed key), not something to silently
 * paper over.
 */
export function decodeDomainFromPublishableKey(publishableKey: string): string {
  const match = publishableKey.match(/^pk_(test|live)_(.+)$/)
  if (!match) {
    throw new Error(`Invalid publishableKey: "${publishableKey}" does not match the expected pk_test_/pk_live_ shape.`)
  }

  let decoded: string
  try {
    decoded = base64UrlDecode(match[2])
  } catch {
    throw new Error('Invalid publishableKey: could not decode its payload.')
  }

  const suffix = HOSTED_AUTH_DOMAIN_SUFFIXES.find(s => decoded.endsWith(s))
  if (!suffix) {
    throw new Error(`Invalid publishableKey: decoded payload "${decoded}" does not end with a known Shipstack domain suffix.`)
  }

  return decoded
}
