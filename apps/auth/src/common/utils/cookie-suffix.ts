import { createHash } from 'crypto';

// Deterministic, derived from the environment's publishableKey — matches
// Clerk's actual mechanism (sha1(publishableKey), base64url, first 8 chars).
// Same publishableKey always yields the same suffix; this is what lets two
// different apps sharing a cookie domain avoid colliding on cookie names,
// with zero coordination needed. Not session-specific — every Session in the
// same environment shares this same suffix.
//
// Duplicated verbatim from apps/platform-api/src/common/utils/cookie-suffix.ts
// per the migration plan's "duplicate now, don't extract" decision.
export function getCookieSuffix(publishableKey: string): string {
  const digest = createHash('sha1').update(publishableKey).digest('base64');
  return digest.replace(/\+/g, '-').replace(/\//g, '_').substring(0, 8);
}
