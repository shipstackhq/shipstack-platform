import { sign as signJwt, verify as verifyJwt } from 'jsonwebtoken';
import type { Response } from 'express';
import { getCookieSuffix } from '@/common/utils/cookie-suffix';

// Direct mode's __client cookie is set by platform-api itself (there is no
// tenant backend to do it, unlike backend-proxy mode) — see AUTH_STATUS.md
// item 2. Signed with platform-api's own key, not the tenant's secretKey
// (which the browser never has access to). This is purely a tamper-evident
// envelope, mirroring sdks/nextjs/src/internal/handler-core.ts's __client
// cookie — platform-api never trusts the JWT-ness itself, only the decoded
// {clientId, clientToken} fields, which are re-validated against the DB on
// every use via resolveClient().
export const CLIENT_COOKIE = '__client';
export const CLIENT_COOKIE_MAX_AGE_SECONDS = 60 * 24 * 60 * 60; // matches Client's own TTL

// Backend-proxy transport for the same signed {clientId, clientToken}
// envelope __client carries as a cookie — a header, not a body field.
// Confirmed this session: a backend-proxy caller (the tenant's own
// server, Basic-auth-authenticated) has no shared cookie jar with FAPI at
// all. It gets signClientCookie's raw JWT back in the JSON response body
// (see clientBootstrap/relayClient's own comments), sets THAT as its own
// __client cookie on its own domain, and on every later request needs to
// relay the SAME signed value back to FAPI somehow. A body field was
// rejected: it would need per-caller-type enforcement (a browser could
// send it too, reopening the exact leak the earlier
// guard-consolidation/DTO cleanup closed) and doesn't work on a bodyless
// GET (the sign_ins/sign_ups :id reload route). A header has neither
// problem — no browser ambiently populates a custom header the way
// cookies auto-attach, and headers work identically on GET and POST.
// Carries the JWT verbatim (not decoded clientId/clientToken) so FAPI
// stays the one signing/verifying authority either way — see
// signClientCookie's own doc comment.
export const CLIENT_HEADER = 'x-shipstack-client';

// Handshake redirect-loop guard — matches Clerk's own __clerk_redirect_count
// (verified via source: checkAndTrackRedirectLoop, capped at exactly 3).
// Mirrors sdks/nextjs's own REDIRECT_COUNT_COOKIE, but this one is FAPI's
// own — a separate cookie jar (FAPI's cross-site domain in dev mode), since
// FAPI's /auth/handshake is a genuinely different hop than the tenant
// backend's own /auth/handshake route.
export const REDIRECT_COUNT_COOKIE = '__shipstack_redirect_count';

interface ClientCookiePayload {
  id: string;
  rotating_token: string;
}

function signingSecret(): string {
  const secret = process.env.CLIENT_COOKIE_SECRET;
  if (!secret) throw new Error('CLIENT_COOKIE_SECRET is not configured');
  return secret;
}

export function readClientCookie(rawCookie: string | undefined): { clientId: string; clientToken: string } | null {
  if (!rawCookie) return null;
  try {
    const payload = verifyJwt(rawCookie, signingSecret()) as unknown as ClientCookiePayload;
    return { clientId: payload.id, clientToken: payload.rotating_token };
  } catch {
    return null;
  }
}

// Single resolution point for "which client is this request acting as,"
// covering both transports: CLIENT_HEADER for backend-proxy (Basic-auth)
// callers, CLIENT_COOKIE for direct-mode browsers. Header takes precedence
// when both are somehow present — a backend-proxy caller (server-to-server,
// Basic auth) is never also a browser with FAPI's own cookie, so this
// never has to arbitrate a genuine conflict, just picks whichever transport
// actually applies to this caller type. Every controller route that
// previously called readClientCookie(cookieValue) directly should call this
// instead, so the header path isn't reimplemented per call site.
export function resolveClientFromRequest(req: { headers?: Record<string, unknown>; cookies?: Record<string, string> }): { clientId: string; clientToken: string } | null {
  const headerValue = req.headers?.[CLIENT_HEADER];
  if (typeof headerValue === 'string') {
    const fromHeader = readClientCookie(headerValue);
    if (fromHeader) return fromHeader;
  }
  return readClientCookie(req.cookies?.[CLIENT_COOKIE]);
}

// SameSite=None requires Secure per spec, and Secure cookies are dropped by
// browsers on plain http:// — which is how localhost dev runs. Cross-site
// SameSite=None+Secure is correct for real (HTTPS) deployments; local dev
// falls back to Lax+non-Secure, which only works because dev is same-site
// (browser and platform-api both on localhost). Not a security-relevant
// downgrade — it only affects whether local testing works at all.
const isProd = process.env.NODE_ENV === 'production';

// isDevBrowserRequest is a required (not optional) third argument —
// deliberately, so every call site must make the decision explicit at the
// type level instead of silently defaulting to "always set the cookie,"
// which is exactly how register/login/refresh/oauth-exchange ended up
// wrong (added before the dev-browser mechanism existed, never revisited).
// A dev/staging cross-site caller can't reliably receive/use this cookie
// anyway (see DevBrowser's doc comment in platform.prisma), so attempting
// to set it there isn't just useless, it's misleading — better to visibly
// skip it than pretend it worked.
// Signs the same tamper-evident envelope setClientCookie() paints as a
// Set-Cookie header, without touching res — exposed separately so
// backend-proxy responses (EnvironmentGuard's req.isBackendProxy) can ALSO
// return this raw JWT string in the JSON body. Backend-proxy callers (a
// tenant's own Next.js
// server, @shipstack/nextjs's route handler) receive FAPI's own Set-Cookie
// header on FAPI's OWN domain, which the tenant's server never forwards to
// its own browser cookie jar — it needs the raw value to re-set as ITS OWN
// httpOnly cookie instead. Relaying this signed value verbatim, rather
// than the tenant's server independently re-signing {clientId,
// clientToken} with its own secretKey, keeps FAPI (CLIENT_COOKIE_SECRET)
// as the ONE signing authority for this cookie in both direct and
// backend-proxy mode — the tenant's secretKey is used for Basic-auth calls
// to FAPI, never for this.
export function signClientCookie(clientId: string, clientToken: string): string {
  return signJwt({ id: clientId, rotating_token: clientToken }, signingSecret(), {
    algorithm: 'HS256',
    expiresIn: CLIENT_COOKIE_MAX_AGE_SECONDS,
  });
}

export function setClientCookie(res: Response, clientId: string, clientToken: string, isDevBrowserRequest: boolean): void {
  if (isDevBrowserRequest) return;
  const jwt = signClientCookie(clientId, clientToken);
  res.cookie(CLIENT_COOKIE, jwt, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: CLIENT_COOKIE_MAX_AGE_SECONDS * 1000,
    path: '/',
  });
}

export function clearClientCookie(res: Response): void {
  res.clearCookie(CLIENT_COOKIE, { httpOnly: true, secure: isProd, sameSite: isProd ? 'none' : 'lax', path: '/' });
}

// __refresh_<suffix> — a per-session recovery secret, minted/ROTATED
// exclusively by AuthService.createHandshake() (see that method's own doc
// comment), never by attempt completion (create()/attemptFirstFactor()/
// resolveExternal()) — one consistent issuance path in both direct and
// backend-proxy mode, rather than the browser needing to already hold one
// from sign-in time. Modeled on Clerk's own __refresh cookie — confirmed
// via packages/backend/src/constants.ts (Cookies.Refresh = '__refresh') and
// authenticateContext.ts (read via getSuffixedCookie, i.e. suffixed and
// httpOnly, never exposed to clerk-js/browser JS at all) in this session's
// clerk-javascript-reference audit, including a live captured Clerk network
// trace showing __refresh issued specifically by the handshake response,
// not by sign-in/sign-up completion. Unlike __client, this is NOT a signed
// JWT envelope — it's an opaque, high-entropy random secret that FAPI
// validates by hashed DB lookup (resolveSessionByRefreshToken), so there's
// nothing to sign/verify locally; the cookie IS the credential. Suffixed
// (getCookieSuffix(publishableKey)) to match __session_<suffix>/
// __client_uat_<suffix>'s own per-publishable-key namespacing — NOT a
// session identifier itself, just avoids collisions between multiple
// Shipstack projects sharing a browser.
const REFRESH_COOKIE_PREFIX = '__refresh';
const REFRESH_COOKIE_MAX_AGE_SECONDS = 60 * 24 * 60 * 60; // matches Session's own refreshTokenTtl ceiling; actual expiry is DB-enforced via Session.expiresAt regardless of cookie lifetime

export function refreshCookieName(publishableKey: string): string {
  return `${REFRESH_COOKIE_PREFIX}_${getCookieSuffix(publishableKey)}`;
}

// Direct mode only — see class-level comment on backend-proxy's own
// treatment (relayed once in the JSON response body instead, same
// signedClientCookie-style transport __client already uses, since a
// Set-Cookie here would land on FAPI's own domain in the tenant server's
// outgoing fetch client, not the tenant's domain).
export function setRefreshCookie(res: Response, publishableKey: string, refreshToken: string): void {
  res.cookie(refreshCookieName(publishableKey), refreshToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: REFRESH_COOKIE_MAX_AGE_SECONDS * 1000,
    path: '/',
  });
}
