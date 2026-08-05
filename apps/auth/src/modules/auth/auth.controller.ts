import { BadRequestException, Body, Controller, Delete, Get, NotImplementedException, Patch, Post, Put, Query, Req, Res, UnauthorizedException, UseGuards } from '@nestjs/common';
import { ApiBasicAuth, ApiCookieAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { EnvironmentGuard } from '@/common/guards/environment.guard';
import { SessionGuard } from '@/common/guards/session.guard';
import { resolveClientFromRequest, setClientCookie, signClientCookie, REDIRECT_COUNT_COOKIE } from '@/common/client-cookie';
import { CookieValue } from '@/common/decorators/cookie-value.decorator';
import { assertDirectModeAllowed } from '@/common/direct-mode-guard';
import { ApiCodedErrorResponse, FlatErrorEnvelope } from '@/common/swagger/error-envelopes';
import { ClientBootstrapDto } from './dto/client-bootstrap.dto';
import { RefreshDto } from './dto/refresh.dto';
import { RefreshFromTokenDto } from './dto/refresh-from-token.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResendVerificationDto } from './dto/resend-verification.dto';
import { PasswordResetConfirmDto } from './dto/password-reset-confirm.dto';
import { VerifyTokenDto } from './dto/verify-token.dto';
import { PasswordResetRequestDto } from './dto/password-reset-request.dto';
import { LogoutAllDto } from './dto/logout-all.dto';
import { UpdateMeDto } from './dto/update-me.dto';
import { ChangePasswordSelfDto } from './dto/change-password-self.dto';

// Phase 1 of the BAPI/FAPI migration: these routes are the FAPI-A slice
// moved from platform-api's identities/auth/public/* twins, with the
// `public/` prefix and redundant `/auth` nesting dropped per the plan's
// naming section (identities/auth/public/register -> auth/register, etc).
// register/login themselves were later deleted in the Phase 9 cutover
// (docs/unified-attempt-architecture.md) — see the comment where they used
// to live, below.
//
// Every route below runs behind EnvironmentGuard, which resolves
// req.environment from the Host header and additionally attaches
// req.isBackendProxy when a valid secretKey was presented via
// Authorization: Basic (sdks/nextjs's handler-core.ts calling through
// sdks/core/src/auth.ts) — the same guard serves both direct/browser mode
// and backend-proxy mode on the same route. One real behavior change this
// requires: assertDirectModeAllowed() must be skipped when
// req.isBackendProxy is true — that check exists to block *browser*
// cookie-based direct mode on PRODUCTION environments (no custom-domain
// support yet), but backend-proxy mode never relies on FAPI's own-domain
// cookie at all (the tenant's own backend holds the secretKey and proxies
// to its own browser), so gating it on the same rule would incorrectly
// break backend-proxy mode's whole reason for existing. See
// assertIfDirectMode() helper below.
@ApiTags('Client / session bootstrap')
@ApiCookieAuth('directModeCookie')
@ApiBasicAuth('backendProxyBasicAuth')
@Controller('auth')
export class AuthController {
  constructor(private readonly service: AuthService) {}

  // Wraps assertDirectModeAllowed() to no-op for backend-proxy callers —
  // see class-level comment.
  private assertIfDirectMode(req: Request, environment: Parameters<typeof assertDirectModeAllowed>[0]): void {
    if ((req as any).isBackendProxy) return;
    assertDirectModeAllowed(environment);
  }

  // Mirrors Clerk's own GET /v1/dev_browser (verb confirmed via clerk-js
  // source: devBrowser.ts calls fetch(..., { method: 'POST' })). Mints an
  // opaque, unauthenticated pointer used by dev/staging callers who can't
  // reliably carry the real httpOnly __client cookie cross-site — see
  // DevBrowser's doc comment in platform.prisma. Guarded by
  // EnvironmentGuard only: this runs before any Client exists and needs
  // no session/secret context, just environment resolution from the
  // Host header (the guard's own stated purpose).
  @ApiOperation({ summary: 'Mint a dev-browser pointer (cross-site dev/staging substitute for the __client cookie)' })
  @ApiResponse({ status: 201 })
  @Post('dev_browser')
  @UseGuards(EnvironmentGuard)
  async devBrowser(@Req() req: Request) {
    const environment = (req as any).environment;
    const result = await this.service.createDevBrowser(environment.id);
    return {
      id: result.id,
      instance_id: environment.id,
      token: result.token,
      client_id: null,
      created_at: result.createdAt,
      updated_at: result.updatedAt,
      home_origin: null,
    };
  }

  // FAPI-hosted handshake — the counterpart to sdks/nextjs's own backend-
  // proxy /auth/handshake route, needed because THAT route only ever runs
  // same-site (the tenant's own backend) and so can paint cookies directly.
  // A direct-mode caller (no tenant backend, browser talking straight to
  // FAPI) has exactly Clerk's cross-site problem in dev/staging — FAPI's
  // own Set-Cookie headers on a cross-site response won't land on the
  // app's origin, so instead this route signs the resolved cookie
  // directives into a JWT and redirects, mirroring Clerk's own
  // __clerk_handshake mechanism (confirmed via decoding a real Clerk
  // handshake token this session — same payload key, same
  // full-Set-Cookie-string shape). format=nonce (an authenticated
  // server-to-server alternative to trusting a client-parsed JWT, which
  // Clerk also supports) is deliberately NOT built yet — no concrete
  // consumer for it exists in this codebase yet, and speculative unused
  // surface is exactly what this codebase has already had to walk back
  // once (sdks/ui). Add it when something actually needs it.
  //
  // No dev_browser query param present is itself meaningful (Clerk's own
  // DevBrowserMissing case) — a fresh DevBrowser is minted as part of the
  // same round trip rather than requiring the caller to have already
  // called POST /auth/dev_browser first, matching Clerk's real behavior.
  @ApiOperation({
    summary: 'Reconcile a desynced session/client cookie via redirect (Clerk-style handshake)',
    description: 'Not JSON — responds with a 302 redirect back to redirect_url, with a signed __shipstack_handshake token appended for the app\'s own same-site response to consume.',
  })
  @ApiResponse({ status: 302 })
  @ApiResponse({ status: 400, type: FlatErrorEnvelope, description: 'redirect_url is required.' })
  @ApiResponse({ status: 501, type: FlatErrorEnvelope, description: 'format=nonce is not yet supported.' })
  @Get('client/handshake')
  @UseGuards(EnvironmentGuard)
  async handshake(
    @Req() req: Request,
    @Res() res: Response,
    @Query('redirect_url') redirectUrl: string | undefined,
    @Query('dev_browser') devBrowserId: string | undefined,
    @Query('format') format: string | undefined,
    @CookieValue(REDIRECT_COUNT_COOKIE) redirectCountCookie: string | undefined,
  ) {
    if (format === 'nonce') {
      throw new NotImplementedException('format=nonce is not yet supported for /auth/handshake');
    }
    if (!redirectUrl) throw new BadRequestException('redirect_url is required');

    const environment = (req as any).environment;

    // Loop guard, mirrors Clerk's own __clerk_redirect_count (verified via
    // source: checkAndTrackRedirectLoop, capped at exactly 3). A genuinely
    // unresolvable dev-browser/session state would otherwise redirect here
    // forever, since a fresh handshake attempt looks identical to the last.
    const redirectCount = Number(redirectCountCookie ?? '0');
    if (redirectCount >= 3) {
      res.clearCookie(REDIRECT_COUNT_COOKIE, { path: '/' });
      return res.redirect(redirectUrl);
    }

    const result = await this.service.createHandshake(devBrowserId, environment.id);
    res.cookie(REDIRECT_COUNT_COOKIE, String(redirectCount + 1), { httpOnly: true, maxAge: 60_000, path: '/' });

    const destination = new URL(redirectUrl);
    destination.searchParams.set('__shipstack_handshake', result.token);
    return res.redirect(destination.toString());
  }

  // Route named 'client', not 'client-bootstrap' — matches Clerk's own
  // FAPI resource exactly (pathRoot = '/client' in their clerk-js Client.ts).
  // "Bootstrap" describes what this call does internally (mints a fresh
  // Client if none exists), not what a caller is asking for ("give me the
  // current Client") — the shorter name is also what handler-core.ts's own
  // browser-facing GET /client route already converged on independently,
  // this just removes the translation layer between the two surfaces.
  //
  // Full CRUD, matching Clerk's GET/PUT/POST/DELETE /v1/client exactly:
  //   GET    — pure read, never rotates the token or touches session state.
  //   POST   — bootstrap: mint-or-resolve the Client, rotate its token.
  //   PUT    — same behavior as POST (Clerk's own PUT /client is
  //            undocumented/reserved; no divergent behavior to give it yet).
  //   DELETE — end every active session for the client. The Client row
  //            itself is NOT deleted (mirrors logout()'s existing "cookie
  //            survives" behavior) — same underlying operation as
  //            DELETE /auth/client/sessions, so both routes call
  //            service.logout() with no sessionId rather than duplicating
  //            the bulk-update logic.
  private async bootstrapAndRespond(req: Request, res: Response, dto: ClientBootstrapDto, devBrowserId: string | undefined) {
    const environment = (req as any).environment;
    this.assertIfDirectMode(req, environment);

    if (devBrowserId) {
      // Dev-browser path — resolves/creates the Client via the DevBrowser
      // row's mapping. MUST NOT call setClientCookie() here: the entire
      // point of this path is that a cross-site dev/staging request can't
      // reliably receive/use an httpOnly cookie, so we stop attempting to
      // set one rather than silently failing to deliver it.
      const result = await this.service.clientBootstrapViaDevBrowser(devBrowserId, environment.id, dto.activeSessionRefreshToken);
      return { ...result, devMode: true };
    }

    const fromClient = resolveClientFromRequest(req);
    const result = await this.service.clientBootstrap(fromClient?.clientId, fromClient?.clientToken, environment.id, dto.activeSessionRefreshToken);
    const isBackendProxy = (req as any).isBackendProxy;
    // Backend-proxy callers (the tenant's own server, never a direct-mode
    // browser) can't use a Set-Cookie header here — it's on FAPI's own
    // domain — so setClientCookie is skipped for them entirely; they relay
    // signedClientCookie below as their own cookie instead. See
    // signClientCookie's own doc comment for why this is FAPI's signature,
    // not the tenant re-signing with their secretKey.
    if (!isBackendProxy) {
      setClientCookie(res, result.clientId, result.clientToken, false);
    }
    return {
      ...result,
      devMode: environment.type === 'DEVELOPMENT',
      ...(isBackendProxy ? { signedClientCookie: signClientCookie(result.clientId, result.clientToken) } : {}),
    };
  }

  @ApiOperation({
    summary: 'Bootstrap the Client (mint-or-resolve, rotate its token)',
    description: 'Direct mode gets the rotated pair back as a Set-Cookie __client; backend-proxy mode gets it as signedClientCookie in the body instead — see the class comment for why.',
  })
  @ApiResponse({ status: 201 })
  @ApiResponse({ status: 403, type: FlatErrorEnvelope, description: 'Direct/cookie mode on a PRODUCTION environment (no custom-domain support yet) — use backend-proxy mode instead.' })
  @Post('client')
  @UseGuards(EnvironmentGuard)
  async clientBootstrap(
    @Req() req: Request,
    @Body() dto: ClientBootstrapDto,
    @Res({ passthrough: true }) res: Response,
    @Query('__shipstack_db_jwt') devBrowserId: string | undefined,
  ) {
    return this.bootstrapAndRespond(req, res, dto, devBrowserId);
  }

  @ApiOperation({ summary: 'Same behavior as POST /client — Clerk\'s own PUT /client is undocumented/reserved, no divergent behavior given to it here either.' })
  @ApiResponse({ status: 201 })
  @ApiResponse({ status: 403, type: FlatErrorEnvelope })
  @Put('client')
  @UseGuards(EnvironmentGuard)
  async clientPut(
    @Req() req: Request,
    @Body() dto: ClientBootstrapDto,
    @Res({ passthrough: true }) res: Response,
    @Query('__shipstack_db_jwt') devBrowserId: string | undefined,
  ) {
    return this.bootstrapAndRespond(req, res, dto, devBrowserId);
  }

  @ApiOperation({ summary: 'Read the current Client — pure read, never rotates the token or touches session state.' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 403, type: FlatErrorEnvelope })
  @Get('client')
  @UseGuards(EnvironmentGuard)
  async clientGet(
    @Req() req: Request,
    @Query('__shipstack_db_jwt') devBrowserId: string | undefined,
  ) {
    const environment = (req as any).environment;
    this.assertIfDirectMode(req, environment);

    if (devBrowserId) {
      // See bootstrapAndRespond's identical branch — a cross-site dev
      // request has no __client cookie to read at all, so GET must resolve
      // through the DevBrowser mapping too, not just POST/PUT.
      const bootstrapped = await this.service.clientBootstrapViaDevBrowser(devBrowserId, environment.id);
      return this.service.fetchClient(bootstrapped.clientId, bootstrapped.clientToken, environment.id);
    }
    const fromClient = resolveClientFromRequest(req);
    return this.service.fetchClient(fromClient?.clientId, fromClient?.clientToken, environment.id);
  }

  @ApiOperation({ summary: 'End every active session for this Client (the Client row/cookie itself survives).' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 403, type: FlatErrorEnvelope })
  @Delete('client')
  @UseGuards(EnvironmentGuard)
  async clientDelete(
    @Req() req: Request,
    @Query('__shipstack_db_jwt') devBrowserId: string | undefined,
  ) {
    const environment = (req as any).environment;
    this.assertIfDirectMode(req, environment);

    if (devBrowserId) {
      const bootstrapped = await this.service.clientBootstrapViaDevBrowser(devBrowserId, environment.id);
      return this.service.logout(bootstrapped.clientId);
    }
    const fromClient = resolveClientFromRequest(req);
    if (!fromClient?.clientId) return { ok: true };
    // __client cookie survives, same as logout() — see that method's own
    // comment. Only session state changes; the Client row/cookie persist so
    // a later sign-in on the same device reuses it.
    return this.service.logout(fromClient.clientId);
  }

  // register/login deleted (Phase 9 cutover,
  // docs/unified-attempt-architecture.md) — superseded by
  // POST /auth/sign_ups and POST /auth/sign_ins (EMAIL_PASSWORD strategy).
  // See AuthService.verifyPasswordCredential/createPasswordIdentity for the
  // shared logic those routes' strategies still depend on.

  // Renamed from /refresh to /tokens — this is Shipstack's equivalent of
  // Clerk's own FAPI /tokens (browser/live-caller, cookie-or-header
  // authenticated, ambient — no explicit refresh-token param required,
  // resolves whichever session is already current for this client). NOT
  // the same job as POST /auth/client/refresh below — see that route's own
  // doc comment for the distinction (this session's own investigation
  // found the two had been conflated into one endpoint, causing a caller
  // with no ambient cookie jar, like Edge middleware, to have no way to
  // use it at all).
  @ApiOperation({
    summary: 'Mint a fresh access token for the active (or a specific) session',
    description: 'A session past its refreshTokenTtl expiresAt degrades gracefully to sessions:[]/activeSessionId:null, not an error.',
  })
  @ApiResponse({ status: 201 })
  @ApiResponse({ status: 401, type: FlatErrorEnvelope, description: 'No client resolvable from a cookie or the x-shipstack-client header.' })
  @ApiResponse({ status: 403, type: FlatErrorEnvelope, description: 'Direct/cookie mode on a PRODUCTION environment.' })
  @Post('client/tokens')
  @UseGuards(EnvironmentGuard)
  async tokens(
    @Req() req: Request,
    @Body() dto: RefreshDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const environment = (req as any).environment;
    this.assertIfDirectMode(req, environment);
    const fromClient = resolveClientFromRequest(req);
    if (!fromClient?.clientId || !fromClient?.clientToken) throw new UnauthorizedException('No client');
    const result = await this.service.refreshSession(fromClient.clientId, fromClient.clientToken, environment.id, dto.sessionRefreshToken);
    const isBackendProxy = (req as any).isBackendProxy;
    // See bootstrapAndRespond()'s identical comment above.
    if (!isBackendProxy) {
      setClientCookie(res, result.clientId, result.clientToken, (req as any).isDevBrowserRequest);
    }
    return {
      ...result,
      devMode: environment.type === 'DEVELOPMENT',
      ...(isBackendProxy ? { signedClientCookie: signClientCookie(result.clientId, result.clientToken) } : {}),
    };
  }

  // Clerk-BAPI-/refresh-equivalent — the SSR/middleware recovery path,
  // NOT the browser's own /tokens call above. Server-only: requires a
  // secretKey (same isBackendProxy mechanism every other backend-proxy
  // route already uses — confirmed this session there's no meaningful
  // blast-radius difference between FAPI and BAPI accepting the same
  // tenant secretKey, since BAPI's own admin surface is already reachable
  // with it). Authenticates purely via {sessionId, refreshToken} — no
  // clientId/clientToken re-proof at all, matching Clerk's own
  // sessions.refreshSession(sessionId, { refresh_token }) contract exactly
  // (confirmed via source read this session): possessing the correct
  // refreshToken for that exact session IS the proof, since it's an
  // opaque, high-entropy secret validated by hashed DB lookup
  // (AuthService.refreshFromToken). sessionId is the caller's own
  // responsibility to have decoded from its already-expired access token
  // (JWT payload's own `sid` claim) — this route never tries to derive it
  // from a cookie or header at all, so it works identically whether the
  // caller is Edge middleware with no ambient cookie jar, or any other
  // server-side context.
  @ApiOperation({
    summary: 'Recover a session server-side using its refresh token (no client cookie required)',
    description: 'For SSR/middleware callers with no ambient cookie jar — pass the sessionId (decoded from the expired access token) and the refreshToken from the __refresh_<suffix> cookie explicitly. Rotates the refresh token on success, same as GET /auth/client/handshake.',
  })
  @ApiResponse({ status: 201 })
  @ApiResponse({ status: 401, type: FlatErrorEnvelope, description: 'secretKey required, or refreshToken invalid/expired/revoked for the given session.' })
  @Post('client/refresh')
  @UseGuards(EnvironmentGuard)
  async refreshFromToken(@Req() req: Request, @Body() dto: RefreshFromTokenDto) {
    if (!(req as any).isBackendProxy) throw new UnauthorizedException('secretKey required');
    const environment = (req as any).environment;
    return this.service.refreshFromToken(dto.sessionId, dto.refreshToken, environment.id);
  }

  // logout/logout-all-current-client absorbed into the client/session
  // resource (Phase D of the client-as-root routing pass): what was
  // POST /auth/logout is now DELETE /auth/client (or DELETE
  // /auth/client/sessions, same underlying AuthService.logout() call) for
  // "end everything", and POST /auth/client/sessions/:id/end for a single
  // session — see AuthController's /auth/client routes and
  // SessionsController. logout-all (revoke every session for an IDENTITY
  // across every client/device, not just the current one) has no
  // client-scoped equivalent and stays put, below.

  @ApiOperation({ summary: 'Consume an email verification token', description: 'No EnvironmentGuard — the token itself is the credential. Cannot be reused once consumed.' })
  @ApiResponse({ status: 201 })
  @ApiResponse({ status: 400, type: FlatErrorEnvelope, description: 'Token invalid, expired, or already used.' })
  @Post('verify-email')
  verifyEmail(@Body() dto: VerifyEmailDto) {
    return this.service.verifyEmail(dto.token);
  }

  @ApiOperation({ summary: 'Re-send the verification email', description: 'Always returns {ok:true} — a no-op for an unknown or already-verified identity (enumeration-safe).' })
  @ApiResponse({ status: 201 })
  @Post('resend-verification')
  @UseGuards(EnvironmentGuard)
  async resendVerification(@Req() req: Request, @Body() dto: ResendVerificationDto) {
    const environment = (req as any).environment;
    return this.service.resendVerification(environment.id, dto.email);
  }

  @ApiOperation({ summary: 'Confirm a password reset', description: 'No EnvironmentGuard — the reset token itself is the credential. Revokes every active session for the identity.' })
  @ApiResponse({ status: 201 })
  @ApiResponse({ status: 400, type: FlatErrorEnvelope, description: 'Token invalid, expired, or already used.' })
  @Post('password-reset/confirm')
  passwordResetConfirm(@Body() dto: PasswordResetConfirmDto) {
    return this.service.passwordResetConfirm(dto);
  }

  // ── Phase 2 additions ───────────────────────────────────────────────────────

  // Tier C, not Tier A: verified via sdks/core/src/auth.ts + http.ts — the
  // SDK's HttpClient always sends `Authorization: Basic
  // publishableKey:secretKey` (constructed once in the constructor, reused
  // for every call including verify()), and identities-auth.controller.ts's
  // platform-api twin also gates `verify` behind ProjectAuthGuard
  // (secret-bearer). So backend-proxy mode genuinely calls this WITH a
  // secretKey, even though the underlying operation (JWT signature check)
  // needs nothing but the publishableKey to resolve the issuer's key. Tier C
  // accepts both shapes on one route, matching how it's actually called
  // today, rather than speculatively splitting into a Tier A variant no
  // current caller uses.
  @ApiOperation({ summary: 'Verify an access token', description: 'Stateless JWT verification against the issuer\'s own key — no DB write, no client/session cookie needed.' })
  @ApiResponse({ status: 201, description: '{ shipstackId, publishableKey, sessionId, valid: true }' })
  @ApiCodedErrorResponse(401, 'The token is malformed, signed by a different issuer, or its exp claim has already elapsed.')
  @Post('verify')
  @UseGuards(EnvironmentGuard)
  async verify(@Req() req: Request, @Body() dto: VerifyTokenDto) {
    const environment = (req as any).environment;
    return this.service.verify(dto.accessToken, environment.publishableKey);
  }

  // change-password removed — was the body-trusted (dto.shipstackId) Tier C
  // variant this route's own comment already flagged as needing a
  // self-service replacement. PATCH /auth/me/password (Tier B, target
  // derived from the verified session, never the body) is that replacement
  // and is a strict improvement, not just a rename — see updateMyPassword
  // below. AuthService.changePassword()/changePasswordSelf() themselves are
  // untouched; only this route is gone.

  // Tier A shape (publishableKey alone suffices — identity is looked up by
  // email, response is always {ok:true}), mounted under Tier C since
  // backend-proxy also calls it and Tier C is a strict superset.
  @ApiOperation({ summary: 'Request a password reset email', description: 'Always returns {ok:true} — a no-op for an unknown email (enumeration-safe).' })
  @ApiResponse({ status: 201 })
  @Post('password-reset/request')
  @UseGuards(EnvironmentGuard)
  async passwordResetRequest(@Req() req: Request, @Body() dto: PasswordResetRequestDto) {
    const environment = (req as any).environment;
    return this.service.passwordResetRequest(dto, environment.id);
  }

  // Tier C only — same shape/gap as change-password (dto.shipstackId
  // trusted directly). See auth.service.ts's logoutAll().
  @ApiOperation({ summary: 'Revoke every session for an identity, across every client/device', description: 'Tier C (backend-proxy/secretKey-bearer) only — target identity trusted directly from the body, not derived from a session.' })
  @ApiResponse({ status: 201 })
  @Post('logout-all')
  @UseGuards(EnvironmentGuard)
  async logoutAll(@Req() req: Request, @Body() dto: LogoutAllDto) {
    const environment = (req as any).environment;
    return this.service.logoutAll(dto.shipstackId, environment.id);
  }

  // NEW — does not exist anywhere on platform-api. Tier B (SessionGuard):
  // the target identity is derived from req.identity.sub (the verified
  // __session JWT), never from the request body — this is the one place
  // SessionGuard's best-effort req.identity decoding becomes load-bearing,
  // so it's hard-required here (throws if missing) even though SessionGuard
  // itself doesn't universally enforce it for other routes yet (see
  // session.guard.ts's class comment).
  @ApiOperation({ summary: 'Update the signed-in identity\'s own profile', description: 'Tier B (SessionGuard) — the target identity is always the __session-verified caller, never trusted from the body.' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 401, type: FlatErrorEnvelope, description: 'No valid __session.' })
  @Patch('me')
  @UseGuards(SessionGuard)
  async updateMe(@Req() req: Request, @Body() dto: UpdateMeDto) {
    const identity = (req as any).identity;
    if (!identity?.sub) {
      throw new UnauthorizedException('Valid session required');
    }
    const environment = (req as any).environment;
    return this.service.updateMe(identity.sub, environment.id, dto);
  }

  // NEW — self-service password change. Tier B (SessionGuard): the target
  // identity is derived from req.identity.sub (verified __session JWT),
  // never from the request body — mirrors updateMe's pattern above exactly.
  // This is the "future self-service variant" flagged in change-password's
  // comment (and in auth.service.ts's changePassword()): same validation/
  // argon2/session-revocation logic as the Tier C route, but body cannot
  // name a target identity since ChangePasswordSelfDto has no such field.
  // Named `me/password` (not a new top-level `change-password-self`) to read
  // consistently with the existing `PATCH auth/me` self-service convention.
  @ApiOperation({ summary: 'Self-service password change', description: 'Tier B (SessionGuard) — target identity derived from __session, never the body. Revokes existing sessions on success, same as the reset-confirm flow.' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 401, type: FlatErrorEnvelope, description: 'No valid __session.' })
  @ApiCodedErrorResponse(401, 'currentPassword does not match (password_incorrect).')
  @ApiCodedErrorResponse(404, 'Identity not found for this session (identity_not_found).')
  @Patch('me/password')
  @UseGuards(SessionGuard)
  async updateMyPassword(@Req() req: Request, @Body() dto: ChangePasswordSelfDto) {
    const identity = (req as any).identity;
    if (!identity?.sub) {
      throw new UnauthorizedException('Valid session required');
    }
    const environment = (req as any).environment;
    return this.service.changePasswordSelf(identity.sub, environment.id, dto.currentPassword, dto.newPassword);
  }
}
