import { BadRequestException, Body, Controller, Get, Param, Post, Query, Req, Res, UseGuards } from '@nestjs/common';
import { ApiBasicAuth, ApiCookieAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { EnvironmentGuard } from '@/common/guards/environment.guard';
import { PlatformPrismaService } from '@/core/database/platform-prisma.service';
import { ConsolePrismaService } from '@/core/database/console-prisma.service';
import { resolveClientFromRequest, setClientCookie, signClientCookie } from '@/common/client-cookie';
import { decodeDomainFromPublishableKey } from '@/common/decode-domain-from-publishable-key';
import { ApiCodedErrorResponse, FlatErrorEnvelope } from '@/common/swagger/error-envelopes';
import { AuthService } from '@/modules/auth/auth.service';
import { renderPopupCloseHtml } from './popup-close.html';
import { AttemptsService } from './attempts.service';
import { CreateSignInAttemptDto } from './dto/create-sign-in-attempt.dto';
import { PrepareFirstFactorDto } from './dto/prepare-first-factor.dto';
import { AttemptFirstFactorDto } from './dto/attempt-first-factor.dto';

// Phase 2/3 (docs/unified-attempt-architecture.md): generic sign-in-attempt
// routes, coexisting with the existing register/login/oauth/* routes in
// auth.controller.ts / oauth.controller.ts — nothing here replaces those
// yet. Guarded by EnvironmentGuard throughout: an attempt is
// pre-auth by definition, same reasoning as dev_browser/handshake.
//
// Client identity (clientId/clientToken) is resolved EXCLUSIVELY from one
// of three places, mirroring AuthController's client/refresh routes
// exactly:
//   1. __shipstack_db_jwt query param (dev-browser mode) — a cross-site
//      dev/staging request can't reliably receive/use an httpOnly cookie
//      at all, so the DevBrowser DB row (keyed by this JS-held pointer) is
//      the substitute source of truth. setClientCookie() MUST NOT be
//      called on this path (see clientBootstrapViaDevBrowser's own doc
//      comment) — attempting to set a cookie that structurally cannot
//      land is worse than visibly not trying.
//   2. __client cookie (direct mode, same-site/production).
//   3. x-shipstack-client header (backend-proxy caller — see
//      client-cookie.ts's CLIENT_HEADER/resolveClientFromRequest doc
//      comments for the full rationale on why this is a header, not a
//      body field: no browser ambiently populates a custom header the way
//      cookies auto-attach, so there's no leak-enforcement problem like
//      the one a body field would reopen, and it works identically on the
//      bodyless GET :id reload route too).
// Never accepted as a request body field or returned as a query param.
// Earlier versions of this controller threaded clientId/clientToken
// through the DTO body and back out through the JSON response (and, on
// GET :id, through a query string) — that handed the Client's bearer
// secret to code paths (JS memory, server logs, browser history) it
// should never have reached. The rotating token must never appear
// anywhere outside the cookie jar / DevBrowser row / header / signedClientCookie
// relay.
@ApiTags('Sign-in attempts')
@ApiCookieAuth('directModeCookie')
@ApiBasicAuth('backendProxyBasicAuth')
@Controller('auth/client/sign_ins')
@UseGuards(EnvironmentGuard)
export class AttemptsController {
  constructor(
    private service: AttemptsService,
    private auth: AuthService,
  ) {}

  // Paints the (possibly just-rotated) client pair back out — httpOnly
  // cookie for a direct-mode browser, signedClientCookie in the body for a
  // backend-proxy caller to relay as its own cookie (see clientBootstrap's
  // identical comment in AuthController). Never both, never a raw
  // clientToken field. Skipped entirely on the dev-browser path — see
  // class comment.
  private relayClient(req: Request, res: Response, clientId: string, clientToken: string) {
    if ((req as any).isBackendProxy) {
      return { signedClientCookie: signClientCookie(clientId, clientToken) };
    }
    setClientCookie(res, clientId, clientToken, false);
    return {};
  }

  @ApiOperation({
    summary: 'Start a sign-in attempt',
    description:
      'For EMAIL_PASSWORD, resolves the attempt synchronously in the same call (status COMPLETE or a FAILED verificationStatus — ' +
      'wrong password/unverified email/no account are never HTTP errors, see the class comment on AttemptOutcome). ' +
      'For EMAIL_CODE/GOOGLE, returns a NEEDS_FIRST_FACTOR attempt to continue via prepare_first_factor/attempt_first_factor.',
  })
  @ApiResponse({ status: 201, description: 'Attempt created — inspect status/verificationStatus, this is not necessarily success.' })
  @ApiCodedErrorResponse(403, 'EMAIL_PASSWORD is disabled for this environment (auth_method_disabled).')
  @Post()
  async create(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Body() dto: CreateSignInAttemptDto,
    @Query('__shipstack_db_jwt') devBrowserId: string | undefined,
  ) {
    const environment = (req as any).environment;

    if (devBrowserId) {
      const bootstrapped = await this.auth.clientBootstrapViaDevBrowser(devBrowserId, environment.id);
      const { attempt, clientUat } = await this.service.create(environment.id, {
        identifier: dto.identifier,
        strategy: dto.strategy,
        password: dto.password,
        redirectUrl: dto.redirectUrl,
        actionCompleteRedirectUrl: dto.actionCompleteRedirectUrl,
        clientId: bootstrapped.clientId,
        clientToken: bootstrapped.clientToken,
        redirectMode: dto.redirectMode,
        popupOpenerOrigin: dto.popupOpenerOrigin,
      });
      // No setClientCookie/signedClientCookie here — the caller already
      // holds the stable devBrowserId; that's what it re-sends next time,
      // not a rotated clientToken (see class comment).
      return { ...attempt, clientUat, devMode: true };
    }

    const fromClient = resolveClientFromRequest(req);
    const { attempt, clientToken: rotatedToken, clientUat } = await this.service.create(environment.id, {
      identifier: dto.identifier,
      strategy: dto.strategy,
      password: dto.password,
      redirectUrl: dto.redirectUrl,
      actionCompleteRedirectUrl: dto.actionCompleteRedirectUrl,
      clientId: fromClient?.clientId,
      clientToken: fromClient?.clientToken,
      redirectMode: dto.redirectMode,
      popupOpenerOrigin: dto.popupOpenerOrigin,
    });
    const relayed = this.relayClient(req, res, attempt.clientId!, rotatedToken);
    return { ...attempt, clientUat, ...relayed };
  }

  @ApiOperation({
    summary: 'Reload a sign-in attempt',
    description: 'Poll/reload an attempt by id — once status is COMPLETE, returns a real accessToken (requires a resolvable client, direct-mode cookie or backend-proxy header). Also relays the (possibly rotated) client via cookie or signedClientCookie.',
  })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 400, type: FlatErrorEnvelope, description: 'The attempt is COMPLETE but no client (cookie or x-shipstack-client header) was resolvable to reload it with.' })
  @ApiResponse({ status: 404, type: FlatErrorEnvelope, description: 'Unknown attempt id, or it belongs to a different environment.' })
  @Get(':id')
  async get(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Param('id') id: string,
    @Query('__shipstack_db_jwt') devBrowserId: string | undefined,
  ) {
    const environment = (req as any).environment;

    if (devBrowserId) {
      const bootstrapped = await this.auth.clientBootstrapViaDevBrowser(devBrowserId, environment.id);
      const { attempt, accessToken, clientUat, sessions, activeSessionId } = await this.service.reload(id, environment.id, bootstrapped.clientToken);
      return { ...attempt, accessToken, clientUat, sessions, activeSessionId, devMode: true };
    }

    const fromClient = resolveClientFromRequest(req);
    const { attempt, accessToken, clientToken: rotatedToken, clientUat, sessions, activeSessionId } = await this.service.reload(id, environment.id, fromClient?.clientToken);
    const relayed = rotatedToken ? this.relayClient(req, res, attempt.clientId!, rotatedToken) : {};
    return { ...attempt, accessToken, clientUat, sessions, activeSessionId, ...relayed };
  }

  @ApiOperation({
    summary: 'Prepare a first factor (send OTP / build OAuth redirect URL)',
    description: 'EMAIL_CODE sends the code via mail here; GOOGLE returns an externalRedirectUrl to navigate the browser to. Sets status NEEDS_FIRST_FACTOR.',
  })
  @ApiResponse({ status: 201 })
  @ApiCodedErrorResponse(403, 'This strategy is disabled for this environment (auth_method_disabled).')
  @ApiResponse({ status: 404, type: FlatErrorEnvelope, description: 'Unknown attempt id, or it belongs to a different environment.' })
  @Post(':id/prepare_first_factor')
  async prepareFirstFactor(@Req() req: Request, @Param('id') id: string, @Body() dto: PrepareFirstFactorDto) {
    const environment = (req as any).environment;
    return this.service.prepareFirstFactor(id, environment.id, dto.strategy, dto.redirectMode, dto.popupOpenerOrigin);
  }

  @ApiOperation({
    summary: 'Attempt a prepared first factor (verify OTP code / password)',
    description:
      'A wrong code returns 201 with verificationStatus UNVERIFIED (still retriable) — see the EMAIL_CODE strategy\'s own MAX_VERIFICATION_ATTEMPTS cap (5). ' +
      'This is never an HTTP error for ordinary wrong-input cases; see the class comment on AttemptOutcome.',
  })
  @ApiResponse({ status: 201 })
  @ApiCodedErrorResponse(403, 'This strategy is disabled for this environment (auth_method_disabled).')
  @ApiResponse({ status: 404, type: FlatErrorEnvelope, description: 'Unknown attempt id, or no strategy has been prepared yet.' })
  @Post(':id/attempt_first_factor')
  async attemptFirstFactor(@Req() req: Request, @Param('id') id: string, @Body() dto: AttemptFirstFactorDto) {
    const environment = (req as any).environment;
    return this.service.attemptFirstFactor(id, environment.id, dto.input ?? {});
  }
}

// Shared OAuth callback for every redirect-based provider strategy —
// deliberately a SEPARATE controller (no @UseGuards(EnvironmentGuard):
// Google/Microsoft redirect here with no publishableKey/secretKey of their
// own, same as the legacy oauth.controller.ts's own google/callback route —
// the one-time `state`/externalLookupKey match is the security boundary,
// not a guard). Provider-agnostic: which strategy owns a given callback is
// resolved by looking up which attempt the state belongs to (its own
// `strategy` column), not by a per-provider route — Phase 8
// (docs/unified-attempt-architecture.md) made this genuinely provider-
// agnostic by resolving the strategy from the attempt itself instead of
// hardcoding GOOGLE.
@ApiTags('OAuth callback')
@Controller('auth/oauth_callback')
export class OAuthCallbackController {
  constructor(
    private service: AttemptsService,
    private platform: PlatformPrismaService,
    private console: ConsolePrismaService,
    private auth: AuthService,
  ) {}

  @ApiOperation({
    summary: 'OAuth provider redirect target (Google, etc.)',
    description:
      'Not a JSON endpoint — browsers land here directly from the provider. On the fixed shared landing host, completes the OAuth exchange and forwards to the tenant\'s own domain carrying the finished handshake JWT. On a tenant\'s own domain (final_redirect_url present), this is a pure redirect-unwrap-and-forward — no auth work happens here. Renders a postMessage/window.close page for POPUP mode. Unguarded by design: the one-time state/externalLookupKey match against the pending attempt is the security boundary, not EnvironmentGuard.',
  })
  @ApiResponse({ status: 302 })
  @ApiResponse({ status: 400, description: 'Missing code/state, or state does not match any pending attempt (expired or already used).' })
  @Get()
  async callback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('final_redirect_url') finalRedirectUrl: string | undefined,
    @Res() res: Response,
  ) {
    // Tenant-domain hop: the fixed host has already done ALL the real
    // work (Google token exchange, session creation, handshake minting)
    // and is handing off a fully-built destination — this branch's ENTIRE
    // job is unwrap-and-redirect, nothing else. No resolveExternal(), no
    // cookie of any kind painted here (dev mode deliberately avoids
    // __client cookies cross-site — see the class-level comment above on
    // __shipstack_db_jwt for why — and this hop has no cookie-painting
    // need at all regardless, since the ONLY cookie-painting step in this
    // entire flow is route-guard-core.ts's middleware verifying
    // __shipstack_handshake on the APP's own origin, not here).
    if (finalRedirectUrl) {
      return res.redirect(307, finalRedirectUrl);
    }

    if (!code || !state) throw new BadRequestException('Missing code or state');

    const pending = await this.platform.signInAttempt.findUnique({ where: { externalLookupKey: state } });
    if (!pending || !pending.strategy) throw new BadRequestException('Invalid or expired sign-in attempt');

    // Google always lands here (the fixed shared host —
    // lcl.shared.dev.shipstack.run locally — is the ONE Google-registered
    // redirect_uri, since Google rejects wildcards outright). This IS the
    // real-work branch — mirrors Clerk's own clerk.shared.lcl.dev exactly
    // (confirmed via a real captured Clerk network trace this session:
    // that fixed host's OWN response already embeds a fully-minted
    // __clerk_handshake inside _final_redirect_url before redirecting to
    // the tenant's own FAPI domain — the tenant hop above never sees
    // code/state at all, only the finished result).
    const attempt = await this.service.resolveExternal(pending.strategy, { code, state });

    // Popup mode — render the postMessage/window.close page instead of a
    // 302, using the origin the caller declared at prepare_first_factor
    // time (see SignInAttempt.redirectMode's own doc comment). Falls back
    // to redirect behavior if popupOpenerOrigin is somehow missing, rather
    // than posting a message to an unscoped/empty target origin.
    if (attempt.redirectMode === 'POPUP' && attempt.popupOpenerOrigin) {
      const html = renderPopupCloseHtml(
        { type: 'SHIPSTACK_OAUTH_RESULT', attemptId: attempt.id, status: attempt.status, redirectUrl: attempt.redirectUrl ?? null },
        attempt.popupOpenerOrigin,
      );
      res.setHeader('Cross-Origin-Opener-Policy', 'unsafe-none');
      res.setHeader('Content-Type', 'text/html');
      return res.send(html);
    }

    if (!attempt.clientId) throw new BadRequestException('Attempt has no bound Client — cannot create a handshake');
    const handshake = await this.auth.createHandshakeForAttempt(attempt.clientId, attempt.environmentId);

    // attempt.redirectUrl is already an absolute URL by the time it reaches
    // here — the SDK resolves it against window.location.origin before
    // ever sending it to FAPI (see sdks/nextjs-v2/src/client/proxy-hooks.ts's
    // signInWithOAuth/signUpWithOAuth).
    const appDestination = new URL(attempt.redirectUrl ?? '/');
    appDestination.searchParams.set('__shipstack_handshake', handshake.token);

    // The tenant's REAL domain still has to be recovered from data, not
    // the request: attempt.environmentId's Environment row's
    // publishableKey already encodes it (decodeDomainFromPublishableKey,
    // built this session).
    const environment = await this.console.environment.findUniqueOrThrow({ where: { id: attempt.environmentId } });
    const tenantDomain = decodeDomainFromPublishableKey(environment.publishableKey);
    const forwardUrl = new URL('/api/v1/auth/oauth_callback', `https://${tenantDomain}`);
    forwardUrl.searchParams.set('final_redirect_url', appDestination.toString());

    // 307, not Express's default 302 — matches Clerk's own redirect exactly
    // (confirmed via a real captured Clerk network trace this session).
    // Functionally identical for this GET-to-GET redirect either way, but
    // matching Clerk's exact status code removes one more variable when
    // diffing behavior against the reference implementation.
    return res.redirect(307, forwardUrl.toString());
  }
}
