import { BadRequestException, HttpStatus, Injectable, NotFoundException } from '@nestjs/common';
import { PlatformPrismaService } from '@/core/database/platform-prisma.service';
import { ConsolePrismaService } from '@/core/database/console-prisma.service';
import { AuthService } from '@/modules/auth/auth.service';
import { EnvironmentService } from '@/modules/environment/environment.service';
import { generateId } from '@/common/utils/id';
import { AuthMethod, RedirectMode } from '@/generated/platform/enums';
import { StrategyRegistryService } from './strategy-registry.service';
import type { AttemptOutcome } from './sign-in-strategy.interface';
import { FapiException } from '@/common/errors/fapi-exception';
import { ErrorCode } from '@/common/errors/error-codes';

// Whole-attempt TTL — Clerk's own "abandon_at" is roughly this order of
// magnitude (their captured samples showed ~15min windows). Distinct from
// each strategy's own verificationExpiresAt, which bounds just the current
// verification step (an OTP code, an OAuth state) — this bounds the whole
// multi-step attempt regardless of how many prepare/attempt round trips it
// takes.
const ATTEMPT_TTL_SECONDS = 15 * 60;

// Generic, strategy-agnostic sign-in attempt lifecycle — see
// docs/unified-attempt-architecture.md. Replaces per-method routes
// (register/login/oauth/*) with one resource whose behavior at each step
// is delegated to a SignInStrategy (resolved via StrategyRegistryService),
// never branched on here directly. Coexists with the old auth.service.ts
// routes during the phased migration — nothing here touches those tables
// or routes.
//
// Token-survives-redirect design (settled in Phase 3, reused by every
// later redirect-based strategy — see the doc's "OAuth for real" step):
// the CALLER binds a Client (clientId/clientToken) to the attempt at
// create() time, same as the legacy oauth.service.ts's exchange() already
// requires. Once a strategy's resolveExternal() marks the attempt
// COMPLETE, get() mints a fresh access token for that bound Client's new
// Session on read — mirrors Clerk's own reload()-by-id pattern (browser
// already knows the attempt id; GET it again, same-site, to pick up
// tokens) rather than a bespoke exchange-code ticket per strategy.
@Injectable()
export class AttemptsService {
  constructor(
    private platform: PlatformPrismaService,
    private console: ConsolePrismaService,
    private strategies: StrategyRegistryService,
    private auth: AuthService,
    private environment: EnvironmentService,
  ) {}

  // Orchestration-layer policy check (docs/environment-resource-task.md
  // point 3, option (a)) — StrategyRegistryService.resolve() stays a pure,
  // stateless dispatch table with no DB access; every call site here that's
  // about to resolve+execute a strategy checks enabled-ness first. Checked
  // at each of create()'s two shortcuts, runPrepareFirstFactor (covers both
  // the explicit prepareFirstFactor() call and create()'s OAuth shortcut),
  // and attemptFirstFactor — every point a strategy is first resolved for a
  // caller-supplied strategy. resolveExternal() is intentionally NOT
  // checked again: by the time an external callback (e.g. Google's
  // redirect) lands, prepareFirstFactor already gated entry, and a dev
  // disabling a method mid-flow should fail the next explicit attempt, not
  // an already-in-flight redirect the browser is honoring.
  private async assertMethodEnabled(environmentId: string, strategy: AuthMethod): Promise<void> {
    const enabled = await this.environment.isEnabled(environmentId, strategy);
    if (!enabled) {
      throw new FapiException(HttpStatus.FORBIDDEN, ErrorCode.AuthMethodDisabled, `Auth method "${strategy}" is disabled for this environment`);
    }
  }

  async create(environmentId: string, params: { identifier?: string; strategy?: AuthMethod; password?: string; redirectUrl?: string; actionCompleteRedirectUrl?: string; clientId?: string; clientToken?: string; redirectMode?: RedirectMode; popupOpenerOrigin?: string }) {
    // Binds (or mints) a Client up front — required so a later resolveExternal()
    // has somewhere to attach the resulting Session, and so get() can issue
    // real tokens once complete. Mirrors every other pre-auth route's own
    // resolveOrCreateClient usage (register/login/oauth exchange).
    const client = await this.auth.resolveOrCreateClient(environmentId, params.clientId, params.clientToken);

    const attempt = await this.platform.signInAttempt.create({
      data: {
        id: generateId(),
        environmentId,
        clientId: client.clientId,
        identifier: params.identifier,
        strategy: params.strategy,
        status: params.identifier ? 'NEEDS_FIRST_FACTOR' : 'NEEDS_IDENTIFIER',
        redirectUrl: params.redirectUrl,
        actionCompleteRedirectUrl: params.actionCompleteRedirectUrl,
        expiresAt: new Date(Date.now() + ATTEMPT_TTL_SECONDS * 1000),
      },
    });

    // Synchronous shortcut for EMAIL_PASSWORD: password auth is naturally
    // one-shot (see EmailPasswordStrategy's own doc comment) — a caller
    // that already has both identifier and password shouldn't need a
    // separate prepare_first_factor/attempt_first_factor round trip just
    // to satisfy the generic two-phase shape every other strategy needs.
    if (params.strategy === 'EMAIL_PASSWORD' && params.identifier && params.password) {
      await this.assertMethodEnabled(environmentId, 'EMAIL_PASSWORD');
      const impl = this.strategies.resolve('EMAIL_PASSWORD');
      const outcome = await impl.attempt(attempt, { password: params.password });
      const resolved = await this.applyOutcome(attempt.id, outcome);
      return { attempt: resolved, clientToken: client.clientToken, clientUat: client.clientUat };
    }

    // Same shortcut, OAuth shape: prepare() needs nothing beyond
    // attempt.environmentId (already known here) — no identifier, no
    // caller-supplied secret, unlike EMAIL_PASSWORD. Folding this into
    // create() removes an entire extra prepare_first_factor round trip
    // that bought nothing (the browser would otherwise sit idle between
    // create() and prepare_first_factor() with no new information arriving
    // in between) and collapses a class of create/prepare state-sync bugs.
    if (params.strategy === 'GOOGLE' || params.strategy === 'MICROSOFT') {
      const prepared = await this.runPrepareFirstFactor(attempt.id, environmentId, params.strategy, params.redirectMode, params.popupOpenerOrigin);
      return { attempt: prepared, clientToken: client.clientToken, clientUat: client.clientUat };
    }

    return { attempt, clientToken: client.clientToken, clientUat: client.clientUat };
  }

  async get(id: string, environmentId: string) {
    const attempt = await this.platform.signInAttempt.findUnique({ where: { id } });
    if (!attempt || attempt.environmentId !== environmentId) throw new NotFoundException('Sign-in attempt not found');
    return attempt;
  }

  // Reload — the actual token-pickup point once an attempt is COMPLETE
  // (see class comment). clientToken must be supplied by the caller (the
  // browser already holds it from create()'s response, or from its own
  // Client bootstrap) — never persisted raw in the attempt row itself.
  async reload(id: string, environmentId: string, clientToken?: string) {
    const attempt = await this.get(id, environmentId);
    if (attempt.status !== 'COMPLETE' || !attempt.clientId) {
      return { attempt, accessToken: null, clientToken: null, clientUat: null, sessions: [], activeSessionId: null };
    }
    if (!clientToken) throw new BadRequestException('clientToken is required to reload a completed sign-in attempt');

    // Returns refreshSession()'s full canonical shape (clientId, sessions,
    // activeSessionId) merged with the attempt, not just accessToken —
    // see auth.service.ts's buildClientBootstrapResponse doc comment for
    // why this is the one source of truth for Client/Session state.
    // Previously this discarded everything but accessToken, which meant
    // this reload path and bootstrapClient/refreshSession's handlers each
    // painted browser cookie state from a different, divergent view of
    // the same session — the root cause of the session-desync bug.
    const result = await this.auth.refreshSession(attempt.clientId, clientToken, environmentId);
    const activeSession = result.sessions.find(s => s.id === result.activeSessionId);
    return {
      attempt,
      accessToken: activeSession?.accessToken ?? null,
      clientToken: result.clientToken,
      clientUat: result.clientUat,
      clientId: result.clientId,
      sessions: result.sessions,
      activeSessionId: result.activeSessionId,
    };
  }

  async prepareFirstFactor(id: string, environmentId: string, strategy: AuthMethod, redirectMode?: RedirectMode, popupOpenerOrigin?: string) {
    await this.get(id, environmentId); // 404s if the attempt doesn't belong to this environment
    return this.runPrepareFirstFactor(id, environmentId, strategy, redirectMode, popupOpenerOrigin);
  }

  // Shared by prepareFirstFactor() (explicit second call) and create()'s
  // OAuth shortcut (same-call, once strategy/environmentId are already
  // known) — identical persistence contract either way.
  private async runPrepareFirstFactor(attemptId: string, environmentId: string, strategy: AuthMethod, redirectMode?: RedirectMode, popupOpenerOrigin?: string) {
    await this.assertMethodEnabled(environmentId, strategy);
    const attempt = await this.platform.signInAttempt.findUniqueOrThrow({ where: { id: attemptId } });
    const impl = this.strategies.resolve(strategy);
    const prepared = await impl.prepare(attempt);

    // Convention: any redirect-based strategy returning verificationData
    // with a `state` field gets that value promoted to the indexed
    // externalLookupKey column — see SignInAttempt.externalLookupKey's own
    // doc comment for why this can't just be a JSON path lookup.
    const data = prepared.verificationData as Record<string, unknown> | null;
    const externalLookupKey = typeof data?.state === 'string' ? data.state : undefined;

    return this.platform.signInAttempt.update({
      where: { id: attempt.id },
      data: {
        strategy,
        status: 'NEEDS_FIRST_FACTOR',
        verificationStatus: 'UNVERIFIED',
        verificationData: prepared.verificationData as any,
        verificationExpiresAt: prepared.verificationExpiresAt,
        externalRedirectUrl: prepared.externalRedirectUrl,
        externalLookupKey,
        // Transport concern only — see SignInAttempt.redirectMode's own
        // doc comment. Recorded regardless of strategy shape; harmless
        // no-op for strategies with no externalRedirectUrl.
        redirectMode: redirectMode ?? 'REDIRECT',
        popupOpenerOrigin: popupOpenerOrigin ?? null,
      },
    });
  }

  async attemptFirstFactor(id: string, environmentId: string, input: unknown) {
    const attempt = await this.get(id, environmentId);
    if (!attempt.strategy) throw new NotFoundException('No strategy prepared for this attempt yet');
    await this.assertMethodEnabled(environmentId, attempt.strategy);
    const impl = this.strategies.resolve(attempt.strategy);
    const outcome = await impl.attempt(attempt, input);
    return this.applyOutcome(attempt.id, outcome);
  }

  // Entry point for strategy-specific external callbacks (e.g.
  // /auth/oauth_callback) — the controller resolves WHICH strategy owns
  // the callback by reading the pending attempt's own `strategy` column
  // (Phase 8), calls its resolveExternal() to find the matching attempt
  // and outcome, then applies it here.
  async resolveExternal(strategy: AuthMethod, request: unknown) {
    const impl = this.strategies.resolve(strategy);
    const { attemptId, outcome } = await impl.resolveExternal(request);
    return this.applyOutcome(attemptId, outcome);
  }

  private async applyOutcome(attemptId: string, outcome: AttemptOutcome) {
    if (outcome.result === 'complete') {
      const attempt = await this.platform.signInAttempt.findUniqueOrThrow({ where: { id: attemptId } });
      if (!attempt.clientId) throw new BadRequestException('Attempt has no bound Client — cannot create a session');

      const environment = await this.console.environment.findUniqueOrThrow({ where: { id: attempt.environmentId } });
      const identity = await this.platform.identity.findUniqueOrThrow({ where: { id: outcome.identityId } });

      // Mints the real Session now, server-side, at the moment the
      // strategy resolves — not deferred to reload(). reload() only ever
      // mints a FRESH ACCESS TOKEN for this already-created Session
      // afterward (via refreshSession), same as any other returning-client
      // token refresh. issueTokens()'s own refreshToken return value is
      // deliberately unused here — __refresh is issued exclusively by
      // createHandshake() (see that method's own doc comment), not by
      // attempt completion, so a client always goes through one
      // consistent path (the handshake endpoint) to obtain it, in both
      // direct and backend-proxy mode.
      await this.auth.issueTokens(
        identity.id, environment.publishableKey, environment.accessTokenTtl, environment.refreshTokenTtl,
        attempt.clientId,
        { email: identity.email, firstName: identity.firstName, lastName: identity.lastName, avatar: identity.avatar },
        attempt.environmentId,
      );

      return this.platform.signInAttempt.update({
        where: { id: attemptId },
        data: { status: 'COMPLETE', verificationStatus: 'VERIFIED', identityId: outcome.identityId },
      });
    }
    if (outcome.result === 'failed') {
      return this.platform.signInAttempt.update({
        where: { id: attemptId },
        data: { verificationStatus: 'FAILED' },
      });
    }
    // still-pending — no state change beyond the retry counter, e.g. a
    // wrong OTP attempt that should still allow retry, or a multi-step
    // passkey ceremony.
    return this.platform.signInAttempt.update({
      where: { id: attemptId },
      data: { verificationAttempts: { increment: 1 } },
    });
  }
}
