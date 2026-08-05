import { BadRequestException, HttpStatus, Injectable, NotFoundException } from '@nestjs/common';
import { PlatformPrismaService } from '@/core/database/platform-prisma.service';
import { ConsolePrismaService } from '@/core/database/console-prisma.service';
import { AuthService } from '@/modules/auth/auth.service';
import { EnvironmentService } from '@/modules/environment/environment.service';
import { generateId } from '@/common/utils/id';
import { AuthMethod, RedirectMode } from '@/generated/platform/enums';
import { SignUpStrategyRegistryService } from './sign-up-strategy-registry.service';
import type { SignUpOutcome } from './sign-up-strategy.interface';
import { FapiException } from '@/common/errors/fapi-exception';
import { ErrorCode } from '@/common/errors/error-codes';

const ATTEMPT_TTL_SECONDS = 15 * 60;

// Sign-up's own generic attempt lifecycle, parallel to AttemptsService
// (SignInAttempt) — see docs/unified-attempt-architecture.md. Coexists
// with the old /auth/register route unchanged.
@Injectable()
export class SignUpAttemptsService {
  constructor(
    private platform: PlatformPrismaService,
    private console: ConsolePrismaService,
    private strategies: SignUpStrategyRegistryService,
    private auth: AuthService,
    private environment: EnvironmentService,
  ) {}

  // See AttemptsService.assertMethodEnabled's identical doc comment — same
  // orchestration-layer policy check, sign-up side.
  private async assertMethodEnabled(environmentId: string, strategy: AuthMethod): Promise<void> {
    const enabled = await this.environment.isEnabled(environmentId, strategy);
    if (!enabled) {
      throw new FapiException(HttpStatus.FORBIDDEN, ErrorCode.AuthMethodDisabled, `Auth method "${strategy}" is disabled for this environment`);
    }
  }

  async create(environmentId: string, params: { identifier?: string; strategy?: AuthMethod; password?: string; firstName?: string; lastName?: string; redirectUrl?: string; actionCompleteRedirectUrl?: string; clientId?: string; clientToken?: string; redirectMode?: RedirectMode; popupOpenerOrigin?: string }) {
    const client = await this.auth.resolveOrCreateClient(environmentId, params.clientId, params.clientToken);

    const attempt = await this.platform.signUpAttempt.create({
      data: {
        id: generateId(),
        environmentId,
        clientId: client.clientId,
        identifier: params.identifier,
        strategy: params.strategy,
        firstName: params.firstName,
        lastName: params.lastName,
        status: params.identifier ? 'NEEDS_FIRST_FACTOR' : 'NEEDS_IDENTIFIER',
        redirectUrl: params.redirectUrl,
        actionCompleteRedirectUrl: params.actionCompleteRedirectUrl,
        expiresAt: new Date(Date.now() + ATTEMPT_TTL_SECONDS * 1000),
      },
    });

    // See AttemptsService.create()'s identical shortcut and its own doc
    // comment — same rationale, sign-up side.
    if (params.strategy === 'EMAIL_PASSWORD' && params.identifier && params.password) {
      await this.assertMethodEnabled(environmentId, 'EMAIL_PASSWORD');
      const impl = this.strategies.resolve('EMAIL_PASSWORD');
      const outcome = await impl.attempt(attempt, { password: params.password });
      const resolved = await this.applyOutcome(attempt.id, outcome);
      return { attempt: resolved, clientToken: client.clientToken, clientUat: client.clientUat };
    }

    // See AttemptsService.create()'s identical OAuth shortcut — same
    // rationale, sign-up side.
    if (params.strategy === 'GOOGLE' || params.strategy === 'MICROSOFT') {
      const prepared = await this.runPrepareFirstFactor(attempt.id, environmentId, params.strategy, params.redirectMode, params.popupOpenerOrigin);
      return { attempt: prepared, clientToken: client.clientToken, clientUat: client.clientUat };
    }

    return { attempt, clientToken: client.clientToken, clientUat: client.clientUat };
  }

  async get(id: string, environmentId: string) {
    const attempt = await this.platform.signUpAttempt.findUnique({ where: { id } });
    if (!attempt || attempt.environmentId !== environmentId) throw new NotFoundException('Sign-up attempt not found');
    return attempt;
  }

  async reload(id: string, environmentId: string, clientToken?: string) {
    const attempt = await this.get(id, environmentId);
    if (attempt.status !== 'COMPLETE' || !attempt.clientId) {
      return { attempt, accessToken: null, clientToken: null, clientUat: null, sessions: [], activeSessionId: null };
    }
    if (!clientToken) throw new BadRequestException('clientToken is required to reload a completed sign-up attempt');

    // See AttemptsService.reload()'s identical doc comment — same fix,
    // sign-up side: forward refreshSession()'s full shape instead of
    // discarding clientId/sessions/activeSessionId down to accessToken.
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

  // Lets a caller fill in/correct identifier/firstName/lastName on an
  // in-progress attempt without restarting it — e.g. a missing required
  // field surfaced after create(). Deliberately narrow: only the fields a
  // caller could legitimately still be supplying pre-verification: status,
  // strategy, and anything verification-related stay owned by
  // prepareVerification/attemptVerification, never this route.
  async update(id: string, environmentId: string, params: { identifier?: string; firstName?: string; lastName?: string }) {
    await this.get(id, environmentId); // 404s if the attempt doesn't belong to this environment
    return this.platform.signUpAttempt.update({
      where: { id },
      data: {
        ...(params.identifier !== undefined && { identifier: params.identifier }),
        ...(params.firstName !== undefined && { firstName: params.firstName }),
        ...(params.lastName !== undefined && { lastName: params.lastName }),
      },
    });
  }

  async prepareVerification(id: string, environmentId: string, strategy: AuthMethod, redirectMode?: RedirectMode, popupOpenerOrigin?: string) {
    await this.get(id, environmentId); // 404s if the attempt doesn't belong to this environment
    return this.runPrepareFirstFactor(id, environmentId, strategy, redirectMode, popupOpenerOrigin);
  }

  // See AttemptsService.runPrepareFirstFactor's identical doc comment —
  // shared by prepareFirstFactor() and create()'s OAuth shortcut.
  private async runPrepareFirstFactor(attemptId: string, environmentId: string, strategy: AuthMethod, redirectMode?: RedirectMode, popupOpenerOrigin?: string) {
    await this.assertMethodEnabled(environmentId, strategy);
    const attempt = await this.platform.signUpAttempt.findUniqueOrThrow({ where: { id: attemptId } });
    const impl = this.strategies.resolve(strategy);
    const prepared = await impl.prepare(attempt);

    const data = prepared.verificationData as Record<string, unknown> | null;
    const externalLookupKey = typeof data?.state === 'string' ? data.state : undefined;

    return this.platform.signUpAttempt.update({
      where: { id: attempt.id },
      data: {
        strategy,
        status: 'NEEDS_FIRST_FACTOR',
        verificationStatus: 'UNVERIFIED',
        verificationData: prepared.verificationData as any,
        verificationExpiresAt: prepared.verificationExpiresAt,
        externalRedirectUrl: prepared.externalRedirectUrl,
        externalLookupKey,
        redirectMode: redirectMode ?? 'REDIRECT',
        popupOpenerOrigin: popupOpenerOrigin ?? null,
      },
    });
  }

  async attemptVerification(id: string, environmentId: string, input: unknown) {
    const attempt = await this.get(id, environmentId);
    if (!attempt.strategy) throw new NotFoundException('No strategy prepared for this attempt yet');
    await this.assertMethodEnabled(environmentId, attempt.strategy);
    const impl = this.strategies.resolve(attempt.strategy);
    const outcome = await impl.attempt(attempt, input);
    return this.applyOutcome(attempt.id, outcome);
  }

  private async applyOutcome(attemptId: string, outcome: SignUpOutcome) {
    if (outcome.result === 'complete') {
      const attempt = await this.platform.signUpAttempt.findUniqueOrThrow({ where: { id: attemptId } });
      if (!attempt.clientId) throw new BadRequestException('Attempt has no bound Client — cannot create a session');

      const environment = await this.console.environment.findUniqueOrThrow({ where: { id: attempt.environmentId } });
      const identity = await this.platform.identity.findUniqueOrThrow({ where: { id: outcome.identityId } });

      await this.auth.issueTokens(
        identity.id, environment.publishableKey, environment.accessTokenTtl, environment.refreshTokenTtl,
        attempt.clientId,
        { email: identity.email, firstName: identity.firstName, lastName: identity.lastName, avatar: identity.avatar },
        attempt.environmentId,
      );

      return this.platform.signUpAttempt.update({
        where: { id: attemptId },
        data: { status: 'COMPLETE', verificationStatus: 'VERIFIED', identityId: outcome.identityId },
      });
    }
    // pending-verification — an Identity now exists, but no session yet:
    // mirrors register()'s own requiresEmailVerification branch. status
    // stays NEEDS_FIRST_FACTOR (not COMPLETE — no session was created) but
    // identityId is recorded so a later login()/attempt (post-verification)
    // can be traced back to this attempt if needed.
    if (outcome.result === 'pending-verification') {
      return this.platform.signUpAttempt.update({
        where: { id: attemptId },
        data: { identityId: outcome.identityId, verificationStatus: 'VERIFIED' },
      });
    }
    if (outcome.result === 'failed') {
      return this.platform.signUpAttempt.update({
        where: { id: attemptId },
        data: { verificationStatus: 'FAILED' },
      });
    }
    return this.platform.signUpAttempt.update({
      where: { id: attemptId },
      data: { verificationAttempts: { increment: 1 } },
    });
  }
}
