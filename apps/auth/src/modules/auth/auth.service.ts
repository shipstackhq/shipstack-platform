import type { Prisma } from "@/generated/platform/client";
import { CLIENT_COOKIE_MAX_AGE_SECONDS, signClientCookie } from "@/common/client-cookie";
import { enqueueOutboxEvent } from "@/core/outbox/outbox";
import { BadRequestException, HttpStatus, Injectable } from '@nestjs/common';
import { PlatformPrismaService } from '@/core/database/platform-prisma.service';
import { ConsolePrismaService } from '@/core/database/console-prisma.service';
import { IdentityTokenService } from '@/core/identity-token/identity-token.service';
import { MailService } from '@/core/mail/mail.service';
import { EnvironmentService } from '@/modules/environment/environment.service';
import { generateId } from '@/common/utils/id';
import { getCookieSuffix } from '@/common/utils/cookie-suffix';
import { FapiException } from '@/common/errors/fapi-exception';
import { ErrorCode } from '@/common/errors/error-codes';
import { createHash, randomBytes } from 'crypto';
import { ZxcvbnFactory } from '@zxcvbn-ts/core';
const _zxcvbnInstance = new ZxcvbnFactory({});
const zxcvbn = _zxcvbnInstance.check.bind(_zxcvbnInstance);
import * as argon2 from 'argon2';

const CLIENT_TTL_SECONDS = 60 * 24 * 60 * 60; // 60 days

// Duplicated from apps/platform-api/src/modules/identities/identities-auth.service.ts
// per the migration plan's explicit "duplicate now, don't extract to a shared
// package" decision (Decisions made section, atomic-napping-crescent.md).
//
// Phase 1 scope: only the FAPI-A slice (Client/Session lifecycle used by the
// already-public register/login/refresh/logout/client-bootstrap routes, plus
// password-reset-confirm/verify-email/resend-verification, all of which were
// unguarded or publishableKey-only on platform-api already — no behavior
// change from a caller's perspective).
//
// Phase 2 adds: verify, changePassword, passwordResetRequest, logoutAll
// (ported from identities-auth.service.ts's secret-gated Mode 1 methods),
// plus updateMe (new — does not exist on platform-api at all). See the
// per-method comments below for guard-tier reasoning; the full writeup is
// in the migration plan and in auth.controller.ts's route-level comments.
@Injectable()
export class AuthService {
  constructor(
    private platform: PlatformPrismaService,
    private console: ConsolePrismaService,
    private identityToken: IdentityTokenService,
    private mail: MailService,
    private environment: EnvironmentService,
  ) {}

  // ── Helpers ──────────────────────────────────────────────────────────────────

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  // clientUat mirrors Clerk's own __client_uat contract: it is the last time
  // a SESSION was active, not the last time the Client row itself was
  // touched (createClient/rotateClientToken return client.updatedAt, which
  // changes on every token rotation regardless of whether any session
  // exists). Client-side, sdks/nextjs's middleware guard treats a nonzero
  // clientUat as "someone is signed in" — so any response with no active
  // session must report 0 here, or a browser that has merely bootstrapped
  // (never signed in) gets misclassified as a stale/mismatched session
  // instead of a clean signed-out visitor.
  // Public (was private) — OAuthService.exchange() has the exact same
  // "resolveOrCreateClient's clientUat needs recomputing once a real
  // session is created" need as register()/login() above, and there's no
  // reason to duplicate this one-line gate a third time.
  clientUatFor(rawClientUat: number, activeSessionId: string | null): number {
    return activeSessionId ? rawClientUat : 0;
  }

  private async createClient(environmentId: string): Promise<{ clientId: string; clientToken: string; clientUat: number }> {
    const clientId = generateId();
    const clientToken = randomBytes(32).toString('hex');
    const client = await this.platform.client.create({
      data: {
        id: clientId,
        environmentId,
        rotatingTokenHash: this.hashToken(clientToken),
        expiresAt: new Date(Date.now() + CLIENT_TTL_SECONDS * 1000),
      },
    });
    return { clientId, clientToken, clientUat: Math.floor(client.updatedAt.getTime() / 1000) };
  }

  private async rotateClientToken(clientId: string): Promise<{ clientToken: string; clientUat: number }> {
    const clientToken = randomBytes(32).toString('hex');
    const client = await this.platform.client.update({
      where: { id: clientId },
      data: { rotatingTokenHash: this.hashToken(clientToken) },
    });
    return { clientToken, clientUat: Math.floor(client.updatedAt.getTime() / 1000) };
  }

  private buildSessionSummary(
    session: { id: string; status: string; expiresAt: Date; createdAt: Date; lastActiveAt: Date; lastAccessToken: string | null },
    identity: { id: string; email: string | null; firstName: string | null; lastName: string | null; avatar: string | null },
  ) {
    const status = session.status === 'ACTIVE' && session.expiresAt < new Date() ? 'EXPIRED' : session.status;
    return {
      object: 'session' as const,
      id: session.id,
      status: status as 'ACTIVE' | 'REVOKED' | 'ENDED' | 'EXPIRED' | 'REMOVED',
      identity: {
        object: 'identity' as const,
        shipstackId: identity.id,
        email: identity.email,
        firstName: identity.firstName,
        lastName: identity.lastName,
        avatar: identity.avatar,
      },
      accessToken: session.lastAccessToken,
      createdAt: Math.floor(session.createdAt.getTime() / 1000),
      lastActiveAt: Math.floor(session.lastActiveAt.getTime() / 1000),
      expiresAt: Math.floor(session.expiresAt.getTime() / 1000),
    };
  }

  private async detectReplay(clientId: string): Promise<void> {
    await this.platform.client.update({
      where: { id: clientId },
      data: { revokedAt: new Date() },
    });
    await this.platform.session.updateMany({
      where: { clientId },
      data: { status: 'REVOKED' },
    });
  }

  private async resolveClient(clientId: string, clientToken: string, environmentId?: string) {
    const client = await this.platform.client.findUnique({ where: { id: clientId } });
    if (!client) throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.ClientInvalid, 'Invalid client');
    if (client.revokedAt) throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.ClientRevoked, 'Client revoked');
    if (client.expiresAt < new Date()) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.ClientExpired, 'Client expired');
    }
    if (environmentId && client.environmentId !== environmentId) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.ClientInvalid, 'Invalid client');
    }

    const hashMatches = this.hashToken(clientToken) === client.rotatingTokenHash;
    if (!hashMatches) {
      await this.detectReplay(client.id);
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.ClientTokenReuseDetected, 'Token reuse detected');
    }
    return client;
  }

  // clientUat is ALWAYS 0 in this method's return value — resolveOrCreateClient
  // has no session context at all (it only ever resolves/mints the Client
  // row), so it can never know whether a session is about to be attached
  // afterward. This was a real bug: every caller that used this method's
  // clientUat directly (without immediately creating a session in the same
  // request) got a nonzero "signed in" signal for an anonymous Client —
  // clientBootstrap/clientBootstrapViaDevBrowser were already fixed to
  // gate through clientUatFor, but this method itself wasn't, and
  // register/login's success paths only looked correct by coincidence
  // (a session really is created moments later in those two call sites,
  // just not through this method). Callers that create a session
  // afterward must compute their own final clientUat via clientUatFor once
  // they know the real session id — see register/login below.
  async resolveOrCreateClient(
    environmentId: string,
    clientId?: string,
    clientToken?: string,
  ): Promise<{ clientId: string; clientToken: string; clientUat: number }> {
    if (!clientId || !clientToken) {
      const c = await this.createClient(environmentId);
      return { ...c, clientUat: 0 };
    }
    try {
      const existing = await this.resolveClient(clientId, clientToken, environmentId);
      const rotated = await this.rotateClientToken(existing.id);
      return { clientId: existing.id, clientToken: rotated.clientToken, clientUat: 0 };
    } catch {
      const c = await this.createClient(environmentId);
      return { ...c, clientUat: 0 };
    }
  }

  async issueTokens(
    identityId: string,
    publishableKey: string,
    accessTokenTtl: number,
    sessionTtl: number,
    clientId: string,
    profile?: { email?: string | null; firstName?: string | null; lastName?: string | null; avatar?: string | null },
    environmentId?: string,
  ) {
    const refreshToken = randomBytes(32).toString('hex');
    const session = await this.platform.session.create({
      data: {
        id: generateId(),
        clientId,
        identityId,
        status: 'ACTIVE',
        refreshTokenHash: this.hashToken(refreshToken),
        expiresAt: new Date(Date.now() + sessionTtl * 1000),
      },
    });

    const cookieSuffix = getCookieSuffix(publishableKey);
    const accessToken = await this.identityToken.signAccessToken(
      identityId, publishableKey, accessTokenTtl, profile, environmentId, session.id, session.status, cookieSuffix,
    );
    await this.platform.session.update({ where: { id: session.id }, data: { lastAccessToken: accessToken } });

    return { accessToken, sessionId: session.id, sessionUat: Math.floor(session.lastActiveAt.getTime() / 1000), refreshToken };
  }

  // ── Auth operations ───────────────────────────────────────────────────────────

  // Delegates to EnvironmentService.getConfig — see
  // docs/environment-resource-task.md point 4: this used to run its own
  // independent `console.environment.findUniqueOrThrow` for the same row
  // EnvironmentService (GET /environment) also queries. Flattened here into
  // the shape this class's call sites already destructure, so none of them
  // needed to change.
  private async getEnvConfig(environmentId: string) {
    const config = await this.environment.getConfig(environmentId);
    return {
      accessTokenTtl: config.accessTokenTtl,
      refreshTokenTtl: config.refreshTokenTtl,
      requireEmailVerification: config.requireEmailVerification,
      minPasswordLength: config.password.minLength,
      passwordRequirements: config.password.requirements,
      collectFirstLastName: config.nameFields.collect,
      requireFirstLastName: config.nameFields.required,
      allowSelfDeletion: config.allowSelfDeletion,
      preventLeakedPasswords: config.password.preventLeakedPasswords,
      minPasswordStrength: config.password.minPasswordStrength,
    };
  }

  private async isPasswordLeaked(password: string): Promise<boolean> {
    try {
      const hash = createHash('sha1').update(password).digest('hex').toUpperCase();
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);
      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      const text = await res.text();
      return text.split('\n').some(line => line.split(':')[0].trim() === suffix);
    } catch {
      // If HIBP is unreachable, fail open — don't block the user
      return false;
    }
  }

  private validatePassword(password: string, minLength: number, requirements: string, minStrength?: number | null): void {
    if (password.length < minLength) {
      throw new BadRequestException(`Password must be at least ${minLength} characters`);
    }
    if (minStrength != null && minStrength > 0) {
      const { score } = zxcvbn(password);
      const labels = ['weak', 'weak', 'fair', 'good', 'strong'];
      if (score < minStrength) {
        throw new BadRequestException(`Password is too weak. Minimum strength required: ${labels[minStrength]}`);
      }
    }
    const checks: Record<string, { pattern: RegExp; message: string }[]> = {
      letters_digits: [
        { pattern: /[a-zA-Z]/, message: 'at least one letter' },
        { pattern: /[0-9]/, message: 'at least one digit' },
      ],
      letters_digits_symbols: [
        { pattern: /[a-zA-Z]/, message: 'at least one letter' },
        { pattern: /[0-9]/, message: 'at least one digit' },
        { pattern: /[^a-zA-Z0-9]/, message: 'at least one symbol' },
      ],
      lowercase_uppercase_digits: [
        { pattern: /[a-z]/, message: 'at least one lowercase letter' },
        { pattern: /[A-Z]/, message: 'at least one uppercase letter' },
        { pattern: /[0-9]/, message: 'at least one digit' },
      ],
      lowercase_uppercase_digits_symbols: [
        { pattern: /[a-z]/, message: 'at least one lowercase letter' },
        { pattern: /[A-Z]/, message: 'at least one uppercase letter' },
        { pattern: /[0-9]/, message: 'at least one digit' },
        { pattern: /[^a-zA-Z0-9]/, message: 'at least one symbol' },
      ],
    };
    const required = checks[requirements] ?? [];
    for (const check of required) {
      if (!check.pattern.test(password)) {
        throw new BadRequestException(`Password must contain ${check.message}`);
      }
    }
  }

  // Billing assigns plans. Auth only announces that the identity exists (D14, D12).
  private async emitIdentityCreated(identityId: string, environmentId: string): Promise<void> {
    await enqueueOutboxEvent(this.platform, {
      aggregateType: "identity",
      aggregateId: identityId,
      eventType: "identity.created",
      payload: { identityId, environmentId },
    });
  }

  private async sendVerificationEmail(identity: { id: string; email: string | null }) {
    if (!identity.email) return;
    const rawToken = randomBytes(32).toString('hex');
    const tokenHash = this.hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await this.platform.verificationToken.deleteMany({ where: { identityId: identity.id } });
    await this.platform.verificationToken.create({
      data: { id: generateId(), identityId: identity.id, tokenHash, expiresAt },
    });

    await this.mail.sendVerificationEmail(identity.email, rawToken);
  }

  // Identity-creation-and-validation core, no Client/Session work —
  // originally split out from the old register() (deleted in the Phase 9
  // cutover, see class comment below) so Phase 4's EmailPasswordStrategy
  // could reuse the exact same validation/creation logic without also
  // minting a second, redundant Client/Session on top of the one
  // AttemptsService already binds/creates. Now only used by
  // EmailPasswordSignUpStrategy. Returns requireEmailVerification so the
  // caller can decide what to do with a not-yet-verified identity in its
  // own response shape.
  //
  // requireEmailVerification is a real, per-Environment, developer-facing
  // setting (console-api's ProjectsController.updateEmailSettings —
  // toggled from the dashboard, @default(false) in schema) — when it's on,
  // a new signup gets the verification email sent automatically here, the
  // same sendVerificationEmail() call resendVerification() already makes.
  // Previously this method created an unverified identity and left sending
  // the email entirely to a caller explicitly hitting POST
  // /auth/resend-verification afterward — a real gap (flagged in this
  // session's very first end-to-end fapi trace), not a deliberate
  // "caller-triggered" design: a developer who turns this setting on
  // reasonably expects sign-up itself to trigger the email, matching how
  // every other password-manager/auth product behaves.
  async createPasswordIdentity(dto: { email: string; password: string; firstName?: string; lastName?: string }, environmentId: string) {
    const email = dto.email.toLowerCase().trim();

    const existing = await this.platform.identity.findUnique({
      where: { environmentId_email: { environmentId, email } },
    });
    if (existing) {
      throw new FapiException(HttpStatus.CONFLICT, ErrorCode.IdentityEmailAlreadyRegistered, 'Email already registered');
    }

    const { requireEmailVerification, minPasswordLength, passwordRequirements, requireFirstLastName, preventLeakedPasswords, minPasswordStrength } = await this.getEnvConfig(environmentId);
    this.validatePassword(dto.password, minPasswordLength, passwordRequirements, minPasswordStrength);
    if (requireFirstLastName && (!dto.firstName?.trim() || !dto.lastName?.trim())) {
      throw new BadRequestException('First and last name are required');
    }
    if (preventLeakedPasswords && await this.isPasswordLeaked(dto.password)) {
      throw new BadRequestException('This password has appeared in a data breach. Please choose a different password.');
    }
    const credential = await argon2.hash(dto.password);

    const identity = await this.platform.identity.create({
      data: {
        id: generateId(),
        environmentId,
        email,
        credential,
        emailVerified: !requireEmailVerification,
        firstName: dto.firstName?.trim() ?? null,
        lastName: dto.lastName?.trim() ?? null,
      },
    });

    await this.emitIdentityCreated(identity.id, environmentId);
    if (requireEmailVerification) {
      await this.sendVerificationEmail({ id: identity.id, email: identity.email });
    }
    return { identity, requireEmailVerification };
  }

  // register()/login() (Phase 1's old /auth/register, /auth/login routes)
  // were deleted in the Phase 9 cutover
  // (docs/unified-attempt-architecture.md) — superseded by
  // AttemptsService/SignUpAttemptsService + EmailPasswordStrategy/
  // EmailPasswordSignUpStrategy, which call createPasswordIdentity()/
  // verifyPasswordCredential() below directly (these were extracted in
  // Phase 4 specifically so both the old and new routes could share this
  // logic — now only the new routes use them).

  // Identity-resolution-and-validation core, no Client/Session work —
  // shared by EmailPasswordStrategy (modules/auth/attempts/strategies/) and
  // (formerly) login().
  async verifyPasswordCredential(email: string, password: string, environmentId: string) {
    const normalizedEmail = email.toLowerCase().trim();
    const identity = await this.platform.identity.findUnique({
      where: { environmentId_email: { environmentId, email: normalizedEmail } },
    });

    if (!identity || !identity.credential) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.IdentityInvalidCredentials, 'Invalid credentials');
    }
    if (identity.status === 'SUSPENDED') {
      throw new FapiException(HttpStatus.FORBIDDEN, ErrorCode.IdentitySuspended, 'Identity suspended');
    }
    if (!identity.emailVerified) {
      throw new FapiException(HttpStatus.FORBIDDEN, ErrorCode.IdentityEmailNotVerified, 'Email not verified');
    }

    const valid = await argon2.verify(identity.credential, password);
    if (!valid) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.IdentityInvalidCredentials, 'Invalid credentials');
    }

    return identity;
  }

  async refreshSession(clientId: string, clientToken: string, environmentId?: string, sessionRefreshToken?: string) {
    const client = await this.resolveClient(clientId, clientToken, environmentId);
    const rotated = await this.rotateClientToken(client.id);

    const session = sessionRefreshToken
      ? await this.resolveSessionByRefreshToken(clientId, sessionRefreshToken)
      : await this.platform.session.findFirst({
          where: { clientId, status: 'ACTIVE' },
          orderBy: { lastActiveAt: 'desc' },
        });

    if (!session || session.expiresAt < new Date()) {
      return { object: 'client' as const, clientId: client.id, clientToken: rotated.clientToken, clientUat: this.clientUatFor(rotated.clientUat, null), sessions: [], activeSessionId: null as string | null };
    }

    const identity = await this.platform.identity.findUniqueOrThrow({ where: { id: session.identityId } });
    if (identity.status === 'SUSPENDED') {
      throw new FapiException(HttpStatus.FORBIDDEN, ErrorCode.IdentitySuspended, 'Identity suspended');
    }

    const environment = await this.console.environment.findUniqueOrThrow({ where: { id: client.environmentId } });
    const cookieSuffix = getCookieSuffix(environment.publishableKey);
    const accessToken = await this.identityToken.signAccessToken(
      identity.id, environment.publishableKey, environment.accessTokenTtl,
      { email: identity.email, firstName: identity.firstName, lastName: identity.lastName, avatar: identity.avatar },
      client.environmentId, session.id, session.status, cookieSuffix,
    );
    const touched = await this.platform.session.update({ where: { id: session.id }, data: { lastActiveAt: new Date(), lastAccessToken: accessToken } });

    return {
      object: 'client' as const,
      clientId: client.id,
      clientToken: rotated.clientToken,
      clientUat: this.clientUatFor(rotated.clientUat, session.id),
      sessions: [this.buildSessionSummary(touched, identity)],
      activeSessionId: session.id as string | null,
    };
  }

  private async resolveSessionByRefreshToken(clientId: string, sessionRefreshToken: string) {
    const session = await this.platform.session.findUnique({
      where: { clientId_refreshTokenHash: { clientId, refreshTokenHash: this.hashToken(sessionRefreshToken) } },
    });
    if (!session || session.status !== 'ACTIVE') {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.SessionInvalid, 'Invalid session');
    }
    return session;
  }

  // POST /auth/client/refresh's own logic — the Clerk-BAPI-/refresh
  // equivalent (see that controller route's own doc comment for the full
  // rationale). Deliberately does NOT take clientId/clientToken at all —
  // sessionId + refreshToken together are the whole proof, exactly
  // mirroring Clerk's own sessions.refreshSession(sessionId, {
  // refresh_token }) contract (confirmed via source read this session).
  // Looks the session up directly by id (not by clientId_refreshTokenHash
  // like resolveSessionByRefreshToken above, since this caller may not
  // have ever resolved/rotated a Client at all — it's not relaying a
  // browser's own client-bootstrap flow, it's an independent server-side
  // recovery call) then verifies the presented refreshToken actually
  // matches that session's own hash — never the other way around (looking
  // up BY refreshTokenHash first) since a Session row has exactly one
  // refreshTokenHash and this ordering gives a clean 404 vs 401
  // distinction for callers to log correctly.
  async refreshFromToken(sessionId: string, refreshToken: string, environmentId: string) {
    const session = await this.platform.session.findUnique({ where: { id: sessionId } });
    if (!session) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.SessionInvalid, 'Invalid session');
    }
    if (session.status !== 'ACTIVE' || session.expiresAt < new Date()) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.SessionInvalid, 'Invalid session');
    }
    if (session.refreshTokenHash !== this.hashToken(refreshToken)) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.SessionInvalid, 'Invalid session');
    }

    const identity = await this.platform.identity.findUniqueOrThrow({ where: { id: session.identityId } });
    if (identity.status === 'SUSPENDED') {
      throw new FapiException(HttpStatus.FORBIDDEN, ErrorCode.IdentitySuspended, 'Identity suspended');
    }

    const environment = await this.console.environment.findUniqueOrThrow({ where: { id: environmentId } });
    const cookieSuffix = getCookieSuffix(environment.publishableKey);
    const accessToken = await this.identityToken.signAccessToken(
      identity.id, environment.publishableKey, environment.accessTokenTtl,
      { email: identity.email, firstName: identity.firstName, lastName: identity.lastName, avatar: identity.avatar },
      environmentId, session.id, session.status, cookieSuffix,
    );

    // Rotate the refresh token on every successful use — same reasoning
    // as createHandshake()'s own rotation (see that method's doc comment):
    // treating each recovery call as a fresh mint limits how long any one
    // presented value stays valid, matching Client.rotatingToken's own
    // established pattern elsewhere in this file.
    const newRefreshToken = randomBytes(32).toString('hex');
    await this.platform.session.update({
      where: { id: session.id },
      data: { lastActiveAt: new Date(), lastAccessToken: accessToken, refreshTokenHash: this.hashToken(newRefreshToken) },
    });

    return { accessToken, refreshToken: newRefreshToken };
  }

  async clientBootstrap(clientId: string | undefined, clientToken: string | undefined, environmentId: string, activeSessionRefreshToken?: string) {
    if (!clientId || !clientToken) {
      const c = await this.createClient(environmentId);
      return { object: 'client' as const, clientId: c.clientId, clientToken: c.clientToken, clientUat: this.clientUatFor(c.clientUat, null), sessions: [], activeSessionId: null as string | null };
    }
    try {
      const client = await this.resolveClient(clientId, clientToken, environmentId);
      const rotated = await this.rotateClientToken(client.id);
      return await this.buildClientBootstrapResponse(client.id, client.environmentId, rotated.clientToken, rotated.clientUat, activeSessionRefreshToken);
    } catch {
      const c = await this.createClient(environmentId);
      return { object: 'client' as const, clientId: c.clientId, clientToken: c.clientToken, clientUat: this.clientUatFor(c.clientUat, null), sessions: [], activeSessionId: null as string | null };
    }
  }

  // Shared by clientBootstrap (cookie/DTO-resolved clientId) and
  // clientBootstrapViaDevBrowser (DevBrowser-row-resolved clientId) — once a
  // Client row and its freshly-rotated token/uat are in hand, the session
  // lookup/rotation/response-building logic is identical regardless of how
  // the Client was resolved. Kept as one implementation so a fix here (like
  // the clientUatFor gating) can't accidentally apply to only one caller.
  private async buildClientBootstrapResponse(
    clientId: string,
    environmentId: string,
    rotatedClientToken: string,
    rotatedClientUat: number,
    activeSessionRefreshToken?: string,
  ) {
    const environment = await this.console.environment.findUniqueOrThrow({ where: { id: environmentId } });
    const cookieSuffix = getCookieSuffix(environment.publishableKey);

    const sessions = await this.platform.session.findMany({
      where: { clientId, status: 'ACTIVE' },
      orderBy: { lastActiveAt: 'desc' },
    });

    const activeSession = activeSessionRefreshToken
      ? sessions.find(s => s.refreshTokenHash === this.hashToken(activeSessionRefreshToken))
      : sessions[0];

    const identities = await this.platform.identity.findMany({
      where: { id: { in: sessions.map(s => s.identityId) } },
    });
    const identityById = new Map(identities.map(i => [i.id, i]));

    const buildSummaries = (rows: typeof sessions) =>
      rows
        .map(s => {
          const identity = identityById.get(s.identityId);
          return identity ? this.buildSessionSummary(s, identity) : null;
        })
        .filter((s): s is NonNullable<typeof s> => s !== null);

    if (!activeSession || activeSession.expiresAt < new Date()) {
      return { object: 'client' as const, clientId, clientToken: rotatedClientToken, clientUat: this.clientUatFor(rotatedClientUat, null), sessions: buildSummaries(sessions), activeSessionId: null as string | null };
    }

    const activeIdentity = identityById.get(activeSession.identityId);
    if (!activeIdentity || activeIdentity.status === 'SUSPENDED') {
      const usable = sessions.filter(s => s.id !== activeSession.id);
      return { object: 'client' as const, clientId, clientToken: rotatedClientToken, clientUat: this.clientUatFor(rotatedClientUat, null), sessions: buildSummaries(usable), activeSessionId: null as string | null };
    }

    const activeExpired = !activeSession.lastAccessToken || activeSession.expiresAt < new Date();
    let touchedActive = activeSession;
    if (activeExpired) {
      const accessToken = await this.identityToken.signAccessToken(
        activeIdentity.id, environment.publishableKey, environment.accessTokenTtl,
        { email: activeIdentity.email, firstName: activeIdentity.firstName, lastName: activeIdentity.lastName, avatar: activeIdentity.avatar },
        environmentId, activeSession.id, activeSession.status, cookieSuffix,
      );
      touchedActive = await this.platform.session.update({ where: { id: activeSession.id }, data: { lastActiveAt: new Date(), lastAccessToken: accessToken } });
    } else {
      touchedActive = await this.platform.session.update({ where: { id: activeSession.id }, data: { lastActiveAt: new Date() } });
    }

    const otherSessions = sessions.filter(s => s.id !== activeSession.id);
    const allSessions = [touchedActive, ...otherSessions];

    return {
      object: 'client' as const,
      clientId,
      clientToken: rotatedClientToken,
      clientUat: this.clientUatFor(rotatedClientUat, activeSession.id),
      sessions: buildSummaries(allSessions),
      activeSessionId: activeSession.id as string | null,
    };
  }

  // Read-only counterpart to clientBootstrap — GET /auth/client. Validates
  // the presented clientId/clientToken exactly like clientBootstrap does,
  // but deliberately never rotates the token or touches session state (no
  // rotateClientToken call, no lastActiveAt/lastAccessToken writes) —
  // matches Clerk's own GET /client being a pure read. A caller with no
  // client yet (or an invalid/expired one) gets an empty, anonymous
  // response rather than an error — same "never throws" contract as
  // clientBootstrap, since this route runs pre-auth (Tier A/C) and an
  // absent client isn't a caller error.
  async fetchClient(clientId: string | undefined, clientToken: string | undefined, environmentId: string) {
    if (!clientId || !clientToken) {
      return { object: 'client' as const, clientId: null, clientUat: 0, sessions: [], activeSessionId: null as string | null };
    }
    let client;
    try {
      client = await this.resolveClient(clientId, clientToken, environmentId);
    } catch {
      return { object: 'client' as const, clientId: null, clientUat: 0, sessions: [], activeSessionId: null as string | null };
    }

    const sessions = await this.platform.session.findMany({
      where: { clientId: client.id, status: 'ACTIVE' },
      orderBy: { lastActiveAt: 'desc' },
    });
    const identities = await this.platform.identity.findMany({
      where: { id: { in: sessions.map(s => s.identityId) } },
    });
    const identityById = new Map(identities.map(i => [i.id, i]));
    const summaries = sessions
      .map(s => {
        const identity = identityById.get(s.identityId);
        return identity ? this.buildSessionSummary(s, identity) : null;
      })
      .filter((s): s is NonNullable<typeof s> => s !== null);

    const clientUat = Math.floor(client.updatedAt.getTime() / 1000);
    const activeSessionId = summaries.find(s => s.status === 'ACTIVE')?.id ?? null;

    return {
      object: 'client' as const,
      clientId: client.id,
      clientUat: this.clientUatFor(clientUat, activeSessionId),
      sessions: summaries,
      activeSessionId,
    };
  }

  // Mints a fresh, unauthenticated dev-browser pointer — see DevBrowser
  // model's doc comment in platform.prisma. Guarded only by
  // EnvironmentGuard at the controller level (resolves environmentId from
  // the Host header, same as every other pre-auth route) since this call
  // happens before any Client exists and needs no session/secret context.
  async createDevBrowser(environmentId: string) {
    const id = generateId();
    const expiresAt = new Date(Date.now() + CLIENT_TTL_SECONDS * 1000);
    const row = await this.platform.devBrowser.create({
      data: { id, environmentId, expiresAt },
    });
    const token = await this.identityToken.signDevBrowserToken(id, environmentId);
    return { id: row.id, token, createdAt: row.createdAt, updatedAt: row.updatedAt };
  }

  // POST /auth/client's dev-browser path. Resolves/creates the Client via
  // the DevBrowser row's mapping instead of the httpOnly __client cookie —
  // the controller MUST NOT call setClientCookie() when this path is taken,
  // since the whole point is that a cross-site dev/staging request can't
  // reliably receive/use an httpOnly cookie in the first place.
  async clientBootstrapViaDevBrowser(devBrowserId: string, environmentId: string, activeSessionRefreshToken?: string) {
    const devBrowser = await this.platform.devBrowser.findUnique({ where: { id: devBrowserId } });

    // REJECTS on unknown/expired/cross-environment — matches Clerk's own
    // FAPI behavior exactly: an invalid __clerk_db_jwt gets a 401 with
    // code dev_browser_unauthenticated, which the client SDK detects and
    // reacts to by discarding the stale value and minting a fresh one via
    // a NEW POST /auth/dev_browser call (see clerk-js's
    // AuthCookieService.handleUnauthenticatedDevBrowser, confirmed against
    // source this session). Silently minting a fresh Client here instead
    // — the previous behavior — gave the caller no signal that anything
    // was wrong: a stale/cross-environment devBrowserId would silently
    // start resolving a brand-new anonymous client with no error, and (in
    // the cross-environment case) would rebind the DevBrowser row to that
    // new environment, stealing the pointer from whichever environment it
    // was previously bound to. Mirrors resolveClientViaDevBrowser's
    // (ClientResolverService) identical rejection — that guard-side
    // sibling was already doing this correctly; this method was the one
    // remaining place with the old silent-mint behavior.
    if (!devBrowser || devBrowser.environmentId !== environmentId || devBrowser.expiresAt < new Date()) {
      throw new FapiException(
        HttpStatus.UNAUTHORIZED,
        ErrorCode.DevBrowserUnauthenticated,
        'Browser unauthenticated',
        'Unable to authenticate this browser for your development instance. Check your cookies and try again.',
      );
    }

    // A valid, same-environment, unexpired DevBrowser row with no Client
    // bound yet is NOT an error — it's the ordinary first-request case for
    // a brand-new dev browser (minted via POST /auth/dev_browser moments
    // earlier, never yet used to bootstrap a Client). Mint one and bind
    // it, same as before.
    if (!devBrowser.clientId) {
      const c = await this.createClient(environmentId);
      await this.platform.devBrowser.update({ where: { id: devBrowserId }, data: { clientId: c.clientId } });
      return { object: 'client' as const, clientId: c.clientId, clientToken: c.clientToken, clientUat: this.clientUatFor(c.clientUat, null), sessions: [], activeSessionId: null as string | null };
    }

    try {
      const client = await this.platform.client.findUniqueOrThrow({ where: { id: devBrowser.clientId } });
      const rotated = await this.rotateClientToken(client.id);
      return await this.buildClientBootstrapResponse(client.id, client.environmentId, rotated.clientToken, rotated.clientUat, activeSessionRefreshToken);
    } catch {
      // Bound Client row is gone (e.g. expired/cleaned up) — mint a fresh
      // one and rebind, rather than erroring the whole dev-browser identity.
      const c = await this.createClient(environmentId);
      await this.platform.devBrowser.update({ where: { id: devBrowserId }, data: { clientId: c.clientId } });
      return { object: 'client' as const, clientId: c.clientId, clientToken: c.clientToken, clientUat: this.clientUatFor(c.clientUat, null), sessions: [], activeSessionId: null as string | null };
    }
  }

  // GET /auth/handshake — the FAPI-hosted counterpart to sdks/nextjs's own
  // backend-proxy handshake route. That route only ever runs same-site (the
  // tenant's own backend), so it can paint cookies directly on its response.
  // A cross-site direct-mode caller (dev/staging, browser talking straight
  // to FAPI) can't rely on FAPI's own Set-Cookie headers landing on the
  // app's origin at all — so instead of setting cookies itself, this method
  // returns literal Set-Cookie header VALUE strings for the caller (the
  // controller) to sign into a JWT and hand back via redirect, mirroring
  // Clerk's own __clerk_handshake mechanism exactly (payload key name and
  // full-Set-Cookie-string shape both confirmed by decoding a real Clerk
  // handshake token). No dev_browser param present is itself meaningful —
  // Clerk's own DevBrowserMissing case — so a fresh DevBrowser is minted as
  // part of the same round trip rather than requiring the caller to have
  // already called POST /auth/dev_browser first.
  async createHandshake(devBrowserId: string | undefined, environmentId: string, activeSessionRefreshToken?: string) {
    const environment = await this.console.environment.findUniqueOrThrow({ where: { id: environmentId } });
    const isDevelopment = environment.type === 'DEVELOPMENT';

    let result: { clientId: string; clientToken: string; clientUat: number; sessions: Array<{ id: string; accessToken: string | null }>; activeSessionId: string | null };
    let resolvedDevBrowserId = devBrowserId;

    if (isDevelopment) {
      if (!resolvedDevBrowserId) {
        const minted = await this.createDevBrowser(environmentId);
        resolvedDevBrowserId = minted.id;
      }
      result = await this.clientBootstrapViaDevBrowser(resolvedDevBrowserId, environmentId, activeSessionRefreshToken);
    } else {
      // PRODUCTION is always same-site by construction (custom-domain
      // precondition — see direct-mode-guard.ts) — no dev-browser concept
      // applies here, resolve the Client the normal cookie-based way, but
      // this method still returns directives rather than setting cookies
      // itself, so the same one code path serves both environment types.
      result = await this.clientBootstrap(undefined, undefined, environmentId, activeSessionRefreshToken);
    }

    const activeSession = result.activeSessionId ? result.sessions.find(s => s.id === result.activeSessionId) ?? null : null;

    const directives: string[] = [];
    const isProd = process.env.NODE_ENV === 'production';
    const secure = isProd ? '; Secure' : '';
    const sameSite = isProd ? 'None' : 'Lax';

    if (isDevelopment && resolvedDevBrowserId) {
      const devBrowserToken = await this.identityToken.signDevBrowserToken(resolvedDevBrowserId, environmentId);
      directives.push(`__shipstack_db_jwt=${devBrowserToken}; Path=/; Max-Age=${CLIENT_TTL_SECONDS}${secure}; SameSite=${sameSite}`);
    }

    directives.push(`__client_uat=${result.clientUat}; Path=/; Max-Age=${CLIENT_TTL_SECONDS}${secure}; SameSite=${sameSite}`);

    if (activeSession?.accessToken) {
      directives.push(`__session=${activeSession.accessToken}; Path=/; Max-Age=900${secure}; SameSite=${sameSite}`);

      // __refresh_<suffix> — minted (and ROTATED) fresh on every handshake
      // that resolves to a real active session, never by attempt
      // completion. Matches Clerk's own behavior exactly (confirmed via a
      // live captured Clerk network trace this session: __refresh only
      // ever appeared in the handshake-response directive bundle, never in
      // the sign-in/sign-up response itself). Rotating on every handshake
      // — not just first mint — mirrors how Client.rotatingToken already
      // works elsewhere in this file; a handshake is a frequent, ordinary
      // reconciliation call (session-expired page loads, dev-browser sync,
      // client_uat mismatches — not just post-OAuth), so treating each
      // call as a fresh mint is the expected steady state, not a rare
      // event. The plaintext exists only in this response and is
      // immediately one-way hashed at rest (Session.refreshTokenHash) —
      // there is no way to recover it afterward except by calling
      // handshake again.
      const refreshToken = randomBytes(32).toString('hex');
      await this.platform.session.update({
        where: { id: activeSession.id },
        data: { refreshTokenHash: this.hashToken(refreshToken) },
      });
      const refreshCookieName = `__refresh_${getCookieSuffix(environment.publishableKey)}`;
      directives.push(`${refreshCookieName}=${refreshToken}; Path=/; Max-Age=${CLIENT_TTL_SECONDS}; HttpOnly${secure}; SameSite=${sameSite}`);
    } else {
      directives.push(`__session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT${secure}; SameSite=${sameSite}`);
    }

    const token = await this.identityToken.signHandshakePayload(directives, environmentId);
    return { token, clientId: result.clientId, clientToken: result.clientToken };
  }

  // OAuth-completion counterpart to createHandshake() above — mints a
  // handshake token for a Client the CALLER already knows is legitimate
  // (a just-completed SignInAttempt's own clientId), skipping the
  // devBrowser/clientToken resolution path entirely. This is safe ONLY
  // because it's called server-side, from OAuthCallbackController
  // immediately after resolveExternal() has already verified the OAuth
  // state/code exchange — the attempt's own one-time state match IS the
  // security boundary here (same trust level createHandshake()'s callers
  // get from a valid clientToken), not a new weaker check. Never expose
  // this as a public route parameter — clientId alone, with no signature/
  // token proof, must never be caller-suppliable from outside FAPI's own
  // server-side OAuth-completion code path.
  //
  // Exists specifically to let oauth_callback mint-and-redirect in ONE hop
  // (matching Clerk's own clerk.accounts.dev behavior exactly — confirmed
  // via a real captured Clerk network trace this session: the tenant FAPI's
  // OAuth-callback response embeds __clerk_handshake directly, no separate
  // handshake-endpoint round trip) instead of createHandshake()'s own
  // devBrowser-bootstrap path, which has no way to resolve a SPECIFIC
  // already-known client without a token this call site never has.
  async createHandshakeForAttempt(clientId: string, environmentId: string) {
    const environment = await this.console.environment.findUniqueOrThrow({ where: { id: environmentId } });
    const isDevelopment = environment.type === 'DEVELOPMENT';

    const rotated = await this.rotateClientToken(clientId);
    const result = await this.buildClientBootstrapResponse(clientId, environmentId, rotated.clientToken, rotated.clientUat);

    const activeSession = result.activeSessionId ? result.sessions.find(s => s.id === result.activeSessionId) ?? null : null;

    const directives: string[] = [];
    const isProd = process.env.NODE_ENV === 'production';
    const secure = isProd ? '; Secure' : '';
    const sameSite = isProd ? 'None' : 'Lax';

    // Unlike createHandshake(), there's no devBrowserId to mint a
    // __shipstack_db_jwt directive for here — this path never goes through
    // clientBootstrapViaDevBrowser, so isDevelopment alone doesn't trigger
    // that directive. A dev-mode caller picks up its own __shipstack_db_jwt
    // via the NEXT ordinary handshake/bootstrap call, same as any other
    // fresh Client would.
    void isDevelopment;

    // The client token was rotated above. The browser must receive the new
    // __client, or its next request presents the old token and trips reuse
    // detection. Signed the same way setClientCookie signs it.
    const clientJwt = signClientCookie(clientId, rotated.clientToken);
    directives.push(`__client=${clientJwt}; Path=/; Max-Age=${CLIENT_COOKIE_MAX_AGE_SECONDS}; HttpOnly${secure}; SameSite=${sameSite}`);
    directives.push(`__client_uat=${result.clientUat}; Path=/; Max-Age=${CLIENT_TTL_SECONDS}${secure}; SameSite=${sameSite}`);

    if (activeSession?.accessToken) {
      directives.push(`__session=${activeSession.accessToken}; Path=/; Max-Age=900${secure}; SameSite=${sameSite}`);

      const refreshToken = randomBytes(32).toString('hex');
      await this.platform.session.update({
        where: { id: activeSession.id },
        data: { refreshTokenHash: this.hashToken(refreshToken) },
      });
      const refreshCookieName = `__refresh_${getCookieSuffix(environment.publishableKey)}`;
      directives.push(`${refreshCookieName}=${refreshToken}; Path=/; Max-Age=${CLIENT_TTL_SECONDS}; HttpOnly${secure}; SameSite=${sameSite}`);
    } else {
      directives.push(`__session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT${secure}; SameSite=${sameSite}`);
    }

    const token = await this.identityToken.signHandshakePayload(directives, environmentId);
    return { token, clientId: result.clientId, clientToken: result.clientToken };
  }

  async logout(clientId: string, sessionId?: string) {
    const where = sessionId ? { id: sessionId, clientId } : { clientId, status: 'ACTIVE' as const };
    await this.platform.session.updateMany({ where, data: { status: 'ENDED' } });
    return { ok: true };
  }

  // ── Session lifecycle — /auth/client/sessions/* ─────────────────────────
  // Every method here is scoped by clientId (never a bare sessionId lookup)
  // — a session's ownership is the entire authorization model for these
  // routes: the caller already proved control of the Client via SessionGuard,
  // and that's the only credential these need. Mirrors resolveClient's own
  // "everything downstream flows from an already-validated Client" posture.

  private async ownedSession(sessionId: string, clientId: string) {
    const session = await this.platform.session.findUnique({ where: { id: sessionId } });
    if (!session || session.clientId !== clientId) {
      throw new FapiException(HttpStatus.NOT_FOUND, ErrorCode.SessionNotFound, 'Session not found');
    }
    return session;
  }

  async getSession(sessionId: string, clientId: string) {
    const session = await this.ownedSession(sessionId, clientId);
    const identity = await this.platform.identity.findUniqueOrThrow({ where: { id: session.identityId } });
    return this.buildSessionSummary(session, identity);
  }

  // Pure heartbeat — bumps lastActiveAt only. Never mints a token or
  // touches lastAccessToken; a caller that needs a fresh token calls
  // mintSessionToken separately (see that method's own comment on why the
  // two are kept apart).
  async touchSession(sessionId: string, clientId: string) {
    await this.ownedSession(sessionId, clientId);
    const updated = await this.platform.session.update({ where: { id: sessionId }, data: { lastActiveAt: new Date() } });
    const identity = await this.platform.identity.findUniqueOrThrow({ where: { id: updated.identityId } });
    return this.buildSessionSummary(updated, identity);
  }

  // Revokes server-side validity — the session can no longer be refreshed
  // or resolved as active, but the row (and its place in sessions[]) is
  // kept. Distinct from removeSession: see that method's own comment.
  async endSession(sessionId: string, clientId: string) {
    await this.ownedSession(sessionId, clientId);
    const updated = await this.platform.session.update({ where: { id: sessionId }, data: { status: 'ENDED' } });
    const identity = await this.platform.identity.findUniqueOrThrow({ where: { id: updated.identityId } });
    return this.buildSessionSummary(updated, identity);
  }

  // Also revokes server-side validity (REMOVED, not ENDED — a separate
  // terminal status per SessionStatus) but additionally signals "forget
  // this session" for UI purposes — e.g. dismissing a signed-out account
  // from a multi-account switcher, where ENDED alone would still surface it
  // in sessions[] as a recently-active-but-now-invalid entry. Functionally
  // identical revocation to endSession; the status value itself is the only
  // difference, kept as two routes/methods so a caller's intent is explicit
  // rather than inferred from context.
  async removeSession(sessionId: string, clientId: string) {
    await this.ownedSession(sessionId, clientId);
    const updated = await this.platform.session.update({ where: { id: sessionId }, data: { status: 'REMOVED' } });
    const identity = await this.platform.identity.findUniqueOrThrow({ where: { id: updated.identityId } });
    return this.buildSessionSummary(updated, identity);
  }

  // Mints a fresh access token for a SPECIFIC session — the multi-session
  // counterpart to refreshSession's "whichever session is active" scope.
  // This is what makes real session switching work: a caller holding
  // multiple concurrent sessions (multi-account) can mint a usable token
  // for any one of them by id, not just the client's single activeSessionId.
  // Deliberately does not touch lastActiveAt/status — minting a token for a
  // session doesn't mean the caller is switching to it as "active" (that's
  // a Client-level concept resolved via activeSessionRefreshToken on
  // POST/PUT /auth/client), just that they want a usable token for it right
  // now.
  async mintSessionToken(sessionId: string, clientId: string) {
    const session = await this.ownedSession(sessionId, clientId);
    if (session.status !== 'ACTIVE' || session.expiresAt < new Date()) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.SessionNotActive, 'Session is not active');
    }
    const identity = await this.platform.identity.findUniqueOrThrow({ where: { id: session.identityId } });
    const client = await this.platform.client.findUniqueOrThrow({ where: { id: clientId } });
    const environment = await this.console.environment.findUniqueOrThrow({ where: { id: client.environmentId } });
    const cookieSuffix = getCookieSuffix(environment.publishableKey);
    const accessToken = await this.identityToken.signAccessToken(
      identity.id, environment.publishableKey, environment.accessTokenTtl,
      { email: identity.email, firstName: identity.firstName, lastName: identity.lastName, avatar: identity.avatar },
      environment.id, session.id, session.status, cookieSuffix,
    );
    const updated = await this.platform.session.update({ where: { id: session.id }, data: { lastAccessToken: accessToken } });
    return this.buildSessionSummary(updated, identity);
  }

  async passwordResetConfirm(dto: { token: string; newPassword: string }) {
    const tokenHash = this.hashToken(dto.token);

    const stored = await this.platform.resetToken.findUnique({
      where: { tokenHash },
      include: { identity: true },
    });
    if (!stored || stored.expiresAt < new Date() || stored.usedAt) {
      throw new BadRequestException('Token invalid, expired, or already used');
    }

    const { minPasswordLength, passwordRequirements, preventLeakedPasswords, minPasswordStrength } = await this.getEnvConfig(stored.identity.environmentId);
    this.validatePassword(dto.newPassword, minPasswordLength, passwordRequirements, minPasswordStrength);
    if (preventLeakedPasswords && await this.isPasswordLeaked(dto.newPassword)) {
      throw new BadRequestException('This password has appeared in a data breach. Please choose a different password.');
    }

    const newCredential = await argon2.hash(dto.newPassword);
    await this.platform.identity.update({
      where: { id: stored.identityId },
      data: { credential: newCredential },
    });

    await this.platform.resetToken.update({
      where: { id: stored.id },
      data: { usedAt: new Date() },
    });

    await this.platform.session.updateMany({ where: { identityId: stored.identityId }, data: { status: 'REVOKED' } });
    return { ok: true };
  }


  async verifyEmail(token: string) {
    const tokenHash = this.hashToken(token);
    const stored = await this.platform.verificationToken.findUnique({ where: { tokenHash } });

    if (!stored || stored.expiresAt < new Date() || stored.usedAt) {
      throw new BadRequestException('Verification token invalid, expired, or already used');
    }

    await this.platform.identity.update({
      where: { id: stored.identityId },
      data: { emailVerified: true },
    });

    await this.platform.verificationToken.update({
      where: { id: stored.id },
      data: { usedAt: new Date() },
    });

    return { ok: true };
  }

  async resendVerification(environmentId: string, email: string) {
    const normalizedEmail = email.toLowerCase().trim();
    const identity = await this.platform.identity.findUnique({
      where: { environmentId_email: { environmentId, email: normalizedEmail } },
    });

    // Always return ok — never reveal if identity exists
    if (!identity || identity.emailVerified) return { ok: true };

    await this.sendVerificationEmail({ id: identity.id, email: identity.email });
    return { ok: true };
  }

  // ── Phase 2: FAPI-B / FAPI-C additions ──────────────────────────────────────

  // Ported from identities-auth.service.ts's verify(). Stateless JWT
  // verification against the issuer's own key — no DB write, no client/
  // session cookie needed. See auth.controller.ts for the Tier A-vs-C guard
  // discussion (backend-proxy mode calls this with Basic auth per
  // sdks/core/src/auth.ts, so it's mounted under Tier C, but the underlying
  // logic here works identically with or without a secretKey).
  async verify(accessToken: string, publishableKey: string) {
    const environmentId = await this.identityToken.resolveEnvironmentId(publishableKey);
    const payload = await this.identityToken.verifyAccessToken(accessToken, environmentId);
    if (!payload || payload.iss !== publishableKey) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.TokenInvalidOrExpired, 'Invalid or expired token');
    }
    return { shipstackId: payload.sub, publishableKey: payload.iss, sessionId: payload.sid, valid: true };
  }

  // Ported from identities-auth.service.ts's changePassword(). Takes
  // dto.shipstackId directly (not derived from a session) — this is the
  // documented gap: fine for Tier C (trusted backend-proxy relaying its own
  // already-authenticated user), unsafe if ever exposed under Tier A/B
  // without deriving the target identity from req.identity.sub instead of
  // trusting the body. Deliberately NOT exposed under Tier A/B in this
  // phase — see auth.controller.ts. A future "self-service change-password"
  // variant using the session's own identity would need a *separate*
  // method that ignores dto.shipstackId entirely and reads
  // req.identity.sub, not a guard swap on this one.
  async changePassword(dto: { shipstackId: string; currentPassword: string; newPassword: string }, environmentId: string) {
    return this.changePasswordSelf(dto.shipstackId, environmentId, dto.currentPassword, dto.newPassword);
  }

  // Session-derived variant — identityId is an explicit first argument
  // supplied by the controller from req.identity.sub (via SessionGuard),
  // never from the request body. Shares all validation/argon2/session-
  // revocation logic with changePassword() above (Tier C, body-trusted),
  // which now delegates here. See auth.controller.ts's `me/password` PATCH
  // handler for the guard-tier reasoning.
  async changePasswordSelf(identityId: string, environmentId: string, currentPassword: string, newPassword: string) {
    const identity = await this.platform.identity.findFirst({
      where: { id: identityId, environmentId },
    });
    if (!identity || !identity.credential) {
      throw new FapiException(HttpStatus.NOT_FOUND, ErrorCode.IdentityNotFound, 'Identity not found');
    }

    const valid = await argon2.verify(identity.credential, currentPassword);
    if (!valid) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.PasswordIncorrect, 'Current password incorrect');
    }

    const { minPasswordLength, passwordRequirements, preventLeakedPasswords, minPasswordStrength } = await this.getEnvConfig(environmentId);
    this.validatePassword(newPassword, minPasswordLength, passwordRequirements, minPasswordStrength);
    if (preventLeakedPasswords && await this.isPasswordLeaked(newPassword)) {
      throw new BadRequestException('This password has appeared in a data breach. Please choose a different password.');
    }

    const newCredential = await argon2.hash(newPassword);
    await this.platform.identity.update({
      where: { id: identityId },
      data: { credential: newCredential },
    });

    await this.platform.session.updateMany({ where: { identityId }, data: { status: 'REVOKED' } });
    return { ok: true };
  }

  // Ported from identities-auth.service.ts's passwordResetRequest(). Looks
  // up the identity by email (never reveals existence), needs only
  // publishableKey — genuinely Tier A shape. Mounted under Tier C anyway
  // since backend-proxy also calls it (Tier C is a strict superset of
  // Tier A's req.environment attachment) and the plan calls for one route,
  // not a fork.
  async passwordResetRequest(dto: { email: string }, environmentId: string) {
    const email = dto.email.toLowerCase().trim();
    const identity = await this.platform.identity.findUnique({
      where: { environmentId_email: { environmentId, email } },
    });

    // Always return ok — never reveal if identity exists
    if (!identity) return { ok: true };

    const rawToken = randomBytes(32).toString('hex');
    const tokenHash = this.hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 min

    await this.platform.resetToken.deleteMany({ where: { identityId: identity.id } });
    await this.platform.resetToken.create({
      data: { id: generateId(), identityId: identity.id, tokenHash, expiresAt },
    });

    await this.mail.sendPasswordReset(email, rawToken);
    return { ok: true };
  }

  // Ported from identities-auth.service.ts's logoutAll(). Takes shipstackId
  // directly — same gap/treatment as changePassword above: Tier C only.
  async logoutAll(shipstackId: string, environmentId: string) {
    const identity = await this.platform.identity.findFirst({
      where: { id: shipstackId, environmentId },
    });
    if (!identity) throw new FapiException(HttpStatus.NOT_FOUND, ErrorCode.IdentityNotFound, 'Identity not found');

    await this.platform.session.updateMany({ where: { identityId: shipstackId, status: 'ACTIVE' }, data: { status: 'REVOKED' } });
    return { ok: true };
  }

  // NEW — does not exist on platform-api at all. Self-service profile
  // update. The controller MUST derive `shipstackId` from req.identity.sub
  // (verified __session JWT via SessionGuard), never from the request body
  // — enforced at the controller layer, see auth.controller.ts. Only
  // firstName/lastName/avatar are updatable here; email/credential changes
  // go through the dedicated verify-email/change-password flows.
  async updateMe(shipstackId: string, environmentId: string, dto: { firstName?: string; lastName?: string; avatar?: string }) {
    const identity = await this.platform.identity.findFirst({
      where: { id: shipstackId, environmentId },
    });
    if (!identity) throw new FapiException(HttpStatus.NOT_FOUND, ErrorCode.IdentityNotFound, 'Identity not found');

    const updated = await this.platform.identity.update({
      where: { id: shipstackId },
      data: {
        ...(dto.firstName !== undefined ? { firstName: dto.firstName?.trim() || null } : {}),
        ...(dto.lastName !== undefined ? { lastName: dto.lastName?.trim() || null } : {}),
        ...(dto.avatar !== undefined ? { avatar: dto.avatar || null } : {}),
      },
    });

    return {
      shipstackId: updated.id,
      email: updated.email,
      firstName: updated.firstName,
      lastName: updated.lastName,
      avatar: updated.avatar,
    };
  }
}
