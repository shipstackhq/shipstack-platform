import { BadRequestException, Logger } from '@nestjs/common';
import { createHash, randomBytes } from 'crypto';
import axios from 'axios';
import { PlatformPrismaService } from '@/core/database/platform-prisma.service';
import { OAuthProvidersService } from '@/modules/auth/oauth-providers/oauth-providers.service';
import type { OAuthProvider } from '@/generated/platform/enums';
import type { SignInAttemptModel } from '@/generated/platform/models/SignInAttempt';
import type { AttemptOutcome, PreparedFirstFactor, SignInStrategy } from '../sign-in-strategy.interface';

// Shared base for every redirect-based OAuth SignInStrategy — extracted
// during Phase 8 (docs/unified-attempt-architecture.md) once adding
// Microsoft revealed the doc's original "config-only" claim was too strong:
// PKCE/state generation, attempt lookup via externalLookupKey, and identity
// resolution ARE fully provider-agnostic and belong here; only the
// authorize URL, token endpoint, userinfo endpoint, scope, and the raw
// profile-response field mapping are genuinely provider-specific and are
// left to each subclass via the abstract hooks below.
export interface OAuthProfile {
  providerUserId: string;
  // Nullable — Microsoft's /oidc/userinfo can omit the email claim for
  // some Azure AD configs (learn.microsoft.com confirmed this session).
  // Was previously typed as required `string` while the Microsoft strategy used to
  // mapProfile() assigned `data.email` unguarded — an account with no email
  // claim threw an uncaught TypeError three calls downstream
  // (OAuthProvidersService.findOrCreateOAuthIdentity's `email.toLowerCase()`),
  // surfacing as an unhandled 500 instead of a clean failed outcome. Fixed
  // at the type boundary so this can't silently regress: any future
  // provider's mapProfile() is now forced to either provide a real email or
  // explicitly return null, and resolveExternal() below handles null as a
  // normal failed outcome, same shape as a token-exchange/profile-fetch
  // failure.
  email: string | null;
  firstName: string | null;
  lastName: string | null;
  avatar: string | null;
}

export abstract class OAuthStrategyBase implements SignInStrategy {
  protected abstract readonly logger: Logger;
  protected abstract readonly provider: OAuthProvider;
  protected abstract readonly authorizeUrl: string;
  protected abstract readonly tokenUrl: string;
  protected abstract readonly userinfoUrl: string;
  protected abstract readonly scope: string;

  constructor(
    protected platform: PlatformPrismaService,
    protected oauthProviders: OAuthProvidersService,
  ) {}

  // Extra authorize-URL params a provider needs beyond the shared set
  // (e.g. Google's access_type=offline). Empty by default.
  protected extraAuthorizeParams(): Record<string, string> {
    return {};
  }

  // Maps the provider's raw userinfo response into the shared shape.
  // Google and Microsoft both happen to use OIDC-standard field names
  // (sub/given_name/family_name/picture) so their overrides are one-liners;
  // a future GitHub adapter (out of scope for this pass) would need a
  // genuinely different implementation here (id not sub, combined name,
  // separate /user/emails call).
  protected abstract mapProfile(data: any): OAuthProfile;

  private generateCodeVerifier(): string {
    return randomBytes(32).toString('base64url');
  }

  private generateCodeChallenge(verifier: string): string {
    return createHash('sha256').update(verifier).digest('base64url');
  }

  private redirectUri(): string {
    return `${process.env.BASE_URL ?? 'http://localhost:9001'}/api/v1/auth/oauth_callback`;
  }

  async prepare(attempt: SignInAttemptModel): Promise<PreparedFirstFactor> {
    const config = await this.oauthProviders.getDecrypted(attempt.environmentId, this.provider);

    const codeVerifier = this.generateCodeVerifier();
    const codeChallenge = this.generateCodeChallenge(codeVerifier);
    const state = randomBytes(16).toString('hex');

    const params = new URLSearchParams({
      client_id: config.providerClientId,
      redirect_uri: this.redirectUri(),
      response_type: 'code',
      scope: this.scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      ...this.extraAuthorizeParams(),
    });

    return {
      externalRedirectUrl: `${this.authorizeUrl}?${params.toString()}`,
      verificationData: { state, codeVerifier },
      verificationExpiresAt: new Date(Date.now() + 10 * 60 * 1000),
    };
  }

  async attempt(_attempt: SignInAttemptModel, _input: unknown): Promise<AttemptOutcome> {
    return { result: 'failed', reason: `${this.provider.toLowerCase()} does not support attempt() — resolves via resolveExternal() from the OAuth callback` };
  }

  async resolveExternal(request: unknown): Promise<{ attemptId: string; outcome: AttemptOutcome }> {
    const { code, state } = request as { code?: string; state?: string };
    if (!code || !state) throw new BadRequestException('Missing code or state');

    const attempt = await this.platform.signInAttempt.findUnique({ where: { externalLookupKey: state } });
    if (!attempt || attempt.expiresAt < new Date()) {
      throw new BadRequestException('Invalid or expired sign-in attempt');
    }

    const verificationData = attempt.verificationData as { state?: string; codeVerifier?: string } | null;
    if (!verificationData?.codeVerifier) {
      throw new BadRequestException('Sign-in attempt has no OAuth verification data');
    }

    const config = await this.oauthProviders.getDecrypted(attempt.environmentId, this.provider);

    let tokenResponse;
    try {
      tokenResponse = await axios.post(this.tokenUrl, {
        code,
        client_id: config.providerClientId,
        client_secret: config.providerClientSecret,
        redirect_uri: this.redirectUri(),
        grant_type: 'authorization_code',
        code_verifier: verificationData.codeVerifier,
      });
    } catch (err: any) {
      const status = err?.response?.status;
      const data = err?.response?.data;
      this.logger.error(`${this.provider} token exchange failed: status=${status} data=${JSON.stringify(data)} message=${err?.message}`);
      return { attemptId: attempt.id, outcome: { result: 'failed', reason: data?.error_description ?? data?.error ?? 'token_exchange_failed' } };
    }

    let profileResponse;
    try {
      profileResponse = await axios.get(this.userinfoUrl, {
        headers: { Authorization: `Bearer ${tokenResponse.data.access_token}` },
      });
    } catch (err: any) {
      this.logger.error(`${this.provider} profile fetch failed: ${err?.message}`);
      return { attemptId: attempt.id, outcome: { result: 'failed', reason: 'profile_fetch_failed' } };
    }

    const profile = this.mapProfile(profileResponse.data);

    if (!profile.email) {
      this.logger.warn(`${this.provider} profile for providerUserId=${profile.providerUserId} has no email claim`);
      return { attemptId: attempt.id, outcome: { result: 'failed', reason: 'no_email_claim' } };
    }

    const { identity, isNew } = await this.oauthProviders.findOrCreateOAuthIdentity(
      attempt.environmentId, profile.providerUserId, profile.email, profile.firstName, profile.lastName, profile.avatar, this.provider,
    );

    return { attemptId: attempt.id, outcome: { result: 'complete', identityId: identity.id, isNewIdentity: isNew } };
  }
}
