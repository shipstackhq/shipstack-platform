import { Injectable } from '@nestjs/common';
import { AuthService } from '@/modules/auth/auth.service';
import type { SignInAttemptModel } from '@/generated/platform/models/SignInAttempt';
import type { AttemptOutcome, PreparedFirstFactor, SignInStrategy } from '../sign-in-strategy.interface';

// Real implementation — email/password is the one strategy in this
// architecture that's naturally one-shot, not two-phase: prepare() and
// attempt() both exist to satisfy the SignInStrategy interface, but the
// actual generic route handler (AttemptsController/AttemptsService)
// special-cases create()-with-a-password to skip straight to attempt()
// without a separate prepare_first_factor round trip — see
// AttemptsService.create()'s own handling. This strategy itself doesn't
// need to know about that shortcut; attempt() below works identically
// whichever route reaches it.
//
// Delegates credential verification to AuthService.verifyPasswordCredential
// — extracted from the legacy login() specifically so this strategy and
// the old /auth/login route share one validation path instead of forking
// it (docs/unified-attempt-architecture.md's "reuse, don't fork"
// principle, applied here the same way Phase 3 applied it to OAuth
// identity resolution).
@Injectable()
export class EmailPasswordStrategy implements SignInStrategy {
  constructor(private auth: AuthService) {}

  async prepare(_attempt: SignInAttemptModel): Promise<PreparedFirstFactor> {
    // No async/external setup needed — password verification happens
    // entirely inside attempt(). verificationExpiresAt still bounds this
    // step, matching every other strategy's shape, even though nothing
    // here can actually go stale before the whole attempt itself expires.
    return {
      verificationData: null,
      verificationExpiresAt: new Date(Date.now() + 15 * 60 * 1000),
    };
  }

  async attempt(attempt: SignInAttemptModel, input: unknown): Promise<AttemptOutcome> {
    const { password } = (input as { password?: string } | undefined) ?? {};
    if (!attempt.identifier || !password) {
      return { result: 'failed', reason: 'identifier and password are required' };
    }
    try {
      const identity = await this.auth.verifyPasswordCredential(attempt.identifier, password, attempt.environmentId);
      return { result: 'complete', identityId: identity.id, isNewIdentity: false };
    } catch (err: any) {
      return { result: 'failed', reason: err?.message ?? 'invalid_credentials' };
    }
  }

  async resolveExternal(): Promise<{ attemptId: string; outcome: AttemptOutcome }> {
    throw new Error('email_password does not support resolveExternal() — resolves via attempt()');
  }
}
