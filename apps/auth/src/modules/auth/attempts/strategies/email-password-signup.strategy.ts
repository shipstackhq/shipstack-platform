import { Injectable } from '@nestjs/common';
import { AuthService } from '@/modules/auth/auth.service';
import type { SignUpAttemptModel } from '@/generated/platform/models/SignUpAttempt';
import type { PreparedFirstFactor } from '../sign-in-strategy.interface';
import type { SignUpOutcome, SignUpStrategy } from '../sign-up-strategy.interface';

// Real implementation — mirrors EmailPasswordStrategy's shape (one-shot,
// no real async prepare step) but for sign-up. Delegates identity creation
// to AuthService.createPasswordIdentity — extracted from the legacy
// register() so this strategy and the old /auth/register route share one
// validation/creation path (same "reuse, don't fork" principle as Phase 3
// applied to OAuth).
@Injectable()
export class EmailPasswordSignUpStrategy implements SignUpStrategy {
  constructor(private auth: AuthService) {}

  async prepare(_attempt: SignUpAttemptModel): Promise<PreparedFirstFactor> {
    return {
      verificationData: null,
      verificationExpiresAt: new Date(Date.now() + 15 * 60 * 1000),
    };
  }

  async attempt(attempt: SignUpAttemptModel, input: unknown): Promise<SignUpOutcome> {
    const { password } = (input as { password?: string } | undefined) ?? {};
    if (!attempt.identifier || !password) {
      return { result: 'failed', reason: 'identifier and password are required' };
    }
    try {
      const { identity, requireEmailVerification } = await this.auth.createPasswordIdentity(
        { email: attempt.identifier, password, firstName: attempt.firstName ?? undefined, lastName: attempt.lastName ?? undefined },
        attempt.environmentId,
      );
      if (requireEmailVerification) {
        return { result: 'pending-verification', identityId: identity.id };
      }
      return { result: 'complete', identityId: identity.id, isNewIdentity: true };
    } catch (err: any) {
      return { result: 'failed', reason: err?.message ?? 'registration_failed' };
    }
  }

  async resolveExternal(): Promise<{ attemptId: string; outcome: SignUpOutcome }> {
    throw new Error('email_password does not support resolveExternal() — resolves via attempt()');
  }
}
