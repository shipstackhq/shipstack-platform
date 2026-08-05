import { BadRequestException, Injectable } from '@nestjs/common';
import { createHash, randomInt } from 'crypto';
import { PlatformPrismaService } from '@/core/database/platform-prisma.service';
import { MailService } from '@/core/mail/mail.service';
import type { SignInAttemptModel } from '@/generated/platform/models/SignInAttempt';
import type { AttemptOutcome, PreparedFirstFactor, SignInStrategy } from '../sign-in-strategy.interface';

// Real implementation, replacing the Phase 2 stub. EMAIL_CODE is sign-in
// only (matches Clerk's own model — their captured supported_first_factors
// list showed email_code alongside oauth_google for an ALREADY-KNOWN
// identifier, never for a brand-new one; sign-up's own email verification
// is register()'s existing 24-hour-token flow, a different mechanism, not
// this one). No identity creation here — an unknown identifier fails
// immediately in prepare(), same shape as EmailPasswordStrategy failing on
// a wrong password rather than silently creating an account.
//
// Same-device, same-tab shape: no externalRedirectUrl, attempt() does the
// real work, resolveExternal() is unused — this is the exact shape Phase 2
// validated the SignInStrategy interface against before any real strategy
// existed.
const CODE_TTL_MS = 10 * 60 * 1000;
const MAX_VERIFICATION_ATTEMPTS = 5;

@Injectable()
export class EmailCodeStrategy implements SignInStrategy {
  constructor(
    private platform: PlatformPrismaService,
    private mail: MailService,
  ) {}

  private hashCode(code: string): string {
    return createHash('sha256').update(code).digest('hex');
  }

  async prepare(attempt: SignInAttemptModel): Promise<PreparedFirstFactor> {
    if (!attempt.identifier) throw new BadRequestException('identifier is required for email_code');

    const identity = await this.platform.identity.findUnique({
      where: { environmentId_email: { environmentId: attempt.environmentId, email: attempt.identifier.toLowerCase().trim() } },
    });
    if (!identity) throw new BadRequestException('No account found for this identifier');
    if (identity.status === 'SUSPENDED') throw new BadRequestException('Identity suspended');

    // 6-digit numeric code — randomInt is cryptographically strong (Node's
    // crypto module), unlike Math.random(). Zero-padded so e.g. 42 reads
    // as "000042", matching what a user expects a 6-digit code to look
    // like.
    const code = randomInt(0, 1_000_000).toString().padStart(6, '0');
    await this.mail.sendVerificationCode(attempt.identifier, code);

    return {
      verificationData: { codeHash: this.hashCode(code), identityId: identity.id },
      verificationExpiresAt: new Date(Date.now() + CODE_TTL_MS),
    };
  }

  async attempt(attempt: SignInAttemptModel, input: unknown): Promise<AttemptOutcome> {
    const code = (input as { code?: string } | undefined)?.code;
    if (!code) return { result: 'failed', reason: 'code is required' };

    if (attempt.verificationAttempts >= MAX_VERIFICATION_ATTEMPTS) {
      return { result: 'failed', reason: 'too_many_attempts' };
    }
    if (attempt.verificationExpiresAt && attempt.verificationExpiresAt < new Date()) {
      return { result: 'failed', reason: 'code_expired' };
    }

    const data = attempt.verificationData as { codeHash?: string; identityId?: string } | null;
    if (!data?.codeHash || !data.identityId) {
      return { result: 'failed', reason: 'no_code_prepared' };
    }

    if (this.hashCode(code) !== data.codeHash) {
      // still-pending, not failed outright — verificationAttempts increments
      // (see AttemptsService.applyOutcome) so the user can retry up to
      // MAX_VERIFICATION_ATTEMPTS times, same UX as a typo'd OTP anywhere
      // else. A wrong password (EmailPasswordStrategy) DOES fail outright
      // instead, since that strategy has no retry-count concept of its own
      // in this design — a deliberate, minor asymmetry between the two
      // strategies' own attempt() semantics, not a bug.
      return { result: 'still-pending' };
    }

    return { result: 'complete', identityId: data.identityId, isNewIdentity: false };
  }

  async resolveExternal(): Promise<{ attemptId: string; outcome: AttemptOutcome }> {
    throw new Error('email_code does not support resolveExternal() — resolves via attempt()');
  }
}
