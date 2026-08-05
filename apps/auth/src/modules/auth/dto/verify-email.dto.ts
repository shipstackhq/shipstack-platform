import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

// No EnvironmentGuard on POST /auth/verify-email, same reasoning as
// PasswordResetConfirmDto's own identical note: the verification token
// itself (validated server-side against VerificationToken.tokenHash,
// scoped to the identity/environment that created it) is the sole
// credential. Deliberate, not an oversight — do not add a guard here.
export class VerifyEmailDto {
  @ApiProperty({ description: 'The token emailed on sign-up (when requireEmailVerification is on) or by resend-verification. Cannot be reused once consumed.' })
  @IsString() token: string;
}
