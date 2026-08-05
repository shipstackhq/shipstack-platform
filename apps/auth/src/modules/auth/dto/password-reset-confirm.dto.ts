import { IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

// NOTE (Phase 1 gap, flagged per plan instructions): this DTO has no
// publishableKey field, matching platform-api's identical DTO — the reset
// token itself (validated server-side against ResetToken.tokenHash, scoped
// to the identity/environment that requested it) is the sole credential.
// There is no EnvironmentGuard on this route for the same reason
// platform-api's password-reset/confirm has no guard today: the token IS
// the auth. This is carried over unchanged, not redesigned, per the task
// instructions ("keep as token-in-body-is-the-credential").
export class PasswordResetConfirmDto {
  @ApiProperty({ description: 'The token emailed by password-reset/request.' })
  @IsString() token: string;
  @ApiProperty({ minLength: 8 })
  @IsString() @MinLength(8) newPassword: string;
}
