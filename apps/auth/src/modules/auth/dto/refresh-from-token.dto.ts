import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

// POST /auth/client/refresh's own body shape — deliberately NOT
// clientId/clientToken-based (see AuthController.refreshFromToken's own doc
// comment: possessing the correct refreshToken for this exact session is
// the whole proof, matching Clerk's sessions.refreshSession(sessionId, {
// refresh_token }) contract). sessionId is the caller's responsibility to
// have already decoded from its own expired access token's `sid` claim.
export class RefreshFromTokenDto {
  @ApiProperty({ description: 'Session id, decoded from the expired access token\'s own `sid` claim.' })
  @IsString() sessionId!: string;

  @ApiProperty({ description: 'The refresh token from the caller\'s own __refresh_<suffix> cookie.' })
  @IsString() refreshToken!: string;
}
