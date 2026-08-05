import { IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

// clientId/clientToken deliberately NOT accepted here — backend-proxy mode
// (no shared __client cookie with FAPI) relays the signed client JWT via
// the x-shipstack-client header instead (see client-cookie.ts's
// CLIENT_HEADER/resolveClientFromRequest doc comments for why a header, not
// a body field: a body field would need per-caller-type enforcement a
// browser could bypass, and doesn't work on the bodyless GET :id reload
// routes elsewhere in this codebase).
export class ClientBootstrapDto {
  @ApiProperty({ required: false, description: 'Switches which of the client\'s sessions is "active" — resolved by refresh token, not sessionId.' })
  @IsString() @IsOptional() activeSessionRefreshToken?: string;
}
