import { IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

// clientId/clientToken deliberately NOT accepted here — see
// ClientBootstrapDto's identical comment. Resolved via
// resolveClientFromRequest() (cookie for direct mode, x-shipstack-client
// header for backend-proxy) instead.
export class RefreshDto {
  @ApiProperty({ required: false, description: 'Omit to refresh whichever session is currently active for this client.' })
  @IsString() @IsOptional() sessionRefreshToken?: string;
}
