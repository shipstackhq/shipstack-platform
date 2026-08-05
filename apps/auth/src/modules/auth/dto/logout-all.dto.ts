import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LogoutAllDto {
  @ApiProperty({ description: 'Tier C only (backend-proxy/secretKey-bearer) — revokes every session for this identity across every client/device, not just the current one.' })
  @IsString() shipstackId: string;
}
