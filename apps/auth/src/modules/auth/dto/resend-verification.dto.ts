import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ResendVerificationDto {
  @ApiProperty({ example: 'jane@example.com', description: 'Silently a no-op for an unknown or already-verified identity — enumeration-safe.' })
  @IsString() email: string;
}
