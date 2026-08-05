import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class PasswordResetRequestDto {
  @ApiProperty({ example: 'jane@example.com', description: 'Silently a no-op for an unknown email — enumeration-safe.' })
  @IsString() email: string;
}
