import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyTokenDto {
  @ApiProperty({ description: 'A JWT access token previously issued by this Environment (sign_ins/sign_ups completion, refresh, or sessions/:id/tokens).' })
  @IsString() accessToken: string;
}
