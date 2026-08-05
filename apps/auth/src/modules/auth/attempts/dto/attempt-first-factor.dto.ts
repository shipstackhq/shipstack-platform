import { IsObject, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class AttemptFirstFactorDto {
  // Strategy-owned shape (e.g. { code: "123456" } for EmailCode) — the
  // generic route/service never interprets this, only the resolved
  // SignInStrategy's own attempt() does.
  @ApiProperty({
    required: false,
    description: 'Strategy-specific verification payload. EMAIL_CODE expects { "code": "123456" }; EMAIL_PASSWORD expects { "password": "..." }.',
    example: { code: '123456' },
  })
  @IsObject() @IsOptional() input?: Record<string, unknown>;
}
