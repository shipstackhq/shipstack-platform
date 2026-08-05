import { IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

// Deliberately does NOT include shipstackId/email/credential fields — the
// target identity is always derived from the verified session
// (req.identity.sub), never trusted from the body. See auth.controller.ts's
// `me` PATCH handler and auth.service.ts's updateMe().
export class UpdateMeDto {
  @ApiProperty({ required: false })
  @IsString() @IsOptional() firstName?: string;
  @ApiProperty({ required: false })
  @IsString() @IsOptional() lastName?: string;
  @ApiProperty({ required: false })
  @IsString() @IsOptional() avatar?: string;
}
