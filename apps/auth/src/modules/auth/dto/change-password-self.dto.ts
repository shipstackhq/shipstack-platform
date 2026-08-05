import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

// Deliberately does NOT include a shipstackId/identity field — the target
// identity is always derived from the verified session (req.identity.sub
// via SessionGuard), never trusted from the body. See auth.controller.ts's
// `me/password` PATCH handler and auth.service.ts's changePasswordSelf().
export class ChangePasswordSelfDto {
  @ApiProperty() @IsString() currentPassword: string;
  @ApiProperty() @IsString() newPassword: string;
}
