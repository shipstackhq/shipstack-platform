import { IsEnum, IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { AuthMethod, RedirectMode } from '@/generated/platform/enums';

export class CreateSignUpAttemptDto {
  @ApiProperty({ required: false, example: 'jane@example.com' })
  @IsString() @IsOptional() identifier?: string;

  @ApiProperty({ required: false, enum: AuthMethod, example: AuthMethod.EMAIL_PASSWORD })
  @IsEnum(AuthMethod) @IsOptional() strategy?: AuthMethod;

  // Present only for EMAIL_PASSWORD's create()-time synchronous shortcut.
  @ApiProperty({ required: false, description: 'Only used when strategy is EMAIL_PASSWORD.' })
  @IsString() @IsOptional() password?: string;

  @ApiProperty({ required: false, description: 'Only enforced when the Environment requires first/last name.' })
  @IsString() @IsOptional() firstName?: string;

  @ApiProperty({ required: false })
  @IsString() @IsOptional() lastName?: string;

  @ApiProperty({ required: false })
  @IsString() @IsOptional() redirectUrl?: string;

  @ApiProperty({ required: false })
  @IsString() @IsOptional() actionCompleteRedirectUrl?: string;

  // clientId/clientToken deliberately NOT accepted here — see
  // CreateSignInAttemptDto's identical comment.
  // Present only for GOOGLE/MICROSOFT's create()-time synchronous
  // prepare shortcut — see CreateSignInAttemptDto's identical fields.
  @ApiProperty({ required: false, enum: RedirectMode })
  @IsEnum(RedirectMode) @IsOptional() redirectMode?: RedirectMode;

  @ApiProperty({ required: false, description: 'Required when redirectMode is POPUP.' })
  @IsString() @IsOptional() popupOpenerOrigin?: string;
}
