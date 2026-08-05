import { IsEnum, IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { AuthMethod, RedirectMode } from '@/generated/platform/enums';

export class PrepareFirstFactorDto {
  @ApiProperty({ enum: AuthMethod, example: AuthMethod.EMAIL_CODE })
  @IsEnum(AuthMethod) strategy!: AuthMethod;

  // Transport for external-navigation strategies (OAuth) — see
  // SignInAttempt.redirectMode's own doc comment. Ignored by strategies
  // that never produce an externalRedirectUrl.
  @ApiProperty({ required: false, enum: RedirectMode })
  @IsEnum(RedirectMode) @IsOptional() redirectMode?: RedirectMode;

  // Required (and only meaningful) when redirectMode is POPUP — scopes the
  // popup-closer page's postMessage call, mirrors the legacy
  // OAuthController's own opener_origin query param.
  @ApiProperty({ required: false, description: 'Required when redirectMode is POPUP.' })
  @IsString() @IsOptional() popupOpenerOrigin?: string;
}
