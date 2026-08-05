import { IsEnum, IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { AuthMethod, RedirectMode } from '@/generated/platform/enums';

export class CreateSignInAttemptDto {
  @ApiProperty({ required: false, example: 'jane@example.com', description: 'Email (or other identifier) being signed in.' })
  @IsString() @IsOptional() identifier?: string;

  @ApiProperty({ required: false, enum: AuthMethod, example: AuthMethod.EMAIL_PASSWORD })
  @IsEnum(AuthMethod) @IsOptional() strategy?: AuthMethod;

  // Present only for EMAIL_PASSWORD's create()-time synchronous shortcut —
  // see AttemptsService.create()'s own handling. Every other strategy
  // ignores this field entirely.
  @ApiProperty({ required: false, description: 'Only used when strategy is EMAIL_PASSWORD.' })
  @IsString() @IsOptional() password?: string;

  @ApiProperty({ required: false, description: 'Where the browser is redirected on completion (OAuth strategies).' })
  @IsString() @IsOptional() redirectUrl?: string;

  @ApiProperty({ required: false })
  @IsString() @IsOptional() actionCompleteRedirectUrl?: string;

  // clientId/clientToken deliberately NOT accepted here — the Client is
  // resolved from the __client cookie (direct mode) or from the backend-
  // proxy caller's own signedClientCookie relay, exactly like
  // AuthController's client/refresh routes. A caller submitting these as
  // body fields would mean the client's rotating secret left the cookie
  // jar at some point, which is the exact bug this DTO used to have.
  // Present only for GOOGLE/MICROSOFT's create()-time synchronous
  // prepare shortcut — see AttemptsService.create()'s own handling. Same
  // fields prepare_first_factor's own DTO carries, since create() now
  // does prepare_first_factor's job inline for OAuth strategies.
  @ApiProperty({ required: false, enum: RedirectMode, description: 'Only used for OAuth strategies (GOOGLE).' })
  @IsEnum(RedirectMode) @IsOptional() redirectMode?: RedirectMode;

  @ApiProperty({ required: false, description: 'Required when redirectMode is POPUP — the opener window\'s origin, for postMessage targeting.' })
  @IsString() @IsOptional() popupOpenerOrigin?: string;
}
