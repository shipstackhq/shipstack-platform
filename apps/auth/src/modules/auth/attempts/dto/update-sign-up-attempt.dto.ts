import { IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

// PATCH /auth/client/sign_ups/:id — lets a caller fill in/correct fields on
// an in-progress attempt. Deliberately narrow — see
// SignUpAttemptsService.update()'s own doc comment for why status/strategy/
// verification fields are excluded.
export class UpdateSignUpAttemptDto {
  @ApiProperty({ required: false })
  @IsString() @IsOptional() identifier?: string;

  @ApiProperty({ required: false })
  @IsString() @IsOptional() firstName?: string;

  @ApiProperty({ required: false })
  @IsString() @IsOptional() lastName?: string;
}
