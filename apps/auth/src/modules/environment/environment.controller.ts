import { Controller, Get, Header, Req, UseGuards } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { EnvironmentService } from './environment.service';
import { EnvironmentGuard } from '@/common/guards/environment.guard';

// Was `config` (formerly `projects/config` on platform-api). Renamed to
// `environment` per docs/environment-resource-task.md, mirroring Clerk's
// single GET /v1/environment — one resource both client SDKs and FAPI's
// own enforcement code read, instead of config/getEnvConfig being two
// independently-queried paths. Still guarded declaratively by
// EnvironmentGuard, no behavior change there.
@ApiTags('Environment')
@Controller('environment')
export class EnvironmentController {
  constructor(private readonly service: EnvironmentService) {}

  @ApiOperation({
    summary: 'Read per-project auth/policy config',
    description:
      'The one resource both client SDKs and FAPI\'s own enforcement code read — discovery and enforcement never drift apart. ' +
      'Only emailPassword/google are ever surfaced under authMethods (MICROSOFT is hard-disabled and never listed; EMAIL_CODE works but isn\'t part of discovery). ' +
      'Session-minting internals (accessTokenTtl/refreshTokenTtl) are deliberately NOT included — internal-only, see getConfig() vs getPublicResource().',
  })
  @ApiResponse({
    status: 200,
    schema: {
      example: {
        authMethods: { emailPassword: true, google: true },
        password: { minLength: 8, requirements: 'letters_digits', preventLeakedPasswords: false, minPasswordStrength: null },
        requireEmailVerification: false,
        nameFields: { collect: false, required: false },
        allowSelfDeletion: true,
      },
    },
  })
  @Get()
  @UseGuards(EnvironmentGuard)
  @Header('Cache-Control', 'no-store')
  getEnvironment(@Req() req: Request) {
    // req.environment is attached by EnvironmentGuard, resolved from the
    // Host header.
    return this.service.getPublicResource((req as any).environment.id);
  }
}
