import { BadRequestException, Controller, Get, Logger, Query, Req } from '@nestjs/common';
import { ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { IdentityTokenService } from '@/core/identity-token/identity-token.service';

// Copied from apps/platform-api/src/common/controllers/well-known.controller.ts.
// Stays fully unguarded — RFC 7517 requires a JWKS endpoint be publicly
// fetchable with no auth of any kind.
@ApiTags('JWKS')
@Controller('.well-known')
export class WellKnownController {
  private readonly logger = new Logger(WellKnownController.name);

  constructor(private readonly identityToken: IdentityTokenService) {}

  @ApiOperation({ summary: 'Fetch the Environment\'s JWKS (RFC 7517)', description: 'Unauthenticated by design — the public keys used to verify FAPI-issued access tokens.' })
  @ApiQuery({ name: 'publishable_key', required: true })
  @ApiResponse({ status: 200, schema: { example: { keys: [{ kty: 'RSA', use: 'sig', alg: 'RS256', kid: 'abc123...' }] } } })
  @ApiResponse({ status: 400, description: 'publishable_key query param is required.' })
  @Get('jwks.json')
  async jwks(@Query('publishable_key') publishableKey: string, @Req() req: Request) {
    this.logger.log(`jwks request: originalUrl=${req.originalUrl} query=${JSON.stringify(req.query)}`);
    if (!publishableKey) throw new BadRequestException('publishable_key query param is required');
    const environmentId = await this.identityToken.resolveEnvironmentId(publishableKey);
    return this.identityToken.getJwks(environmentId);
  }
}
