import { Body, Controller, Get, Param, Patch, Post, Query, Req, Res, UseGuards } from '@nestjs/common';
import { ApiBasicAuth, ApiCookieAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { EnvironmentGuard } from '@/common/guards/environment.guard';
import { resolveClientFromRequest, setClientCookie, signClientCookie } from '@/common/client-cookie';
import { ApiCodedErrorResponse, FlatErrorEnvelope } from '@/common/swagger/error-envelopes';
import { AuthService } from '@/modules/auth/auth.service';
import { SignUpAttemptsService } from './sign-up-attempts.service';
import { CreateSignUpAttemptDto } from './dto/create-sign-up-attempt.dto';
import { UpdateSignUpAttemptDto } from './dto/update-sign-up-attempt.dto';
import { PrepareFirstFactorDto } from './dto/prepare-first-factor.dto';
import { AttemptFirstFactorDto } from './dto/attempt-first-factor.dto';

// Mirrors AttemptsController's shape for SignInAttempt — see
// docs/unified-attempt-architecture.md and AttemptsController's own
// class-level comment for the full rationale (dev-browser / cookie /
// backend-proxy relay, never a request body field or query string).
@ApiTags('Sign-up attempts')
@ApiCookieAuth('directModeCookie')
@ApiBasicAuth('backendProxyBasicAuth')
@Controller('auth/client/sign_ups')
@UseGuards(EnvironmentGuard)
export class SignUpAttemptsController {
  constructor(
    private service: SignUpAttemptsService,
    private auth: AuthService,
  ) {}

  private relayClient(req: Request, res: Response, clientId: string, clientToken: string) {
    if ((req as any).isBackendProxy) {
      return { signedClientCookie: signClientCookie(clientId, clientToken) };
    }
    setClientCookie(res, clientId, clientToken, false);
    return {};
  }

  @ApiOperation({
    summary: 'Start a sign-up attempt',
    description:
      'For EMAIL_PASSWORD, resolves synchronously in the same call — status COMPLETE unless requireEmailVerification is on, ' +
      'in which case the identity is created unverified and a verification email is sent automatically (see resend-verification for the retry case). ' +
      'A duplicate email is never an HTTP error, only a FAILED verificationStatus.',
  })
  @ApiResponse({ status: 201 })
  @ApiCodedErrorResponse(403, 'EMAIL_PASSWORD is disabled for this environment (auth_method_disabled).')
  @Post()
  async create(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Body() dto: CreateSignUpAttemptDto,
    @Query('__shipstack_db_jwt') devBrowserId: string | undefined,
  ) {
    const environment = (req as any).environment;

    if (devBrowserId) {
      const bootstrapped = await this.auth.clientBootstrapViaDevBrowser(devBrowserId, environment.id);
      const { attempt, clientUat } = await this.service.create(environment.id, {
        identifier: dto.identifier,
        strategy: dto.strategy,
        password: dto.password,
        firstName: dto.firstName,
        lastName: dto.lastName,
        redirectUrl: dto.redirectUrl,
        actionCompleteRedirectUrl: dto.actionCompleteRedirectUrl,
        clientId: bootstrapped.clientId,
        clientToken: bootstrapped.clientToken,
        redirectMode: dto.redirectMode,
        popupOpenerOrigin: dto.popupOpenerOrigin,
      });
      return { ...attempt, clientUat, devMode: true };
    }

    const fromClient = resolveClientFromRequest(req);
    const { attempt, clientToken: rotatedToken, clientUat } = await this.service.create(environment.id, {
      identifier: dto.identifier,
      strategy: dto.strategy,
      password: dto.password,
      firstName: dto.firstName,
      lastName: dto.lastName,
      redirectUrl: dto.redirectUrl,
      actionCompleteRedirectUrl: dto.actionCompleteRedirectUrl,
      clientId: fromClient?.clientId,
      clientToken: fromClient?.clientToken,
      redirectMode: dto.redirectMode,
      popupOpenerOrigin: dto.popupOpenerOrigin,
    });
    const relayed = this.relayClient(req, res, attempt.clientId!, rotatedToken);
    return { ...attempt, clientUat, ...relayed };
  }

  @ApiOperation({
    summary: 'Reload a sign-up attempt',
    description: 'Poll/reload an attempt by id — once status is COMPLETE, returns a real accessToken. Also relays the (possibly rotated) client via cookie or signedClientCookie.',
  })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 400, type: FlatErrorEnvelope, description: 'The attempt is COMPLETE but no client (cookie or x-shipstack-client header) was resolvable to reload it with.' })
  @ApiResponse({ status: 404, type: FlatErrorEnvelope, description: 'Unknown attempt id, or it belongs to a different environment.' })
  @Get(':id')
  async get(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Param('id') id: string,
    @Query('__shipstack_db_jwt') devBrowserId: string | undefined,
  ) {
    const environment = (req as any).environment;

    if (devBrowserId) {
      const bootstrapped = await this.auth.clientBootstrapViaDevBrowser(devBrowserId, environment.id);
      const { attempt, accessToken, clientUat, sessions, activeSessionId } = await this.service.reload(id, environment.id, bootstrapped.clientToken);
      return { ...attempt, accessToken, clientUat, sessions, activeSessionId, devMode: true };
    }

    const fromClient = resolveClientFromRequest(req);
    const { attempt, accessToken, clientToken: rotatedToken, clientUat, sessions, activeSessionId } = await this.service.reload(id, environment.id, fromClient?.clientToken);
    const relayed = rotatedToken ? this.relayClient(req, res, attempt.clientId!, rotatedToken) : {};
    return { ...attempt, accessToken, clientUat, sessions, activeSessionId, ...relayed };
  }

  @ApiOperation({ summary: 'Correct/fill in fields on an in-progress sign-up attempt', description: 'Narrow by design — only identifier/firstName/lastName. Status/strategy/verification fields cannot be set this way.' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 404, type: FlatErrorEnvelope })
  @Patch(':id')
  async update(@Req() req: Request, @Param('id') id: string, @Body() dto: UpdateSignUpAttemptDto) {
    const environment = (req as any).environment;
    return this.service.update(id, environment.id, { identifier: dto.identifier, firstName: dto.firstName, lastName: dto.lastName });
  }

  @ApiOperation({ summary: 'Prepare sign-up verification (send OTP / build OAuth redirect URL)' })
  @ApiResponse({ status: 201 })
  @ApiCodedErrorResponse(403, 'This strategy is disabled for this environment (auth_method_disabled).')
  @ApiResponse({ status: 404, type: FlatErrorEnvelope })
  @Post(':id/prepare_verification')
  async prepareVerification(@Req() req: Request, @Param('id') id: string, @Body() dto: PrepareFirstFactorDto) {
    const environment = (req as any).environment;
    return this.service.prepareVerification(id, environment.id, dto.strategy, dto.redirectMode, dto.popupOpenerOrigin);
  }

  @ApiOperation({
    summary: 'Attempt sign-up verification (verify OTP code / complete OAuth)',
    description: 'A wrong code returns 201 with a FAILED/still-pending verificationStatus, not an HTTP error — see the class comment on AttemptOutcome.',
  })
  @ApiResponse({ status: 201 })
  @ApiCodedErrorResponse(403, 'This strategy is disabled for this environment (auth_method_disabled).')
  @ApiResponse({ status: 404, type: FlatErrorEnvelope })
  @Post(':id/attempt_verification')
  async attemptVerification(@Req() req: Request, @Param('id') id: string, @Body() dto: AttemptFirstFactorDto) {
    const environment = (req as any).environment;
    return this.service.attemptVerification(id, environment.id, dto.input ?? {});
  }
}
