import { CanActivate, ExecutionContext, HttpStatus, Injectable } from '@nestjs/common';
import { EnvironmentGuard } from './environment.guard';
import { ConsolePrismaService } from '@/core/database/console-prisma.service';
import { ClientResolverService } from '@/common/client-resolver.service';
import { IdentityTokenService } from '@/core/identity-token/identity-token.service';
import { CLIENT_COOKIE, readClientCookie } from '@/common/client-cookie';
import { FapiException } from '@/common/errors/fapi-exception';
import { ErrorCode } from '@/common/errors/error-codes';
import { BackendProxyDetector } from './backend-proxy-detector';

// FAPI Tier B — self-service actions on an already signed-in identity
// (logout-all, verify, change-password, profile update, quota/subscription
// self-read). Extends the merged EnvironmentGuard, then resolves the
// __client cookie (or body-provided clientId/clientToken) via
// ClientResolverService — a duplicate of identities-auth.service.ts's
// resolveClient, per the plan's "duplicate, don't share" decision — and
// attaches req.client.
//
// JUDGMENT CALL (flagged for review before Phase 2 route wiring): this guard
// also best-effort-decodes the __session JWT to attach req.identity when
// present, but does NOT hard-require a valid session or enforce
// resource-ownership here. The plan's guard design says action-level code
// "must check session/resource ownership (e.g. change-password's target ===
// the token's sub)" — that check is meaningfully only enforceable once real
// route handlers exist to define what "the target" even is, which is Phase
// 2 scope (verify/change-password/profile-update are the first real Tier B
// consumers). Making req.identity mandatory now, with no consuming handler,
// would just be an untestable guess. Tightening this to hard-require
// req.identity (and throw if verification fails) should happen as part of
// wiring the first Tier B route in Phase 2, not deferred indefinitely.
@Injectable()
export class SessionGuard extends EnvironmentGuard implements CanActivate {
  constructor(
    console: ConsolePrismaService,
    backendProxyDetector: BackendProxyDetector,
    private clientResolver: ClientResolverService,
    private identityToken: IdentityTokenService,
  ) {
    super(console, backendProxyDetector);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    await super.canActivate(context);

    const request = context.switchToHttp().getRequest();
    const environment = request.environment;

    // Dev-browser path first — mirrors every other Tier A/C route's
    // handling (AuthController.clientBootstrap, AttemptsController). A
    // cross-site dev/staging request can't reliably carry the httpOnly
    // __client cookie at all, so __shipstack_db_jwt (read-only resolved via
    // ClientResolverService.resolveClientViaDevBrowser — no minting here,
    // this is a guard identifying the caller, not bootstrapping state)
    // takes priority when present.
    const devBrowserId = request.query?.__shipstack_db_jwt;
    if (typeof devBrowserId === 'string') {
      const client = await this.clientResolver.resolveClientViaDevBrowser(devBrowserId, environment.id);
      request.client = client;
    } else {
      const cookiePair = readClientCookie(request.cookies?.[CLIENT_COOKIE]);
      const clientId = cookiePair?.clientId ?? request.body?.clientId;
      const clientToken = cookiePair?.clientToken ?? request.body?.clientToken;

      if (!clientId || !clientToken) {
        throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.ClientCredentialsMissing, 'Missing client credentials');
      }

      const client = await this.clientResolver.resolveClient(clientId, clientToken, environment.id);
      request.client = client;
    }

    // Best-effort only — see class-level comment on why this isn't enforced
    // yet.
    const sessionJwt = request.cookies?.['__session'] ?? request.headers['authorization']?.replace(/^Bearer\s+/i, '');
    if (sessionJwt) {
      const identity = await this.identityToken.verifyAccessToken(sessionJwt, environment.id);
      if (identity) request.identity = identity;
    }

    return true;
  }
}
