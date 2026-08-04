import { CanActivate, ExecutionContext, HttpStatus, Injectable } from '@nestjs/common';
import { ConsolePrismaService } from '@/core/database/console-prisma.service';
import { resolveSlugFromHost } from '@/common/resolve-slug-from-host';
import { FapiException } from '@/common/errors/fapi-exception';
import { ErrorCode } from '@/common/errors/error-codes';
import { BackendProxyDetector } from './backend-proxy-detector';

// Merges the former Tier A (PublishableKeyGuard) and Tier C
// (PublishableKeyOrSecretGuard) into a single guard. Resolves Environment
// purely from the request's Host header (via resolveSlugFromHost — matches
// Clerk's actual FAPI behavior, confirmed against clerk-js's fapiClient.ts
// and the backend SDK's authenticateContext.ts/handshake.ts: every real
// caller, browser or server, always has a resolvable per-project hostname
// before it ever makes a request). There is no publishableKey-param
// fallback — FAPI has no legitimate caller that lacks a resolvable
// per-project hostname; a caller with only a bare publishableKey (no
// hostname) is exactly the pattern that belongs to apps/bapi's global
// api.clerk.com-equivalent endpoint, not FAPI.
//
// Also detects a backend-proxy caller via BackendProxyDetector (a valid
// secretKey presented via Authorization: Basic) so a downstream handler can
// tell a tenant's own backend-proxy server apart from a direct browser
// caller. secretKey has nothing to do with environment resolution — the
// Host header always handles that regardless of caller type — it's purely
// an additive signal.
@Injectable()
export class EnvironmentGuard implements CanActivate {
  constructor(
    protected console: ConsolePrismaService,
    private backendProxyDetector: BackendProxyDetector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const slug = resolveSlugFromHost(request.headers?.host);

    if (!slug) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.EnvironmentUnresolved, 'Unable to resolve environment from Host header');
    }

    const environment = await this.console.environment.findUnique({ where: { slug } });
    if (!environment || environment.status === 'SUSPENDED') {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.EnvironmentUnresolved, 'Unable to resolve environment from Host header');
    }

    request.environment = environment;
    request.isBackendProxy = await this.backendProxyDetector.detect(request, environment.publishableKey);
    // Single source of truth for "does this request carry a dev-browser
    // pointer" — every route reads req.isDevBrowserRequest instead of each
    // re-deriving it from its own query params. See client-cookie.ts's
    // setClientCookie, whose third argument this flag feeds directly.
    request.isDevBrowserRequest = typeof request.query?.__shipstack_db_jwt === 'string';
    return true;
  }
}
