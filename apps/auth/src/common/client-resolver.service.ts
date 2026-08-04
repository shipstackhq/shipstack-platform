import { HttpStatus, Injectable } from '@nestjs/common';
import { createHash } from 'crypto';
import { PlatformPrismaService } from '@/core/database/platform-prisma.service';
import { FapiException } from '@/common/errors/fapi-exception';
import { ErrorCode } from '@/common/errors/error-codes';

// Duplicated (deliberately, not imported) from
// apps/platform-api/src/modules/identities/identities-auth.service.ts's
// private hashToken/resolveClient/detectReplay methods. Per the migration
// plan (atomic-napping-crescent.md, "Decisions made"), Client/Session
// lifecycle logic is duplicated into apps/fapi rather than extracted into a
// shared package — apps/fapi and apps/platform-api are separate deployables
// with no cross-app imports by design (that boundary is itself part of the
// BAPI/FAPI security model). If platform-api's resolveClient logic changes,
// this copy must be updated in lockstep until the eventual Go-port
// extraction (out of scope for this migration).
@Injectable()
export class ClientResolverService {
  constructor(private platform: PlatformPrismaService) {}

  hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  // Rotating-token reuse (a token hash that no longer matches the stored
  // hash) is treated as theft/replay: the Client and all of its Sessions are
  // revoked outright rather than just rejecting the one request.
  private async detectReplay(clientId: string): Promise<void> {
    await this.platform.client.update({
      where: { id: clientId },
      data: { revokedAt: new Date() },
    });
    await this.platform.session.updateMany({
      where: { clientId },
      data: { status: 'REVOKED' },
    });
  }

  async resolveClient(clientId: string, clientToken: string, environmentId?: string) {
    const client = await this.platform.client.findUnique({ where: { id: clientId } });
    if (!client) throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.ClientInvalid, 'Invalid client');
    if (client.revokedAt) throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.ClientRevoked, 'Client revoked');
    if (client.expiresAt < new Date()) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.ClientExpired, 'Client expired');
    }
    if (environmentId && client.environmentId !== environmentId) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.ClientInvalid, 'Invalid client');
    }

    const hashMatches = this.hashToken(clientToken) === client.rotatingTokenHash;
    if (!hashMatches) {
      await this.detectReplay(client.id);
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.ClientTokenReuseDetected, 'Token reuse detected');
    }
    return client;
  }

  // Read-only dev-browser resolution for guards — deliberately NOT the same
  // as AuthService.clientBootstrapViaDevBrowser, which mints/rotates. This
  // just looks up the DevBrowser row's already-bound Client, the same way
  // resolveClient() looks up an already-known clientId/clientToken pair —
  // no minting, no rotation, no side effects. A guard's job is to identify
  // the caller, not to bootstrap state; routes that need to mint (POST/PUT
  // /auth/client) already do that themselves via AuthService.
  async resolveClientViaDevBrowser(devBrowserId: string, environmentId: string) {
    const devBrowser = await this.platform.devBrowser.findUnique({ where: { id: devBrowserId } });
    if (!devBrowser || devBrowser.environmentId !== environmentId || devBrowser.expiresAt < new Date()) {
      throw new FapiException(
        HttpStatus.UNAUTHORIZED,
        ErrorCode.DevBrowserInvalidOrExpired,
        'Invalid or expired dev-browser token',
      );
    }
    if (!devBrowser.clientId) {
      throw new FapiException(
        HttpStatus.UNAUTHORIZED,
        ErrorCode.DevBrowserInvalidOrExpired,
        'Dev-browser has no bound client yet',
      );
    }
    const client = await this.platform.client.findUnique({ where: { id: devBrowser.clientId } });
    if (!client || client.revokedAt || client.expiresAt < new Date() || client.environmentId !== environmentId) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.ClientInvalid, 'Invalid client');
    }
    return client;
  }
}
