import { Injectable } from '@nestjs/common';
import { createHash, createPublicKey } from 'crypto';
import { sign, verify } from 'jsonwebtoken';
import { ConsolePrismaService } from '@/core/database/console-prisma.service';
import { EncryptionService } from '@/core/encryption/encryption.service';

export interface IdentityTokenPayload {
  sub: string;
  iss: string;
  sid: string;
  sts: string;
  csx: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  avatar?: string;
}

interface KeyPair {
  privateKey: string;
  publicKey: string;
  kid: string;
}

const MAX_CACHE_SIZE = 1000;

// Full sign+verify counterpart to apps/platform-api/src/core/identity-token/
// identity-token.service.ts, duplicated per the migration plan's "duplicate
// now, don't extract" decision.
//
// Supersedes Phase 0's verify-only SessionTokenService: Phase 1 moved
// register/login/refresh/client-bootstrap onto FAPI, and issueTokens (in
// auth.service.ts) needs to mint __session access tokens itself now — a
// verify-only service can no longer cover FAPI's needs. This requires
// EncryptionService (to decrypt Environment.jwtPrivateKey), which the
// verify-only version didn't need since it never signs. SessionGuard now
// depends on this service directly (see common/guards/session.guard.ts);
// the old verify-only service has been removed.
@Injectable()
export class IdentityTokenService {
  // LRU cache: environmentId → KeyPair
  private cache = new Map<string, KeyPair>();

  constructor(
    private console: ConsolePrismaService,
    private encryption: EncryptionService,
  ) {}

  private evictIfFull() {
    if (this.cache.size >= MAX_CACHE_SIZE) {
      // Map preserves insertion order — delete the oldest entry
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
  }

  private async getKeyPair(environmentId: string): Promise<KeyPair> {
    const cached = this.cache.get(environmentId);
    if (cached) {
      // Move to end (most recently used)
      this.cache.delete(environmentId);
      this.cache.set(environmentId, cached);
      return cached;
    }

    const env = await this.console.environment.findUnique({
      where: { id: environmentId },
      select: { jwtPublicKey: true, jwtPrivateKey: true },
    });

    if (!env) throw new Error(`Environment ${environmentId} not found`);
    if (env.jwtPublicKey === 'PENDING') {
      throw new Error(`Environment ${environmentId} has no JWT key pair — it was created before key pair support. Re-create the environment or run the backfill migration.`);
    }

    const privateKey = this.encryption.decrypt(env.jwtPrivateKey);
    const publicKey = env.jwtPublicKey;
    const kid = createHash('sha256').update(publicKey).digest('hex').slice(0, 16);

    const pair: KeyPair = { privateKey, publicKey, kid };
    this.evictIfFull();
    this.cache.set(environmentId, pair);
    return pair;
  }

  async signAccessToken(
    identityId: string,
    publishableKey: string,
    accessTokenTtl: number,
    profile: { email?: string | null; firstName?: string | null; lastName?: string | null; avatar?: string | null } | undefined,
    environmentId: string | undefined,
    sessionId: string,
    sessionStatus: string,
    cookieSuffix: string,
  ): Promise<string> {
    // Resolve environmentId from publishableKey if not provided
    const envId = environmentId ?? await this.resolveEnvironmentId(publishableKey);
    const { privateKey, kid } = await this.getKeyPair(envId);

    return sign(
      {
        sub: identityId,
        iss: publishableKey,
        sid: sessionId,
        sts: sessionStatus.toLowerCase(),
        csx: cookieSuffix,
        ...(profile?.email && { email: profile.email }),
        ...(profile?.firstName && { firstName: profile.firstName }),
        ...(profile?.lastName && { lastName: profile.lastName }),
        ...(profile?.avatar && { avatar: profile.avatar }),
      },
      privateKey,
      { algorithm: 'RS256', expiresIn: accessTokenTtl, keyid: kid },
    );
  }

  // Dev-browser token — a separate payload shape ({ dev: <DevBrowser.id> }),
  // not an identity/session token, so it doesn't go through
  // signAccessToken's identity-specific signature. Reuses the same
  // per-environment RS256 keypair as every other FAPI-issued JWT rather
  // than a standalone HS256 secret, keeping one signing/rotation story
  // instead of two. Mirrors Clerk's own __clerk_db_jwt shape
  // ({"dev":"dvb_..."}) confirmed by decoding a real Clerk token.
  async signDevBrowserToken(devBrowserId: string, environmentId: string): Promise<string> {
    const { privateKey, kid } = await this.getKeyPair(environmentId);
    return sign({ dev: devBrowserId }, privateKey, { algorithm: 'RS256', keyid: kid });
  }

  // Handshake payload — a signed envelope carrying literal Set-Cookie header
  // value strings, not a session/identity claim. A cross-site caller (direct
  // mode, dev/staging) can't have FAPI's own Set-Cookie response headers
  // land on the app's origin directly, so instead FAPI signs the directives
  // and hands them back via redirect for the app's own same-site response to
  // replay. Payload key name ("handshake") and the fact that it carries full
  // Set-Cookie strings (not separate name/value fields) both confirmed by
  // decoding a real Clerk __clerk_handshake token. Short-lived by design —
  // expiresIn is deliberately tight since this is consumed once, immediately,
  // in the same round trip that minted it.
  async signHandshakePayload(directives: string[], environmentId: string): Promise<string> {
    const { privateKey, kid } = await this.getKeyPair(environmentId);
    return sign({ handshake: directives }, privateKey, { algorithm: 'RS256', keyid: kid, expiresIn: 60 });
  }

  async verifyAccessToken(token: string, environmentId: string): Promise<IdentityTokenPayload | null> {
    try {
      const { publicKey } = await this.getKeyPair(environmentId);
      return verify(token, publicKey, { algorithms: ['RS256'] }) as IdentityTokenPayload;
    } catch {
      return null;
    }
  }

  async getJwks(environmentId: string) {
    const { publicKey, kid } = await this.getKeyPair(environmentId);
    const keyObj = createPublicKey(publicKey);
    const jwk = keyObj.export({ format: 'jwk' });
    return {
      keys: [{ ...jwk, use: 'sig', alg: 'RS256', kid }],
    };
  }

  async resolveEnvironmentId(publishableKey: string): Promise<string> {
    const env = await this.console.environment.findUnique({
      where: { publishableKey },
      select: { id: true },
    });
    if (!env) throw new Error(`No environment found for publishable key`);
    return env.id;
  }
}
