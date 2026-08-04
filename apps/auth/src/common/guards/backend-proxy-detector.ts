import { HttpStatus, Injectable } from '@nestjs/common';
import { ConsolePrismaService } from '@/core/database/console-prisma.service';
import { FapiException } from '@/common/errors/fapi-exception';
import { ErrorCode } from '@/common/errors/error-codes';
import * as argon2 from 'argon2';

// Shared by every guard that needs to distinguish a backend-proxy caller
// from a direct browser caller — EnvironmentGuard uses this so a request
// is never REQUIRED to present a secretKey to pass, but a downstream
// handler can still tell them apart when one is presented. See
// docs/sdk-rebuild-v2.md's backend-proxy-mode design notes for why this
// matters: sign_ins/sign_ups need to know whether the caller is a
// tenant's own backend server (which needs a signed __client cookie
// relayed back, see client-cookie.ts's signClientCookie) or a direct
// browser call (which never does).
//
// SANCTIONED secretKey READ (plan Section 4): FAPI's generated console Prisma
// client has secretKey removed from the schema entirely, so this must use
// a scoped raw query against the console schema's environments table.
//
// Deliberately NOT cached yet — every call here re-runs a real
// argon2.verify (measured ~35ms on this codebase's actual argon2id
// params, m=65536/t=3/p=4). That cost is real and worth addressing before
// this is wired into high-frequency routes (sign_ins/attempt_first_factor
// etc.), but the caching design (outcome-cache keyed on a fast hash of
// publishableKey:secretKey, never the raw secret, argon2 remains the only
// thing that ever validates against the DB) is intentionally deferred —
// this extraction is additive/unimplemented-cache for now, so the
// separation of concerns lands first and the perf fix lands as its own
// reviewable change.
@Injectable()
export class BackendProxyDetector {
  constructor(private console: ConsolePrismaService) {}

  private async fetchSecretKey(publishableKey: string): Promise<{ id: string; secretKey: string } | null> {
    const rows = await this.console.$queryRaw<Array<{ id: string; secret_key: string }>>`
      SELECT id, secret_key FROM console.environments WHERE publishable_key = ${publishableKey} LIMIT 1
    `;
    if (!rows[0]) return null;
    return { id: rows[0].id, secretKey: rows[0].secret_key };
  }

  /**
   * Parses `Authorization: Basic <publishableKey>:<secretKey>` off the
   * request, if present, and verifies it against the resolved
   * environment's real argon2id secretKey hash. Returns the decoded
   * secretKey only on success. Returns null (never throws) when no Basic
   * header is present at all — that's the expected, ordinary case for a
   * direct-mode browser caller, not an error. Throws only when a Basic
   * header IS present but doesn't verify — a caller that attempted
   * backend-proxy auth and got it wrong should fail loudly, not silently
   * fall back to being treated as direct mode.
   */
  async detect(request: any, resolvedPublishableKey: string): Promise<boolean> {
    const authHeader = request.headers?.['authorization'];
    if (!authHeader?.startsWith('Basic ')) return false;

    const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf-8');
    const [, secretKey] = decoded.split(':');
    if (!secretKey) return false;

    const secretRow = await this.fetchSecretKey(resolvedPublishableKey);
    if (!secretRow) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.InvalidCredentials, 'Invalid credentials');
    }
    const valid = await argon2.verify(secretRow.secretKey, secretKey);
    if (!valid) {
      throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.InvalidCredentials, 'Invalid credentials');
    }
    return true;
  }
}
