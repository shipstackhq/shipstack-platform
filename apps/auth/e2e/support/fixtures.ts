import { Pool } from 'pg';
import { generateKeyPairSync, randomBytes } from 'crypto';
import * as argon2 from 'argon2';
import { EncryptionService } from '../../src/core/encryption/encryption.service';

// Raw pg client, deliberately NOT fapi's own generated console Prisma
// client — that client has no write methods for console-schema models at
// all (workspaces/projects/environments aren't modeled as writable there;
// see console.prisma's own header comment on the read-only boundary). This
// is the one place e2e fixtures are allowed to reach around that boundary,
// scoped to test-only setup, never used by application code.
let pool: Pool | null = null;
function getPool(): Pool {
  if (!pool) {
    pool = new Pool({ connectionString: process.env.CONSOLE_DATABASE_URL, max: 5 });
  }
  return pool;
}

export async function closeFixturePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

function id(): string {
  return randomBytes(16).toString('hex');
}

export interface SeededEnvironment {
  workspaceId: string;
  projectId: string;
  environmentId: string;
  publishableKey: string;
  secretKey: string;
  slug: string;
}

// Full Workspace -> Project -> Environment chain a real Environment row
// requires (see console-api's schema.prisma for the FK chain) plus a real
// RSA keypair, encrypted the exact same way IdentityTokenService will
// decrypt it at request time (same EncryptionService class, same
// ENCRYPTION_KEY from e2e/.env.test) — so tokens signed against a seeded
// environment actually verify.
//
// secret_key stores an ARGON2ID HASH of secretKey, not the plaintext —
// confirmed against BackendProxyDetector.detect(), which argon2.verify()s
// Basic-auth credentials directly against this column. secret_key_encrypted
// is a SEPARATE, AES-256-GCM-decryptable copy (console-api's own
// reveal-in-dashboard mechanism) — the two columns hold the same secret in
// two different, non-interchangeable forms; using the wrong one where the
// other is expected fails in a way that looks like an app bug rather than
// a fixture bug (found by running POST /auth/verify against this fixture
// and getting a 500 from argon2.verify() on a non-PHC-formatted string).
export async function seedEnvironment(overrides: Partial<{ slug: string; type: 'DEVELOPMENT' | 'PRODUCTION'; requireEmailVerification: boolean; accessTokenTtl: number; refreshTokenTtl: number }> = {}): Promise<SeededEnvironment> {
  const db = getPool();
  const encryption = new EncryptionService();

  const workspaceId = id();
  const projectId = id();
  const environmentId = id();
  const slug = overrides.slug ?? `e2e-${id().slice(0, 12)}`;
  // Encoded the same way console-api encodes real keys (slug + hosted domain,
  // base64url), so the callback can recover the tenant domain from the key.
  const publishableKey = `pk_test_${Buffer.from(`${slug}.stack.shipstack.development`).toString("base64url")}`;
  const secretKey = `sk_test_${id()}`;
  const secretKeyHash = await argon2.hash(secretKey);
  const secretKeyEncrypted = encryption.encrypt(secretKey);

  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const jwtPrivateKeyEncrypted = encryption.encrypt(privateKey);

  await db.query('INSERT INTO console.workspaces (id, name, slug, is_default, updated_at) VALUES ($1, $2, $3, false, now())', [
    workspaceId, `E2E Workspace ${workspaceId.slice(0, 8)}`, `e2e-ws-${workspaceId.slice(0, 12)}`,
  ]);

  await db.query('INSERT INTO console.projects (id, workspace_id, mode) VALUES ($1, $2, $3)', [
    projectId, workspaceId, 'B2C',
  ]);

  await db.query(
    `INSERT INTO console.environments (
      id, project_id, name, type, slug, publishable_key, secret_key, secret_key_encrypted,
      jwt_public_key, jwt_private_key, access_token_ttl, refresh_token_ttl,
      require_email_verification, min_password_length, password_requirements,
      collect_first_last_name, require_first_last_name, allow_self_deletion,
      prevent_leaked_passwords, status, allowed_origins
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
    [
      environmentId, projectId, 'E2E Environment', overrides.type ?? 'DEVELOPMENT', slug,
      publishableKey, secretKeyHash, secretKeyEncrypted,
      publicKey, jwtPrivateKeyEncrypted, overrides.accessTokenTtl ?? 900, overrides.refreshTokenTtl ?? 604800,
      overrides.requireEmailVerification ?? false, 8, 'letters_digits',
      false, false, true,
      false, 'ACTIVE', [],
    ],
  );

  return { workspaceId, projectId, environmentId, publishableKey, secretKey, slug };
}

// Full teardown for one seeded environment — deletes bottom-up
// (identities/sessions/etc first isn't needed here since Environment has no
// ON DELETE CASCADE from platform-schema tables back to console; platform
// rows are cleaned separately, see cleanPlatformData). Deleting the
// workspace cascades to project/environment via their own FKs.
export async function deleteEnvironment(env: SeededEnvironment): Promise<void> {
  const db = getPool();
  await db.query('DELETE FROM console.workspaces WHERE id = $1', [env.workspaceId]);
}

// Inserts (or upserts) an AuthMethodConfig row for the given environment —
// e2e's own equivalent of console-api's auth-methods.service.ts setEnabled.
// No fixture previously inserted ANY AuthMethodConfig row, which is exactly
// why the default-enabled behavior (EnvironmentService.isEnabled, `?? true`
// for a missing row) matters: every pre-existing e2e test relies on
// EMAIL_PASSWORD/EMAIL_CODE working with zero rows seeded. Use this only to
// test the disabled path explicitly.
export async function seedAuthMethodConfig(
  environmentId: string,
  method: 'EMAIL_PASSWORD' | 'MAGIC_LINK' | 'EMAIL_CODE' | 'PASSKEY' | 'GOOGLE' | 'GITHUB' | 'APPLE' | 'MICROSOFT',
  enabled: boolean,
): Promise<void> {
  const db = getPool();
  await db.query(
    `INSERT INTO console.auth_method_configs (id, environment_id, method, enabled)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (environment_id, method) DO UPDATE SET enabled = EXCLUDED.enabled`,
    [id(), environmentId, method, enabled],
  );
}
