import { Pool } from 'pg';

// Same rationale as fixtures.ts for using raw pg instead of fapi's own
// generated Prisma clients — this one's on the PLATFORM side though, where
// fapi's client CAN write (platform is fapi's own schema). Using raw pg
// here too anyway, for one reason: deleting identities/clients by
// environmentId cascades to sessions/identity_providers/reset_tokens/etc
// via the schema's own ON DELETE CASCADE (see bapi's init migration), but
// sign_in_attempts/sign_up_attempts/dev_browsers have no FK relationship to
// identities/clients at all and need their own explicit delete — a plain
// SQL cleanup is simplest to keep all of that in one place rather than
// spreading it across fapi's PlatformPrismaService model-by-model.
let pool: Pool | null = null;
function getPool(): Pool {
  if (!pool) {
    pool = new Pool({ connectionString: process.env.PLATFORM_DATABASE_URL, max: 5 });
  }
  return pool;
}

export async function closeCleanupPool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

// Wipes every platform-schema row created by tests against one environment.
// identities/clients deletes cascade to sessions/identity_providers/
// reset_tokens/verification_tokens/quota_entities/quota_usage/credits;
// sign_in_attempts/sign_up_attempts/dev_browsers are deleted explicitly
// since nothing cascades into them.
export async function cleanPlatformData(environmentId: string): Promise<void> {
  const db = getPool();
  await db.query('DELETE FROM platform.sign_in_attempts WHERE environment_id = $1', [environmentId]);
  await db.query('DELETE FROM platform.sign_up_attempts WHERE environment_id = $1', [environmentId]);
  await db.query('DELETE FROM platform.dev_browsers WHERE environment_id = $1', [environmentId]);
  await db.query('DELETE FROM platform.clients WHERE environment_id = $1', [environmentId]);
  await db.query('DELETE FROM platform.identities WHERE environment_id = $1', [environmentId]);
}

// No API route in scope suspends an identity directly (that's a bapi/
// admin-surface operation), so tests that need a SUSPENDED identity go
// straight to the DB — same raw-pg rationale as the rest of this file.
export async function suspendIdentity(environmentId: string, email: string): Promise<void> {
  const db = getPool();
  await db.query(
    "UPDATE platform.identities SET status = 'SUSPENDED' WHERE environment_id = $1 AND email = $2",
    [environmentId, email.toLowerCase().trim()],
  );
}

// TTL/expiry boundary testing needs a session whose expiresAt is already in
// the past WITHOUT actually sleeping past a real TTL (accessTokenTtl/
// refreshTokenTtl are seeded in whole seconds — sleeping 1-2s per test would
// make the suite slow and flaky under load). Same rationale as
// suspendIdentity: no API route backdates a session, so this goes straight
// to the DB. Sets status back to ACTIVE explicitly (defensive — callers
// always mint a fresh session first) so the only variable under test is
// expiresAt, not status.
export async function expireSession(sessionId: string): Promise<void> {
  const db = getPool();
  await db.query(
    "UPDATE platform.sessions SET status = 'ACTIVE', expires_at = now() - interval '1 hour' WHERE id = $1",
    [sessionId],
  );
}
