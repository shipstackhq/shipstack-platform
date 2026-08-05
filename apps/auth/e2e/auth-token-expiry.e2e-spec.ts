import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { createTestApp } from './support/app';
import { seedEnvironment, deleteEnvironment, closeFixturePool, SeededEnvironment } from './support/fixtures';
import { cleanPlatformData, closeCleanupPool, expireSession } from './support/cleanup';
import { uniqueEmail } from './support/email';

// Token TTL / expiry boundary conditions — two independent expiry clocks
// exist in this system and neither was previously covered end to end:
//
// 1. The access token's own JWT `exp` claim (IdentityTokenService.
//    signAccessToken's `expiresIn: accessTokenTtl`) — verified statelessly
//    by POST /auth/verify against the issuer's public key, no DB lookup.
// 2. The Session row's own `expiresAt` column (AuthService.issueTokens:
//    `new Date(Date.now() + sessionTtl * 1000)`, sessionTtl = the
//    Environment's refreshTokenTtl) — checked independently by
//    buildSessionSummary (status downgrades to 'EXPIRED'), refreshSession
//    (degrades to an empty/no-active-session response), and
//    mintSessionToken (hard-rejects with session_not_active).
//
// These two clocks are NOT the same thing and can desync: a session can
// still be within its refreshTokenTtl window while its last-minted access
// token has already expired (normal — that's what refresh/mint-token are
// for), or a session can be fully expired while an already-issued access
// token's shorter TTL hasn't run out yet. Both boundaries are exercised
// here independently rather than assuming one implies the other.
//
// accessTokenTtl is seeded at 3 seconds for the JWT-expiry tests so the
// suite can wait past a REAL expiry rather than mocking the clock (jwt.sign's
// expiresIn/jwt.verify have no injectable clock in this codebase). Kept short
// but not razor-thin (a 1s TTL proved flaky under full-suite load — sign-up
// + reload + verify sometimes didn't complete inside the window), and only
// in the two tests that need it, to keep runtime reasonable. Session-level
// expiry tests use expireSession() to backdate expires_at directly instead
// of sleeping past the (much longer) real refreshTokenTtl.
describe('token TTL / expiry boundaries (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await createTestApp();
  });

  afterAll(async () => {
    await app.close();
    await closeFixturePool();
    await closeCleanupPool();
  });

  const password = 'correct horse battery staple 1';

  async function signUpAndGetSession(
    env: SeededEnvironment,
    email: string,
  ): Promise<{ agent: ReturnType<typeof request.agent>; sessionId: string; accessToken: string }> {
    const host = `${env.slug}.stack.shipstack.development`;
    const agent = request.agent(app.getHttpServer());
    const signUp = await agent
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', host)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
    const reloaded = await agent
      .get(`/api/v1/auth/client/sign_ups/${signUp.body.id}`)
      .set('Host', host);
    const verified = await request(app.getHttpServer())
      .post('/api/v1/auth/verify')
      .set('Host', host)
      .auth(env.publishableKey, env.secretKey)
      .send({ accessToken: reloaded.body.accessToken });
    return { agent, sessionId: verified.body.sessionId, accessToken: reloaded.body.accessToken };
  }

  describe('access token JWT expiry (POST /auth/verify)', () => {
    let env: SeededEnvironment;
    beforeEach(async () => {
      env = await seedEnvironment({ accessTokenTtl: 3 });
    });
    afterEach(async () => {
      await cleanPlatformData(env.environmentId);
      await deleteEnvironment(env);
    });
    const host = () => `${env.slug}.stack.shipstack.development`;

    it('a freshly issued token verifies as valid, before its TTL elapses', async () => {
      const { accessToken } = await signUpAndGetSession(env, uniqueEmail('e2e-ttl'));

      const verified = await request(app.getHttpServer())
        .post('/api/v1/auth/verify')
        .set('Host', host())
        .auth(env.publishableKey, env.secretKey)
        .send({ accessToken });

      expect(verified.status).toBe(201);
      expect(verified.body.valid).toBe(true);
    });

    it('the same token is rejected as invalid_or_expired once its TTL has genuinely elapsed', async () => {
      const { accessToken } = await signUpAndGetSession(env, uniqueEmail('e2e-ttl'));

      await new Promise(r => setTimeout(r, 3500));

      const verified = await request(app.getHttpServer())
        .post('/api/v1/auth/verify')
        .set('Host', host())
        .auth(env.publishableKey, env.secretKey)
        .send({ accessToken });

      expect(verified.status).toBe(401);
      expect(verified.body.errors?.[0]?.code).toBe('token_invalid_or_expired');
    });

    it('an expired access token still round-trips through refresh/mint into a NEW, verifiable token', async () => {
      const { agent, sessionId, accessToken } = await signUpAndGetSession(env, uniqueEmail('e2e-ttl'));

      await new Promise(r => setTimeout(r, 3500));
      const staleCheck = await request(app.getHttpServer())
        .post('/api/v1/auth/verify')
        .set('Host', host())
        .auth(env.publishableKey, env.secretKey)
        .send({ accessToken });
      expect(staleCheck.status).toBe(401);
      expect(staleCheck.body.errors?.[0]?.code).toBe('token_invalid_or_expired');

      // The session itself is still well within its (default) refreshTokenTtl
      // window — only the previously-issued access token's short TTL expired.
      // Minting a fresh token for the same still-active session must succeed
      // and produce something that verifies again.
      const minted = await agent.post(`/api/v1/auth/client/sessions/${sessionId}/tokens`).set('Host', host());
      expect(minted.status).toBe(201);
      expect(minted.body.accessToken).not.toBe(accessToken);

      const reverified = await request(app.getHttpServer())
        .post('/api/v1/auth/verify')
        .set('Host', host())
        .auth(env.publishableKey, env.secretKey)
        .send({ accessToken: minted.body.accessToken });
      expect(reverified.status).toBe(201);
      expect(reverified.body.valid).toBe(true);
    });
  });

  describe('session expiresAt boundary (independent of the access token TTL)', () => {
    let env: SeededEnvironment;
    beforeEach(async () => {
      env = await seedEnvironment();
    });
    afterEach(async () => {
      await cleanPlatformData(env.environmentId);
      await deleteEnvironment(env);
    });
    const host = () => `${env.slug}.stack.shipstack.development`;

    it('GET :id reports an expired-but-still-ACTIVE-status session as EXPIRED, not ACTIVE', async () => {
      const { agent, sessionId } = await signUpAndGetSession(env, uniqueEmail('e2e-ttl'));
      await expireSession(sessionId);

      const res = await agent.get(`/api/v1/auth/client/sessions/${sessionId}`).set('Host', host());

      expect(res.status).toBe(200);
      // buildSessionSummary derives this from expiresAt, independent of the
      // DB row's own status column, which expireSession() deliberately left
      // as ACTIVE — this is a computed-at-read-time downgrade, not a stored
      // status value.
      expect(res.body.status).toBe('EXPIRED');
    });

    it('POST :id/tokens (mint) rejects an expired session with session_not_active, same code as an ended one', async () => {
      const { agent, sessionId } = await signUpAndGetSession(env, uniqueEmail('e2e-ttl'));
      await expireSession(sessionId);

      const mint = await agent.post(`/api/v1/auth/client/sessions/${sessionId}/tokens`).set('Host', host());

      expect(mint.status).toBe(401);
      expect(mint.body.errors?.[0]?.code).toBe('session_not_active');
    });

    it('POST /auth/client/tokens (no explicit sessionRefreshToken) degrades to no-active-session, not an error, once the session has expired', async () => {
      const { agent, sessionId } = await signUpAndGetSession(env, uniqueEmail('e2e-ttl'));
      await expireSession(sessionId);

      const refreshed = await agent.post('/api/v1/auth/client/tokens').set('Host', host()).send({});

      expect(refreshed.status).toBe(201);
      expect(refreshed.body.sessions).toEqual([]);
      expect(refreshed.body.activeSessionId).toBeNull();
    });

    it('touch() still succeeds on an expired session — a heartbeat is not the same authorization boundary as minting/refreshing', async () => {
      const { agent, sessionId } = await signUpAndGetSession(env, uniqueEmail('e2e-ttl'));
      await expireSession(sessionId);

      // ownedSession() (the sole authz check for touch/end/remove/get) is
      // ownership-based, not expiry-based — only mintSessionToken and
      // refreshSession's "resolve the active session" path add their own
      // extra expiresAt check on top. Asserting this explicitly so a future
      // change that accidentally tightens touch()'s check is caught here,
      // not discovered as a surprise regression.
      const res = await agent.post(`/api/v1/auth/client/sessions/${sessionId}/touch`).set('Host', host());

      expect(res.status).toBe(201);
      expect(res.body.status).toBe('EXPIRED');
    });
  });
});
