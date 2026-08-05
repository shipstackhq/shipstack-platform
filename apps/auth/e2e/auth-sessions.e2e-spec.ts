import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { createTestApp } from './support/app';
import { seedEnvironment, deleteEnvironment, closeFixturePool, SeededEnvironment } from './support/fixtures';
import { cleanPlatformData, closeCleanupPool } from './support/cleanup';
import { uniqueEmail } from './support/email';

// /auth/client/sessions/* — client-as-root session lifecycle. Every route
// runs behind SessionGuard, ownership (session.clientId === req.client.id)
// is the entire authz model (see AuthService's "Session lifecycle" comment).
//
// POST /auth/client/sessions/:id uses Clerk's own single-route + {action}
// body shape (end/remove), not separate :id/end + :id/remove paths — see
// SessionActionDto's own doc comment for why.
describe('session lifecycle (e2e)', () => {
  let app: INestApplication;
  let env: SeededEnvironment;

  beforeAll(async () => {
    app = await createTestApp();
  });

  afterAll(async () => {
    await app.close();
    await closeFixturePool();
    await closeCleanupPool();
  });

  beforeEach(async () => {
    env = await seedEnvironment();
  });

  afterEach(async () => {
    await cleanPlatformData(env.environmentId);
    await deleteEnvironment(env);
  });

  const password = 'correct horse battery staple 1';
  const host = () => `${env.slug}.stack.shipstack.development`;

  // Signs up, reloads to get a real accessToken, and verifies it to learn
  // the real sessionId — returns the agent (cookie jar, reusable for
  // further calls against the SAME client) plus the sessionId.
  async function signUpAndGetSession(email: string): Promise<{ agent: ReturnType<typeof request.agent>; sessionId: string }> {
    const agent = request.agent(app.getHttpServer());
    const signUp = await agent
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', host())
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
    const reloaded = await agent
      .get(`/api/v1/auth/client/sign_ups/${signUp.body.id}`)
      .set('Host', host());
    const verified = await request(app.getHttpServer())
      .post('/api/v1/auth/verify')
      .set('Host', host())
      .auth(env.publishableKey, env.secretKey)
      .send({ accessToken: reloaded.body.accessToken });
    return { agent, sessionId: verified.body.sessionId };
  }

  describe('GET :id', () => {
    it('returns the session for its own client', async () => {
      const { agent, sessionId } = await signUpAndGetSession(uniqueEmail('e2e-session'));

      const res = await agent.get(`/api/v1/auth/client/sessions/${sessionId}`).set('Host', host());

      expect(res.status).toBe(200);
      expect(res.body.id).toBe(sessionId);
      expect(res.body.status).toBe('ACTIVE');
      expect(res.body.object).toBe('session');
    });

    it('a session belonging to a DIFFERENT client returns session_not_found, not a leak', async () => {
      const { sessionId } = await signUpAndGetSession(uniqueEmail('e2e-session'));

      // A second, unrelated client (its own agent, own __client cookie) —
      // must bootstrap a client of its own first, since SessionGuard needs
      // req.client resolved before it can even attempt ownership.
      const otherAgent = request.agent(app.getHttpServer());
      await otherAgent.post('/api/v1/auth/client').set('Host', host()).send({});

      const res = await otherAgent.get(`/api/v1/auth/client/sessions/${sessionId}`).set('Host', host());

      expect(res.status).toBe(404);
      expect(res.body.errors?.[0]?.code).toBe('session_not_found');
    });

    it('an unknown sessionId returns session_not_found', async () => {
      const agent = request.agent(app.getHttpServer());
      await agent.post('/api/v1/auth/client').set('Host', host()).send({});

      const res = await agent.get('/api/v1/auth/client/sessions/sess_does_not_exist').set('Host', host());

      expect(res.status).toBe(404);
      expect(res.body.errors?.[0]?.code).toBe('session_not_found');
    });
  });

  describe('DELETE (bulk end)', () => {
    it('ends every active session for the client, leaves other clients untouched', async () => {
      const email = uniqueEmail('e2e-session');
      const { agent, sessionId } = await signUpAndGetSession(email);

      // A second sign-in on a SEPARATE client for the SAME identity — must
      // survive this client's bulk-end.
      const otherAgent = request.agent(app.getHttpServer());
      const otherSignIn = await otherAgent
        .post('/api/v1/auth/client/sign_ins')
        .set('Host', host())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
      const otherReloaded = await otherAgent
        .get(`/api/v1/auth/client/sign_ins/${otherSignIn.body.id}`)
        .set('Host', host());
      const otherVerified = await request(app.getHttpServer())
        .post('/api/v1/auth/verify')
        .set('Host', host())
        .auth(env.publishableKey, env.secretKey)
        .send({ accessToken: otherReloaded.body.accessToken });
      const otherSessionId = otherVerified.body.sessionId;

      const del = await agent.delete('/api/v1/auth/client/sessions').set('Host', host());
      expect(del.status).toBe(200);
      expect(del.body.ok).toBe(true);

      const check = await agent.get(`/api/v1/auth/client/sessions/${sessionId}`).set('Host', host());
      expect(check.body.status).toBe('ENDED');

      const otherCheck = await otherAgent.get(`/api/v1/auth/client/sessions/${otherSessionId}`).set('Host', host());
      expect(otherCheck.body.status).toBe('ACTIVE');
    });
  });

  describe('POST :id/touch', () => {
    it('bumps lastActiveAt, does not change status or accessToken', async () => {
      const { agent, sessionId } = await signUpAndGetSession(uniqueEmail('e2e-session'));

      const before = await agent.get(`/api/v1/auth/client/sessions/${sessionId}`).set('Host', host());

      // Ensure a real clock delta — lastActiveAt is second-resolution
      // (Math.floor(getTime()/1000) in buildSessionSummary).
      await new Promise(r => setTimeout(r, 1100));

      const touched = await agent.post(`/api/v1/auth/client/sessions/${sessionId}/touch`).set('Host', host());

      expect(touched.status).toBe(201);
      expect(touched.body.status).toBe('ACTIVE');
      expect(touched.body.lastActiveAt).toBeGreaterThan(before.body.lastActiveAt);
      // touch() is a pure heartbeat — never mints a token (see
      // AuthService.touchSession's own doc comment).
      expect(touched.body.accessToken).toBe(before.body.accessToken);
    });

    it('touching an unowned session is rejected', async () => {
      const { sessionId } = await signUpAndGetSession(uniqueEmail('e2e-session'));
      const otherAgent = request.agent(app.getHttpServer());
      await otherAgent.post('/api/v1/auth/client').set('Host', host()).send({});

      const res = await otherAgent.post(`/api/v1/auth/client/sessions/${sessionId}/touch`).set('Host', host());
      expect(res.status).toBe(404);
    });
  });

  describe('POST :id {action: "end"}', () => {
    it('ends a single session, other sessions for the same client are unaffected', async () => {
      const email = uniqueEmail('e2e-session');
      const { agent, sessionId: firstSessionId } = await signUpAndGetSession(email);

      // Second sign-in, SAME client (same agent/cookie jar) — a real
      // multi-session-per-client scenario, not a second client.
      const secondSignIn = await agent
        .post('/api/v1/auth/client/sign_ins')
        .set('Host', host())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
      const secondReloaded = await agent
        .get(`/api/v1/auth/client/sign_ins/${secondSignIn.body.id}`)
        .set('Host', host());
      const secondVerified = await request(app.getHttpServer())
        .post('/api/v1/auth/verify')
        .set('Host', host())
        .auth(env.publishableKey, env.secretKey)
        .send({ accessToken: secondReloaded.body.accessToken });
      const secondSessionId = secondVerified.body.sessionId;

      expect(secondSessionId).not.toBe(firstSessionId);

      const ended = await agent
        .post(`/api/v1/auth/client/sessions/${firstSessionId}`)
        .set('Host', host())
        .send({ action: 'end' });
      expect(ended.status).toBe(201);
      expect(ended.body.status).toBe('ENDED');

      const secondCheck = await agent.get(`/api/v1/auth/client/sessions/${secondSessionId}`).set('Host', host());
      expect(secondCheck.body.status).toBe('ACTIVE');
    });

    it('an ended session no longer mints tokens', async () => {
      const { agent, sessionId } = await signUpAndGetSession(uniqueEmail('e2e-session'));

      await agent.post(`/api/v1/auth/client/sessions/${sessionId}`).set('Host', host()).send({ action: 'end' });

      const mint = await agent.post(`/api/v1/auth/client/sessions/${sessionId}/tokens`).set('Host', host());
      expect(mint.status).toBe(401);
      expect(mint.body.errors?.[0]?.code).toBe('session_not_active');
    });
  });

  describe('POST :id {action: "remove"}', () => {
    it('sets status REMOVED, distinct from end/ENDED', async () => {
      const { agent, sessionId } = await signUpAndGetSession(uniqueEmail('e2e-session'));

      const removed = await agent
        .post(`/api/v1/auth/client/sessions/${sessionId}`)
        .set('Host', host())
        .send({ action: 'remove' });

      expect(removed.status).toBe(201);
      expect(removed.body.status).toBe('REMOVED');
    });
  });

  describe('POST :id {action: "..."} validation', () => {
    it('an unsupported action is rejected with a 400', async () => {
      const { agent, sessionId } = await signUpAndGetSession(uniqueEmail('e2e-session'));

      const res = await agent
        .post(`/api/v1/auth/client/sessions/${sessionId}`)
        .set('Host', host())
        .send({ action: 'not-a-real-action' });

      expect(res.status).toBe(400);
    });
  });

  describe('POST :id/tokens', () => {
    it('mints a fresh, verifiable access token for the session', async () => {
      const { agent, sessionId } = await signUpAndGetSession(uniqueEmail('e2e-session'));

      const minted = await agent.post(`/api/v1/auth/client/sessions/${sessionId}/tokens`).set('Host', host());

      expect(minted.status).toBe(201);
      expect(minted.body.accessToken).toEqual(expect.any(String));

      const verified = await request(app.getHttpServer())
        .post('/api/v1/auth/verify')
        .set('Host', host())
        .auth(env.publishableKey, env.secretKey)
        .send({ accessToken: minted.body.accessToken });

      expect(verified.status).toBe(201);
      expect(verified.body.valid).toBe(true);
      expect(verified.body.sessionId).toBe(sessionId);
    });

    it('mints independently for each session on a multi-session client — not the client-wide active one', async () => {
      const email = uniqueEmail('e2e-session');
      const { agent, sessionId: firstSessionId } = await signUpAndGetSession(email);

      const secondSignIn = await agent
        .post('/api/v1/auth/client/sign_ins')
        .set('Host', host())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
      const secondReloaded = await agent
        .get(`/api/v1/auth/client/sign_ins/${secondSignIn.body.id}`)
        .set('Host', host());
      const secondVerified = await request(app.getHttpServer())
        .post('/api/v1/auth/verify')
        .set('Host', host())
        .auth(env.publishableKey, env.secretKey)
        .send({ accessToken: secondReloaded.body.accessToken });
      const secondSessionId = secondVerified.body.sessionId;

      // Mint explicitly for the FIRST (no-longer-"active") session — proves
      // tokens() isn't scoped to whichever session the client currently
      // considers active (see mintSessionToken's own doc comment: this is
      // the multi-session counterpart to refreshSession's single-active
      // scope).
      const mintFirst = await agent.post(`/api/v1/auth/client/sessions/${firstSessionId}/tokens`).set('Host', host());
      expect(mintFirst.status).toBe(201);

      const verifyFirst = await request(app.getHttpServer())
        .post('/api/v1/auth/verify')
        .set('Host', host())
        .auth(env.publishableKey, env.secretKey)
        .send({ accessToken: mintFirst.body.accessToken });
      expect(verifyFirst.body.sessionId).toBe(firstSessionId);
      expect(verifyFirst.body.sessionId).not.toBe(secondSessionId);
    });

    it('minting for an unowned session is rejected', async () => {
      const { sessionId } = await signUpAndGetSession(uniqueEmail('e2e-session'));
      const otherAgent = request.agent(app.getHttpServer());
      await otherAgent.post('/api/v1/auth/client').set('Host', host()).send({});

      const res = await otherAgent.post(`/api/v1/auth/client/sessions/${sessionId}/tokens`).set('Host', host());
      expect(res.status).toBe(404);
    });

    it('minting for a removed session is rejected', async () => {
      const { agent, sessionId } = await signUpAndGetSession(uniqueEmail('e2e-session'));
      await agent.post(`/api/v1/auth/client/sessions/${sessionId}`).set('Host', host()).send({ action: 'remove' });

      const mint = await agent.post(`/api/v1/auth/client/sessions/${sessionId}/tokens`).set('Host', host());
      expect(mint.status).toBe(401);
      expect(mint.body.errors?.[0]?.code).toBe('session_not_active');
    });
  });
});
