import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { createTestApp } from './support/app';
import { seedEnvironment, deleteEnvironment, closeFixturePool, SeededEnvironment } from './support/fixtures';
import { cleanPlatformData, closeCleanupPool } from './support/cleanup';
import { findSetCookie } from './support/cookies';
import { uniqueEmail } from './support/email';

// Full email/password sign-up -> sign-in flow against a real app instance
// and real Postgres (shipstack_test) — no mocks below the HTTP boundary.
//
// Two things confirmed by hand (via a throwaway debug spec) before writing
// real assertions around them, both surprising enough to be worth stating
// explicitly:
//
// 1. create()/reload() never set the __client cookie or return a
//    clientToken in the body (that's the whole point of the fix made
//    earlier this session) — a caller MUST use a cookie-jar-persisting
//    client across the create() -> reload() round trip, exactly like a
//    real browser would. supertest's plain `request(app)` does NOT persist
//    cookies between separate calls; `request.agent(app)` does. Using the
//    wrong one here silently produces "clientToken is required to reload a
//    completed attempt" instead of a real result.
//
// 2. EmailPasswordStrategy.attempt() and EmailPasswordSignUpStrategy.attempt()
//    both deliberately CATCH whatever AuthService.verifyPasswordCredential/
//    createPasswordIdentity throws (wrong password -> UnauthorizedException,
//    duplicate email -> ConflictException) and convert it into a
//    `{result:'failed', reason}` OUTCOME rather than letting it become an
//    HTTP error response. So a wrong password or a duplicate signup is a
//    normal 200/201 response with status:'NEEDS_FIRST_FACTOR' and
//    verificationStatus:'FAILED' — not a 401/409. This is a deliberate,
//    uniform design (every attempt failure is a state transition, not an
//    HTTP error), confirmed by reading both strategies directly, not an
//    assumption.
describe('email/password sign-up -> sign-in (e2e)', () => {
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

  it('signs up, verifies the session cookie/token, then signs back in with the same credentials', async () => {
    const email = uniqueEmail();
    const password = 'correct horse battery staple 1';

    // ── Sign-up ────────────────────────────────────────────────────────
    const signUpAgent = request.agent(app.getHttpServer());

    const signUpCreate = await signUpAgent
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

    expect(signUpCreate.status).toBe(201);
    expect(signUpCreate.body.status).toBe('COMPLETE');
    expect(signUpCreate.body.id).toEqual(expect.any(String));
    const clientCookieFromCreate = findSetCookie(signUpCreate.headers, '__client=');
    expect(clientCookieFromCreate).toBeDefined();
    expect(clientCookieFromCreate).toContain('HttpOnly');

    const signUpReload = await signUpAgent
      .get(`/api/v1/auth/client/sign_ups/${signUpCreate.body.id}`)
      .set('Host', `${env.slug}.stack.shipstack.development`);

    expect(signUpReload.status).toBe(200);
    expect(signUpReload.body.accessToken).toEqual(expect.any(String));

    // Sanity-check the access token itself is a well-formed, signed JWT
    // usable against this environment — not just "some string came back".
    const verifyAfterSignUp = await request(app.getHttpServer())
      .post('/api/v1/auth/verify')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .auth(env.publishableKey, env.secretKey)
      .send({ accessToken: signUpReload.body.accessToken });

    expect(verifyAfterSignUp.status).toBe(201);
    expect(verifyAfterSignUp.body.valid).toBe(true);
    expect(verifyAfterSignUp.body.publishableKey).toBe(env.publishableKey);

    // ── Sign-in — same credentials, fresh (cookie-less) agent ────────────
    // Deliberately a NEW agent, not signUpAgent — proves sign-in works for a
    // genuinely new client too (the common real-world case: a different
    // device/session signing into an already-registered account), rather
    // than only the already-authenticated-client path.
    const signInAgent = request.agent(app.getHttpServer());

    const signInCreate = await signInAgent
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

    expect(signInCreate.status).toBe(201);
    expect(signInCreate.body.status).toBe('COMPLETE');

    const signInReload = await signInAgent
      .get(`/api/v1/auth/client/sign_ins/${signInCreate.body.id}`)
      .set('Host', `${env.slug}.stack.shipstack.development`);

    expect(signInReload.status).toBe(200);
    expect(signInReload.body.accessToken).toEqual(expect.any(String));

    const verifyAfterSignIn = await request(app.getHttpServer())
      .post('/api/v1/auth/verify')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .auth(env.publishableKey, env.secretKey)
      .send({ accessToken: signInReload.body.accessToken });

    expect(verifyAfterSignIn.status).toBe(201);
    expect(verifyAfterSignIn.body.valid).toBe(true);
    // Both attempts resolved to the SAME identity — sign-in found the
    // account sign-up created, rather than (incorrectly) creating a second one.
    expect(verifyAfterSignIn.body.shipstackId).toBe(verifyAfterSignUp.body.shipstackId);
  });

  it('reports a failed outcome (not an HTTP error) for the wrong password', async () => {
    const email = uniqueEmail();
    const password = 'correct horse battery staple 1';

    const signUpCreate = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
    expect(signUpCreate.body.status).toBe('COMPLETE');

    const signInCreate = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password: 'wrong password entirely' });

    expect(signInCreate.status).toBe(201);
    expect(signInCreate.body.status).toBe('NEEDS_FIRST_FACTOR');
    expect(signInCreate.body.verificationStatus).toBe('FAILED');
    // No session/identity was ever attached to this failed attempt.
    expect(signInCreate.body.identityId).toBeNull();
  });

  it('reports a failed outcome (not an HTTP error) for a duplicate sign-up email', async () => {
    const email = uniqueEmail();
    const password = 'correct horse battery staple 1';

    const first = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
    expect(first.body.status).toBe('COMPLETE');

    const second = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

    expect(second.status).toBe(201);
    expect(second.body.status).toBe('NEEDS_FIRST_FACTOR');
    expect(second.body.verificationStatus).toBe('FAILED');
    expect(second.body.identityId).toBeNull();
  });
});
