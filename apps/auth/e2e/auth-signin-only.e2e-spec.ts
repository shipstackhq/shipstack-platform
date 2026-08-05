import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { createTestApp } from './support/app';
import { seedEnvironment, deleteEnvironment, closeFixturePool, SeededEnvironment } from './support/fixtures';
import { cleanPlatformData, closeCleanupPool, suspendIdentity } from './support/cleanup';
import { findSetCookie } from './support/cookies';
import { uniqueEmail } from './support/email';

// Sign-in ONLY — every account here is created via a helper (createAccount
// below), never as the test's own point of focus. auth-email-password.e2e-
// spec.ts already covers the sign-up -> sign-in happy path and the
// duplicate-signup/wrong-password cases; this file's job is the sign-in
// side specifically, against accounts that already exist (the realistic
// "returning user" case) and the failure modes unique to sign-in
// (unknown email, suspended identity) that the other file doesn't touch.
describe('email/password sign-in only (e2e)', () => {
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

  // Creates an account via a real sign-up call (COMPLETE, no manual DB
  // insert) — a sign-in test should exercise sign-in against a REAL
  // identity created the same way a real user's would be, not a hand-
  // crafted DB row that might drift from what sign-up actually produces.
  async function createAccount(email: string): Promise<void> {
    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
    if (res.body.status !== 'COMPLETE') {
      throw new Error(`createAccount fixture failed: ${JSON.stringify(res.body)}`);
    }
  }

  it('signs in successfully with correct credentials, on a fresh client with no prior __client cookie', async () => {
    const email = uniqueEmail('e2e-signin');
    await createAccount(email);

    const agent = request.agent(app.getHttpServer());

    const created = await agent
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

    expect(created.status).toBe(201);
    expect(created.body.status).toBe('COMPLETE');
    const clientCookie = findSetCookie(created.headers, '__client=');
    expect(clientCookie).toBeDefined();

    const reloaded = await agent
      .get(`/api/v1/auth/client/sign_ins/${created.body.id}`)
      .set('Host', `${env.slug}.stack.shipstack.development`);

    expect(reloaded.status).toBe(200);
    expect(reloaded.body.accessToken).toEqual(expect.any(String));

    const verified = await request(app.getHttpServer())
      .post('/api/v1/auth/verify')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .auth(env.publishableKey, env.secretKey)
      .send({ accessToken: reloaded.body.accessToken });

    expect(verified.status).toBe(201);
    expect(verified.body.valid).toBe(true);
  });

  it('signing in twice for the same account produces two independent sessions (two different sids)', async () => {
    const email = uniqueEmail('e2e-signin');
    await createAccount(email);

    async function signInAndGetSessionId(): Promise<string> {
      const agent = request.agent(app.getHttpServer());
      const created = await agent
        .post('/api/v1/auth/client/sign_ins')
        .set('Host', `${env.slug}.stack.shipstack.development`)
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
      const reloaded = await agent
        .get(`/api/v1/auth/client/sign_ins/${created.body.id}`)
        .set('Host', `${env.slug}.stack.shipstack.development`);
      const verified = await request(app.getHttpServer())
        .post('/api/v1/auth/verify')
        .set('Host', `${env.slug}.stack.shipstack.development`)
        .auth(env.publishableKey, env.secretKey)
        .send({ accessToken: reloaded.body.accessToken });
      return verified.body.sessionId;
    }

    const firstSessionId = await signInAndGetSessionId();
    const secondSessionId = await signInAndGetSessionId();

    expect(firstSessionId).toEqual(expect.any(String));
    expect(secondSessionId).toEqual(expect.any(String));
    expect(firstSessionId).not.toBe(secondSessionId);
  });

  it('reports a failed outcome for an email with no account at all', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: 'no-such-account@example.com', strategy: 'EMAIL_PASSWORD', password });

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('NEEDS_FIRST_FACTOR');
    expect(res.body.verificationStatus).toBe('FAILED');
    expect(res.body.identityId).toBeNull();
  });

  it('reports a failed outcome for a suspended identity, even with the correct password', async () => {
    const email = uniqueEmail('e2e-signin');
    await createAccount(email);
    await suspendIdentity(env.environmentId, email);

    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('NEEDS_FIRST_FACTOR');
    expect(res.body.verificationStatus).toBe('FAILED');
  });

  it('identifier lookup is case-insensitive (sign in with a differently-cased email)', async () => {
    // Uppercased on top of uniqueEmail()'s output (not a hand-written
    // literal) so this still gets the same collision-proofing every other
    // test's email does, while still exercising a genuinely different case
    // than what createAccount() registers with.
    const email = uniqueEmail('e2e-signin').toUpperCase();
    await createAccount(email);

    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email.toLowerCase(), strategy: 'EMAIL_PASSWORD', password });

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('COMPLETE');
  });
});
