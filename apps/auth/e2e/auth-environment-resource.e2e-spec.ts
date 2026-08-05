import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { createTestApp } from './support/app';
import { seedEnvironment, seedAuthMethodConfig, deleteEnvironment, closeFixturePool, SeededEnvironment } from './support/fixtures';
import { cleanPlatformData, closeCleanupPool } from './support/cleanup';
import { uniqueEmail } from './support/email';

// GET /environment (renamed from /config, docs/environment-resource-task.md)
// plus the real enforcement behavior that makes this more than a rename:
// AuthMethodConfig.enabled is now actually checked by the attempt flows,
// not just reported by discovery.
describe('environment resource + auth method enforcement (e2e)', () => {
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

  it('GET /environment returns the full expanded shape', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/environment')
      .set('Host', `${env.slug}.stack.shipstack.development`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      authMethods: { emailPassword: true, google: true },
      password: {
        minLength: 8,
        requirements: 'letters_digits',
        preventLeakedPasswords: false,
        minPasswordStrength: null,
      },
      requireEmailVerification: false,
      nameFields: { collect: false, required: false },
      allowSelfDeletion: true,
    });
    // Session-minting internals must never leak into the public resource.
    expect(res.body.accessTokenTtl).toBeUndefined();
    expect(res.body.refreshTokenTtl).toBeUndefined();
  });

  it('an unconfigured auth method (no AuthMethodConfig row at all) defaults to enabled, both for discovery and enforcement', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/environment')
      .set('Host', `${env.slug}.stack.shipstack.development`);
    expect(res.body.authMethods.emailPassword).toBe(true);

    const email = uniqueEmail();
    const signUp = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password: 'correct horse battery staple 1' });

    expect(signUp.status).toBe(201);
    expect(signUp.body.status).toBe('COMPLETE');
  });

  it('rejects sign-up via a disabled auth method with a coded error', async () => {
    await seedAuthMethodConfig(env.environmentId, 'EMAIL_PASSWORD', false);

    const email = uniqueEmail();
    const signUp = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password: 'correct horse battery staple 1' });

    expect(signUp.status).toBe(403);
    expect(signUp.body.errors?.[0]?.code).toBe('auth_method_disabled');
  });

  it('rejects sign-in via a disabled auth method with a coded error', async () => {
    const email = uniqueEmail();
    const password = 'correct horse battery staple 1';

    // Seed the identity while EMAIL_PASSWORD is still enabled...
    const signUp = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
    expect(signUp.body.status).toBe('COMPLETE');

    // ...then disable it and confirm sign-in is rejected cleanly.
    await seedAuthMethodConfig(env.environmentId, 'EMAIL_PASSWORD', false);

    const signIn = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

    expect(signIn.status).toBe(403);
    expect(signIn.body.errors?.[0]?.code).toBe('auth_method_disabled');
  });

  it('an explicitly enabled auth method still works, distinguishing "enabled" from "unconfigured"', async () => {
    await seedAuthMethodConfig(env.environmentId, 'EMAIL_PASSWORD', true);

    const email = uniqueEmail();
    const signUp = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password: 'correct horse battery staple 1' });

    expect(signUp.status).toBe(201);
    expect(signUp.body.status).toBe('COMPLETE');
  });

  // Microsoft OAuth is pulled from v1 entirely (dropped from scope, no e2e
  // coverage of its own) — EnvironmentService.DISABLED_METHODS hard-denies
  // it rather than letting it fall through to the "unconfigured = enabled"
  // default that every other method gets. Unlike EMAIL_PASSWORD above, this
  // is NOT overridable via AuthMethodConfig — there is no dashboard toggle
  // that can turn a dropped-from-scope, untested provider back on.
  it('MICROSOFT is rejected even with no AuthMethodConfig row — hard-denied, not just unconfigured', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: uniqueEmail(), strategy: 'MICROSOFT' });

    expect(res.status).toBe(403);
    expect(res.body.errors?.[0]?.code).toBe('auth_method_disabled');
  });

  it('MICROSOFT stays rejected even with an explicit enabled:true AuthMethodConfig row', async () => {
    await seedAuthMethodConfig(env.environmentId, 'MICROSOFT', true);

    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .send({ identifier: uniqueEmail(), strategy: 'MICROSOFT' });

    expect(res.status).toBe(403);
    expect(res.body.errors?.[0]?.code).toBe('auth_method_disabled');
  });

  it('discovery (GET /environment) never surfaces MICROSOFT as an auth method', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/environment')
      .set('Host', `${env.slug}.stack.shipstack.development`);

    expect(res.body.authMethods).toEqual({ emailPassword: true, google: true });
    expect(res.body.authMethods.microsoft).toBeUndefined();
  });
});
