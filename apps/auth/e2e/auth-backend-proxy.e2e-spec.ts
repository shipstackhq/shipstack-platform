import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { createTestApp } from './support/app';
import { seedEnvironment, deleteEnvironment, closeFixturePool, SeededEnvironment } from './support/fixtures';
import { cleanPlatformData, closeCleanupPool } from './support/cleanup';
import { uniqueEmail } from './support/email';

// Backend-proxy mode — a tenant's own server (e.g. the Next.js SDK's route
// handler) calls FAPI with `Authorization: Basic publishableKey:secretKey`
// instead of a browser cookie jar. EnvironmentGuard's BackendProxyDetector
// verifies the secret and sets req.isBackendProxy, which changes behavior
// in exactly two places (confirmed this session by grepping every
// isBackendProxy call site):
//
// 1. relayClient() (attempts.controller.ts) returns `signedClientCookie`
//    in the JSON body instead of a Set-Cookie header — a backend-proxy
//    caller has no browser cookie jar of its own to receive a Set-Cookie
//    into; it needs the raw signed value to re-set as ITS OWN httpOnly
//    cookie on ITS OWN response to the real browser.
// 2. assertIfDirectMode() (auth.controller.ts) is skipped for backend-proxy
//    callers — PRODUCTION-type environments block DIRECT mode (no custom-
//    domain support yet, assertDirectModeAllowed's own doc comment), but
//    backend-proxy mode is exempt since it never relies on FAPI's own
//    cross-site cookie at all.
//
// This is the load-bearing path for SDK backend-proxy support — untested
// until now despite every guard/controller change this session touching
// isBackendProxy's plumbing.
describe('backend-proxy mode (e2e)', () => {
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
  const proxyAuth = () => ({ Authorization: `Basic ${Buffer.from(`${env.publishableKey}:${env.secretKey}`).toString('base64')}` });

  describe('POST /auth/client via Basic auth', () => {
    it('returns signedClientCookie in the body, never a Set-Cookie header', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/auth/client')
        .set('Host', host())
        .set(proxyAuth())
        .send({});

      expect(res.status).toBe(201);
      expect(res.body.signedClientCookie).toEqual(expect.any(String));
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('a direct-mode call (no Basic auth) gets a Set-Cookie, never signedClientCookie', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/auth/client')
        .set('Host', host())
        .send({});

      expect(res.status).toBe(201);
      expect(res.body.signedClientCookie).toBeUndefined();
      expect(res.headers['set-cookie']).toBeDefined();
    });
  });

  describe('sign_ups/sign_ins via Basic auth', () => {
    it('full sign-up flow via backend-proxy: signedClientCookie relayed on create AND reload, real token verifiable', async () => {
      const email = uniqueEmail('e2e-proxy');

      const signUp = await request(app.getHttpServer())
        .post('/api/v1/auth/client/sign_ups')
        .set('Host', host())
        .set(proxyAuth())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

      expect(signUp.status).toBe(201);
      expect(signUp.body.status).toBe('COMPLETE');
      expect(signUp.body.signedClientCookie).toEqual(expect.any(String));
      expect(signUp.headers['set-cookie']).toBeUndefined();

      const reloaded = await request(app.getHttpServer())
        .get(`/api/v1/auth/client/sign_ups/${signUp.body.id}`)
        .set('Host', host())
        .set(proxyAuth())
        .set('x-shipstack-client', signUp.body.signedClientCookie);

      expect(reloaded.status).toBe(200);
      expect(reloaded.body.accessToken).toEqual(expect.any(String));
      expect(reloaded.body.signedClientCookie).toEqual(expect.any(String));
      expect(reloaded.headers['set-cookie']).toBeUndefined();

      const verified = await request(app.getHttpServer())
        .post('/api/v1/auth/verify')
        .set('Host', host())
        .auth(env.publishableKey, env.secretKey)
        .send({ accessToken: reloaded.body.accessToken });

      expect(verified.status).toBe(201);
      expect(verified.body.valid).toBe(true);
    });

    it('sign-in via backend-proxy for an existing account works the same way', async () => {
      const email = uniqueEmail('e2e-proxy');
      const signUp = await request(app.getHttpServer())
        .post('/api/v1/auth/client/sign_ups')
        .set('Host', host())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
      expect(signUp.body.status).toBe('COMPLETE');

      const signIn = await request(app.getHttpServer())
        .post('/api/v1/auth/client/sign_ins')
        .set('Host', host())
        .set(proxyAuth())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

      expect(signIn.status).toBe(201);
      expect(signIn.body.status).toBe('COMPLETE');
      expect(signIn.body.signedClientCookie).toEqual(expect.any(String));
    });

    it('an invalid secretKey on the Basic header is rejected, not silently treated as direct mode', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/auth/client/sign_ins')
        .set('Host', host())
        .set('Authorization', `Basic ${Buffer.from(`${env.publishableKey}:sk_test_totally_wrong`).toString('base64')}`)
        .send({ identifier: uniqueEmail('e2e-proxy'), strategy: 'EMAIL_PASSWORD', password });

      expect(res.status).toBe(401);
      expect(res.body.errors?.[0]?.code).toBe('invalid_credentials');
    });
  });

  describe('PRODUCTION environment: backend-proxy bypasses the direct-mode block', () => {
    it('a PRODUCTION environment via backend-proxy (Basic auth) succeeds', async () => {
      const prodEnv = await seedEnvironment({ type: 'PRODUCTION' });
      try {
        const res = await request(app.getHttpServer())
          .post('/api/v1/auth/client')
          .set('Host', `${prodEnv.slug}.stack.shipstack.development`)
          .set({ Authorization: `Basic ${Buffer.from(`${prodEnv.publishableKey}:${prodEnv.secretKey}`).toString('base64')}` })
          .send({});

        expect(res.status).toBe(201);
        expect(res.body.signedClientCookie).toEqual(expect.any(String));
      } finally {
        await cleanPlatformData(prodEnv.environmentId);
        await deleteEnvironment(prodEnv);
      }
    });

    it('a PRODUCTION environment via DIRECT mode (no Basic auth) is blocked', async () => {
      const prodEnv = await seedEnvironment({ type: 'PRODUCTION' });
      try {
        const res = await request(app.getHttpServer())
          .post('/api/v1/auth/client')
          .set('Host', `${prodEnv.slug}.stack.shipstack.development`)
          .send({});

        expect(res.status).toBe(403);
      } finally {
        await cleanPlatformData(prodEnv.environmentId);
        await deleteEnvironment(prodEnv);
      }
    });
  });
});
