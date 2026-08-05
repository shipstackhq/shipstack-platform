import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { createTestApp } from './support/app';
import { seedEnvironment, deleteEnvironment, closeFixturePool, SeededEnvironment } from './support/fixtures';
import { cleanPlatformData, closeCleanupPool } from './support/cleanup';
import { findSetCookie } from './support/cookies';
import { uniqueEmail } from './support/email';

// Dev-browser mode — the __shipstack_db_jwt mechanism that stands in for
// the __client cookie when a cross-site dev/staging request can't reliably
// carry an httpOnly cookie at all (see AttemptsController's class comment
// for the full rationale, and DevBrowser's own doc comment in
// platform.prisma).
//
// Two things confirmed by reading the actual code before writing any
// assertions around them, both non-obvious enough to be worth stating:
//
// 1. POST /auth/dev_browser's response has BOTH `id` (the raw DevBrowser
//    row id) and `token` (a signed JWT wrapping that id, minted by
//    IdentityTokenService.signDevBrowserToken). The `__shipstack_db_jwt`
//    query param every downstream route reads is resolved as the raw
//    DevBrowser.id via a direct `findUnique({ where: { id: devBrowserId }
//    })` (see AuthService.clientBootstrapViaDevBrowser) — NOT as a
//    verified JWT. There is no verifyDevBrowserToken anywhere in this
//    codebase; the signed `token` field is minted but never checked by
//    anything. This test therefore uses `id`, matching what the real
//    system actually reads — using `token` here would be testing a value
//    nothing downstream consumes.
//
// 2. Reusing the same devBrowserId across multiple calls DOES persist the
//    same underlying Client (clientBootstrapViaDevBrowser looks up
//    devBrowser.clientId and reuses it once bound) — this is the
//    dev-browser-mode equivalent of a browser sending the same __client
//    cookie back on every request. A sign-up followed by a sign-in using
//    the SAME devBrowserId is therefore a valid same-device flow, exactly
//    like the cookie-based auth-email-password.e2e-spec.ts's signUpAgent.
describe('dev-browser mode (e2e)', () => {
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

  async function mintDevBrowser(): Promise<string> {
    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/dev_browser')
      .set('Host', `${env.slug}.stack.shipstack.development`);
    expect(res.status).toBe(201);
    expect(res.body.id).toEqual(expect.any(String));
    expect(res.body.token).toEqual(expect.any(String));
    return res.body.id;
  }

  it('POST /auth/dev_browser mints a pointer scoped to the resolved environment', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/dev_browser')
      .set('Host', `${env.slug}.stack.shipstack.development`);

    expect(res.status).toBe(201);
    expect(res.body.instance_id).toBe(env.environmentId);
    expect(res.body.client_id).toBeNull(); // no Client bound yet — nothing has signed in through it
  });

  it('sign_ups via __shipstack_db_jwt never sets a __client cookie, and reports devMode:true', async () => {
    const devBrowserId = await mintDevBrowser();
    const email = uniqueEmail('e2e-devbrowser');

    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .query({ __shipstack_db_jwt: devBrowserId })
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('COMPLETE');
    expect(res.body.devMode).toBe(true);
    // The whole point of dev-browser mode: no httpOnly cookie is even
    // attempted, since it structurally cannot land cross-site.
    expect(findSetCookie(res.headers, '__client=')).toBeUndefined();
  });

  it('full sign-up -> sign-in round trip using ONLY the devBrowserId (no cookie jar at all)', async () => {
    const devBrowserId = await mintDevBrowser();
    const email = uniqueEmail('e2e-devbrowser');

    // ── Sign-up ────────────────────────────────────────────────────────
    const signUpCreate = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .query({ __shipstack_db_jwt: devBrowserId })
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

    expect(signUpCreate.status).toBe(201);
    expect(signUpCreate.body.status).toBe('COMPLETE');

    // reload() — same devBrowserId, plain request() (no agent/cookie jar
    // needed at all in this mode, unlike the cookie-based flow).
    const signUpReload = await request(app.getHttpServer())
      .get(`/api/v1/auth/client/sign_ups/${signUpCreate.body.id}`)
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .query({ __shipstack_db_jwt: devBrowserId });

    expect(signUpReload.status).toBe(200);
    expect(signUpReload.body.accessToken).toEqual(expect.any(String));
    expect(signUpReload.body.devMode).toBe(true);

    const verifyAfterSignUp = await request(app.getHttpServer())
      .post('/api/v1/auth/verify')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .auth(env.publishableKey, env.secretKey)
      .send({ accessToken: signUpReload.body.accessToken });
    expect(verifyAfterSignUp.status).toBe(201);
    expect(verifyAfterSignUp.body.valid).toBe(true);

    // ── Sign-in — SAME devBrowserId, proving the DevBrowser -> Client
    // binding persists across calls the same way a __client cookie would ──
    const signInCreate = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .query({ __shipstack_db_jwt: devBrowserId })
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

    expect(signInCreate.status).toBe(201);
    expect(signInCreate.body.status).toBe('COMPLETE');

    const signInReload = await request(app.getHttpServer())
      .get(`/api/v1/auth/client/sign_ins/${signInCreate.body.id}`)
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .query({ __shipstack_db_jwt: devBrowserId });

    expect(signInReload.status).toBe(200);
    expect(signInReload.body.accessToken).toEqual(expect.any(String));

    const verifyAfterSignIn = await request(app.getHttpServer())
      .post('/api/v1/auth/verify')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .auth(env.publishableKey, env.secretKey)
      .send({ accessToken: signInReload.body.accessToken });

    expect(verifyAfterSignIn.status).toBe(201);
    expect(verifyAfterSignIn.body.valid).toBe(true);
    expect(verifyAfterSignIn.body.shipstackId).toBe(verifyAfterSignUp.body.shipstackId);
  });

  it('GET/DELETE /auth/client also resolve via __shipstack_db_jwt, with no cookie involved', async () => {
    const devBrowserId = await mintDevBrowser();
    const email = uniqueEmail('e2e-devbrowser');

    await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .query({ __shipstack_db_jwt: devBrowserId })
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

    // The DevBrowser is now bound to a real Client (created during sign-up)
    // — GET /auth/client should resolve THAT client via the same pointer,
    // not mint a new one.
    const getClient = await request(app.getHttpServer())
      .get('/api/v1/auth/client')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .query({ __shipstack_db_jwt: devBrowserId });

    expect(getClient.status).toBe(200);
    expect(getClient.body.clientId).toEqual(expect.any(String));
    expect(getClient.body.sessions.length).toBeGreaterThan(0);

    const del = await request(app.getHttpServer())
      .delete('/api/v1/auth/client')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .query({ __shipstack_db_jwt: devBrowserId });

    expect(del.status).toBe(200);
    expect(del.body.ok).toBe(true);
  });

  it('a devBrowserId scoped to a DIFFERENT environment is REJECTED (dev_browser_unauthenticated), never silently rebound', async () => {
    // Was previously "never throws" (see git history / task doc) — an
    // unknown/expired/cross-environment devBrowserId used to silently mint
    // a fresh anonymous Client and REBIND the DevBrowser row to it,
    // stealing the pointer away from whichever environment it was
    // previously bound to. Fixed to match Clerk's real FAPI behavior
    // exactly: an invalid __clerk_db_jwt gets a 401 with code
    // dev_browser_unauthenticated (confirmed against clerk-js's
    // AuthCookieService.handleUnauthenticatedDevBrowser and Base.ts's
    // status===401 && code==='dev_browser_unauthenticated' check this
    // session) — the client SDK is expected to detect that specific code
    // and react by discarding the stale value and minting a fresh one via
    // a NEW POST /auth/dev_browser call, not by having the server silently
    // paper over the mismatch. See ClientResolverService.resolveClientViaDevBrowser
    // for the guard-side sibling that already did this correctly — this
    // was the one remaining call site with the old silent-mint behavior.
    const otherEnv = await seedEnvironment();
    try {
      const devBrowserId = await mintDevBrowser(); // minted against `env`, not `otherEnv`
      const email = uniqueEmail('e2e-devbrowser');
      const signUp = await request(app.getHttpServer())
        .post('/api/v1/auth/client/sign_ups')
        .set('Host', `${env.slug}.stack.shipstack.development`)
        .query({ __shipstack_db_jwt: devBrowserId })
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
      expect(signUp.body.status).toBe('COMPLETE');
      const originalClientId = signUp.body.clientId;

      const res = await request(app.getHttpServer())
        .get('/api/v1/auth/client')
        .set('Host', `${otherEnv.slug}.stack.shipstack.development`)
        .query({ __shipstack_db_jwt: devBrowserId });

      expect(res.status).toBe(401);
      expect(res.body.errors).toHaveLength(1);
      expect(res.body.errors[0]).toMatchObject({
        message: 'Browser unauthenticated',
        code: 'dev_browser_unauthenticated',
      });

      // The ORIGINAL environment's binding is untouched — the rejected
      // cross-environment attempt never got a chance to steal or rebind
      // the DevBrowser row, so the original devBrowserId still resolves
      // the SAME client it did before.
      const originalStillIntact = await request(app.getHttpServer())
        .get('/api/v1/auth/client')
        .set('Host', `${env.slug}.stack.shipstack.development`)
        .query({ __shipstack_db_jwt: devBrowserId });

      expect(originalStillIntact.status).toBe(200);
      expect(originalStillIntact.body.clientId).toBe(originalClientId);
    } finally {
      await cleanPlatformData(otherEnv.environmentId);
      await deleteEnvironment(otherEnv);
    }
  });

  it('an unknown devBrowserId (never minted) is REJECTED the same way', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/auth/client')
      .set('Host', `${env.slug}.stack.shipstack.development`)
      .query({ __shipstack_db_jwt: 'not-a-real-dev-browser-id' });

    expect(res.status).toBe(401);
    expect(res.body.errors[0]).toMatchObject({
      message: 'Browser unauthenticated',
      code: 'dev_browser_unauthenticated',
    });
  });
});
