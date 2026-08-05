import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import nock from 'nock';
import { createTestApp } from './support/app';
import { seedEnvironment, deleteEnvironment, closeFixturePool, SeededEnvironment } from './support/fixtures';
import { cleanPlatformData, closeCleanupPool } from './support/cleanup';

// Google OAuth — cannot e2e-test a real Google login (no headless-browser
// Google auth in CI, and Google blocks automated login anyway). What IS
// ours and IS testable: PKCE/state generation, the callback handler, the
// token-exchange + userinfo HTTP calls, profile mapping, and identity
// linking/creation — everything except the actual Google redirect itself.
//
// axios.post/axios.get in oauth-strategy.base.ts are module-level calls,
// not NestJS DI tokens — overrideProvider (used for MailService) doesn't
// apply here. nock intercepts at the HTTP layer instead, same effect:
// real code runs, only the two outbound network calls are faked.
//
// DEFAULT_GOOGLE_CLIENT_ID/SECRET are already set in e2e/.env.test — no
// OAuthProviderConfig fixture row needed, getShipstackDefaults() covers it
// (see oauth-providers.service.ts).
describe('Google OAuth (e2e)', () => {
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
    nock.cleanAll();
  });

  const host = () => `${env.slug}.stack.shipstack.development`;

  function mockGoogleTokenExchange() {
    nock('https://oauth2.googleapis.com')
      .post('/token')
      .reply(200, { access_token: 'fake-google-access-token', token_type: 'Bearer', expires_in: 3600 });
  }

  function mockGoogleUserinfo(profile: Record<string, unknown>) {
    nock('https://www.googleapis.com')
      .get('/oauth2/v3/userinfo')
      .reply(200, profile);
  }

  // Extracts state from the real externalRedirectUrl create() returns —
  // proves PKCE/state were actually generated and threaded through, not
  // hand-crafted by the test.
  // The SDK's job after an OAuth sign-in: take the __shipstack_handshake token from
  // the final redirect and paint its cookies on the app's own origin. This does
  // the same, and returns the Cookie header a browser would now send.
  async function handshakeCookies(callbackRes: { headers: Record<string, string | string[] | undefined> }): Promise<string> {
    const tenantHop = await request(app.getHttpServer())
      .get(new URL(callbackRes.headers.location as string).pathname)
      .set('Host', new URL(callbackRes.headers.location as string).host)
      .query(Object.fromEntries(new URL(callbackRes.headers.location as string).searchParams))
      .redirects(0);
    const landing = new URL(tenantHop.headers.location as string);
    const token = landing.searchParams.get('__shipstack_handshake')!;
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')) as { handshake: string[] };
    return payload.handshake.map(directive => directive.split(';')[0]).join('; ');
  }

  function extractState(externalRedirectUrl: string): string {
    return new URL(externalRedirectUrl).searchParams.get('state')!;
  }

  it('full sign-in flow: create -> real callback -> mocked token/userinfo -> new identity created', async () => {
    const agent = request.agent(app.getHttpServer());

    const created = await agent
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', host())
      .send({ strategy: 'GOOGLE', redirectUrl: 'https://example.com/after' });

    expect(created.status).toBe(201);
    expect(created.body.externalRedirectUrl).toContain('accounts.google.com');
    const state = extractState(created.body.externalRedirectUrl);
    expect(state).toEqual(expect.any(String));

    mockGoogleTokenExchange();
    mockGoogleUserinfo({
      sub: 'google-user-12345',
      email: 'e2e-google-user@example.com',
      given_name: 'Ada',
      family_name: 'Lovelace',
      picture: 'https://example.com/avatar.png',
    });

    // Same agent as create(): the callback is a browser navigation in the same
    // session, so the client token it rotates must land in the same cookie jar.
    const callback = await agent
      .get('/api/v1/auth/oauth_callback')
      .query({ code: 'fake-authorization-code', state })
      .redirects(0);

    expect(callback.status).toBe(307); // 307 on purpose, matching Clerk (attempts.controller.ts)
    // The callback hands off to the tenant's own domain first, carrying the
    // final destination (and the handshake token) in final_redirect_url.
    const forward = new URL(callback.headers.location);
    expect(forward.origin).toBe(`https://${env.slug}.stack.shipstack.development`);
    expect(forward.pathname).toBe('/api/v1/auth/oauth_callback');
    expect(forward.searchParams.get('final_redirect_url')).toMatch(/^https:\/\/example\.com\/after\?__shipstack_handshake=/);
    expect(nock.isDone()).toBe(true); // both mocked calls were actually hit

    const reloaded = await request(app.getHttpServer())
      .get(`/api/v1/auth/client/sign_ins/${created.body.id}`)
      .set('Host', host())
      .set('Cookie', await handshakeCookies(callback)); // the rotated client token from the callback

    expect(reloaded.status).toBe(200);
    expect(reloaded.body.status).toBe('COMPLETE');
    expect(reloaded.body.accessToken).toEqual(expect.any(String));

    const verified = await request(app.getHttpServer())
      .post('/api/v1/auth/verify')
      .set('Host', host())
      .auth(env.publishableKey, env.secretKey)
      .send({ accessToken: reloaded.body.accessToken });

    expect(verified.status).toBe(201);
    expect(verified.body.valid).toBe(true);
  });

  it('signing in again with the same Google account links to the SAME identity, not a new one', async () => {
    async function signInWithGoogle(profile: Record<string, unknown>) {
      const agent = request.agent(app.getHttpServer());
      const created = await agent
        .post('/api/v1/auth/client/sign_ins')
        .set('Host', host())
        .send({ strategy: 'GOOGLE', redirectUrl: 'https://example.com/after' });
      const state = extractState(created.body.externalRedirectUrl);

      mockGoogleTokenExchange();
      mockGoogleUserinfo(profile);

      const callback = await request(app.getHttpServer())
        .get('/api/v1/auth/oauth_callback')
        .query({ code: 'fake-authorization-code', state })
        .redirects(0);

      const reloaded = await request(app.getHttpServer())
        .get(`/api/v1/auth/client/sign_ins/${created.body.id}`)
        .set('Host', host())
        .set('Cookie', await handshakeCookies(callback)); // the rotated client token from the callback
      const verified = await request(app.getHttpServer())
        .post('/api/v1/auth/verify')
        .set('Host', host())
        .auth(env.publishableKey, env.secretKey)
        .send({ accessToken: reloaded.body.accessToken });
      return verified.body.shipstackId;
    }

    const profile = {
      sub: 'google-user-same-account',
      email: 'e2e-google-repeat@example.com',
      given_name: 'Ada',
      family_name: 'Lovelace',
      picture: null,
    };

    const firstShipstackId = await signInWithGoogle(profile);
    const secondShipstackId = await signInWithGoogle(profile);

    expect(secondShipstackId).toBe(firstShipstackId);
  });

  it('a Google profile with no email claim fails cleanly, not a 500', async () => {
    const agent = request.agent(app.getHttpServer());
    const created = await agent
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', host())
      .send({ strategy: 'GOOGLE', redirectUrl: 'https://example.com/after' });
    const state = extractState(created.body.externalRedirectUrl);

    mockGoogleTokenExchange();
    mockGoogleUserinfo({ sub: 'google-user-no-email', given_name: 'No', family_name: 'Email' }); // no `email` field

    const callback = await request(app.getHttpServer())
      .get('/api/v1/auth/oauth_callback')
      .query({ code: 'fake-authorization-code', state })
      .redirects(0);

    // resolveExternal's own no_email_claim guard (oauth-strategy.base.ts) —
    // a failed outcome, still resolves to a real redirect, never a 500.
    expect(callback.status).toBe(307); // 307 on purpose, matching Clerk (attempts.controller.ts)

    const reloaded = await request(app.getHttpServer())
      .get(`/api/v1/auth/client/sign_ins/${created.body.id}`)
      .set('Host', host())
      .set('Cookie', await handshakeCookies(callback)); // the rotated client token from the callback
    expect(reloaded.body.status).toBe('NEEDS_FIRST_FACTOR');
    expect(reloaded.body.verificationStatus).toBe('FAILED');
  });

  it('an unknown/garbage state is rejected with a 400, no HTTP call is made', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/auth/oauth_callback')
      .query({ code: 'fake-authorization-code', state: 'not-a-real-state' });

    expect(res.status).toBe(400);
    expect(nock.pendingMocks()).toEqual([]); // nothing was even mocked/hit — confirms no network attempt
  });
});
