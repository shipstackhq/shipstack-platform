import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { createTestApp } from './support/app';
import { seedEnvironment, deleteEnvironment, closeFixturePool, SeededEnvironment } from './support/fixtures';
import { cleanPlatformData, closeCleanupPool } from './support/cleanup';
import { uniqueEmail } from './support/email';
import { FakeMailService } from './support/fake-mail.service';
import { MailService } from '../src/core/mail/mail.service';

// EMAIL_CODE (OTP) sign-in — sign-in only, matches Clerk's own model
// (EmailCodeStrategy's own doc comment: an unknown identifier fails
// immediately in prepare(), no identity creation here).
//
// Unlike EMAIL_PASSWORD, there is NO create()-time synchronous shortcut for
// this strategy — AttemptsService.create() only special-cases
// EMAIL_PASSWORD and OAuth (see attempts.service.ts). The real sequence is
// always three calls: POST sign_ins {identifier} -> POST
// sign_ins/:id/prepare_first_factor {strategy: EMAIL_CODE} -> POST
// sign_ins/:id/attempt_first_factor {input: {code}} -> GET sign_ins/:id
// for the token, matching the very first end-to-end trace done this
// session.
//
// The plaintext code is NEVER persisted anywhere (only its SHA-256 hash,
// see EmailCodeStrategy.prepare()) — the only way a test can learn what
// code to submit is by intercepting the send itself. support/app.ts
// overrides MailService with FakeMailService for exactly this reason; this
// suite retrieves the SAME instance the app is using via
// app.get(MailService) — overrideProvider(MailService).useValue(fake)
// swaps what the MailService TOKEN resolves to; it does NOT additionally
// register FakeMailService as its own separate token, so the lookup here
// must be keyed by the original token, not the fake's own class (confirmed
// by a real "Nest could not find FakeMailService element" failure when
// this was tried the other way).
describe('email code (OTP) sign-in (e2e)', () => {
  let app: INestApplication;
  let fakeMail: FakeMailService;
  let env: SeededEnvironment;

  beforeAll(async () => {
    app = await createTestApp();
    fakeMail = app.get(MailService) as unknown as FakeMailService;
  });

  afterAll(async () => {
    await app.close();
    await closeFixturePool();
    await closeCleanupPool();
  });

  beforeEach(async () => {
    env = await seedEnvironment();
    fakeMail.clear();
  });

  afterEach(async () => {
    await cleanPlatformData(env.environmentId);
    await deleteEnvironment(env);
  });

  const password = 'correct horse battery staple 1';
  const host = () => `${env.slug}.stack.shipstack.development`;

  async function createAccount(email: string): Promise<void> {
    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/client/sign_ups')
      .set('Host', host())
      .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
    if (res.body.status !== 'COMPLETE') {
      throw new Error(`createAccount fixture failed: ${JSON.stringify(res.body)}`);
    }
  }

  it('signs in via the full three-step OTP flow, using the real code captured from the fake mailer', async () => {
    const email = uniqueEmail('e2e-otp');
    await createAccount(email);

    const agent = request.agent(app.getHttpServer());

    const created = await agent
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', host())
      .send({ identifier: email });

    expect(created.status).toBe(201);
    expect(created.body.status).toBe('NEEDS_FIRST_FACTOR');

    const prepared = await agent
      .post(`/api/v1/auth/client/sign_ins/${created.body.id}/prepare_first_factor`)
      .set('Host', host())
      .send({ strategy: 'EMAIL_CODE' });

    expect(prepared.status).toBe(201);

    const code = fakeMail.lastCodeFor(email);
    expect(code).toMatch(/^\d{6}$/);

    const attempted = await agent
      .post(`/api/v1/auth/client/sign_ins/${created.body.id}/attempt_first_factor`)
      .set('Host', host())
      .send({ input: { code } });

    expect(attempted.status).toBe(201);
    expect(attempted.body.status).toBe('COMPLETE');

    const reloaded = await agent
      .get(`/api/v1/auth/client/sign_ins/${created.body.id}`)
      .set('Host', host());

    expect(reloaded.status).toBe(200);
    expect(reloaded.body.accessToken).toEqual(expect.any(String));

    const verified = await request(app.getHttpServer())
      .post('/api/v1/auth/verify')
      .set('Host', host())
      .auth(env.publishableKey, env.secretKey)
      .send({ accessToken: reloaded.body.accessToken });

    expect(verified.status).toBe(201);
    expect(verified.body.valid).toBe(true);
  });

  it('prepare_first_factor for an identifier with no account fails immediately (no code is ever sent)', async () => {
    const agent = request.agent(app.getHttpServer());

    const created = await agent
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', host())
      .send({ identifier: 'no-such-account@example.com' });

    const prepared = await agent
      .post(`/api/v1/auth/client/sign_ins/${created.body.id}/prepare_first_factor`)
      .set('Host', host())
      .send({ strategy: 'EMAIL_CODE' });

    // BadRequestException thrown synchronously from prepare() (see
    // EmailCodeStrategy.prepare() — "No account found for this identifier")
    // — this one strategy step DOES throw rather than returning a
    // still-pending/failed outcome, unlike attempt()'s own wrong-code
    // handling below.
    expect(prepared.status).toBe(400);
    expect(fakeMail.verificationCodes).toHaveLength(0);
  });

  it('a wrong code is still-pending (retriable), not an outright failure', async () => {
    const email = uniqueEmail('e2e-otp');
    await createAccount(email);

    const agent = request.agent(app.getHttpServer());
    const created = await agent
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', host())
      .send({ identifier: email });
    await agent
      .post(`/api/v1/auth/client/sign_ins/${created.body.id}/prepare_first_factor`)
      .set('Host', host())
      .send({ strategy: 'EMAIL_CODE' });

    const wrongAttempt = await agent
      .post(`/api/v1/auth/client/sign_ins/${created.body.id}/attempt_first_factor`)
      .set('Host', host())
      .send({ input: { code: '000000' } });

    expect(wrongAttempt.status).toBe(201);
    // still-pending, not failed — see AttemptsService.applyOutcome and
    // EmailCodeStrategy.attempt()'s own comment on this being a deliberate
    // asymmetry vs EMAIL_PASSWORD's outright-fail behavior.
    expect(wrongAttempt.body.status).toBe('NEEDS_FIRST_FACTOR');
    expect(wrongAttempt.body.verificationAttempts).toBe(1);

    // The real code, submitted right after, still works — the attempt
    // wasn't burned by the earlier wrong guess.
    const code = fakeMail.lastCodeFor(email);
    const rightAttempt = await agent
      .post(`/api/v1/auth/client/sign_ins/${created.body.id}/attempt_first_factor`)
      .set('Host', host())
      .send({ input: { code } });

    expect(rightAttempt.status).toBe(201);
    expect(rightAttempt.body.status).toBe('COMPLETE');
  });

  it('exceeding MAX_VERIFICATION_ATTEMPTS (5) fails the attempt outright, even with the correct code', async () => {
    const email = uniqueEmail('e2e-otp');
    await createAccount(email);

    const agent = request.agent(app.getHttpServer());
    const created = await agent
      .post('/api/v1/auth/client/sign_ins')
      .set('Host', host())
      .send({ identifier: email });
    await agent
      .post(`/api/v1/auth/client/sign_ins/${created.body.id}/prepare_first_factor`)
      .set('Host', host())
      .send({ strategy: 'EMAIL_CODE' });

    for (let i = 0; i < 5; i++) {
      await agent
        .post(`/api/v1/auth/client/sign_ins/${created.body.id}/attempt_first_factor`)
        .set('Host', host())
        .send({ input: { code: '000000' } });
    }

    const code = fakeMail.lastCodeFor(email);
    const finalAttempt = await agent
      .post(`/api/v1/auth/client/sign_ins/${created.body.id}/attempt_first_factor`)
      .set('Host', host())
      .send({ input: { code } });

    expect(finalAttempt.status).toBe(201);
    expect(finalAttempt.body.status).toBe('NEEDS_FIRST_FACTOR');
    expect(finalAttempt.body.verificationStatus).toBe('FAILED');
  });
});
