import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { createTestApp } from './support/app';
import { seedEnvironment, deleteEnvironment, closeFixturePool, SeededEnvironment } from './support/fixtures';
import { cleanPlatformData, closeCleanupPool } from './support/cleanup';
import { uniqueEmail } from './support/email';
import { FakeMailService } from './support/fake-mail.service';
import { MailService } from '../src/core/mail/mail.service';

// Email verification (signup -> verify link -> resend) and forgot/reset
// password. All three rely on FakeMailService (see support/fake-mail.service.ts)
// to capture the plaintext token a real email would carry — same rationale
// as auth-email-code.e2e-spec.ts: AuthService.sendVerificationEmail/
// passwordResetRequest hash the token before persisting it
// (VerificationToken.tokenHash / ResetToken.tokenHash), so the plaintext
// only ever exists in the mail call itself.
//
// requireEmailVerification is a real, per-Environment, developer-facing
// setting (console-api's ProjectsController.updateEmailSettings) — the
// fixture defaults it to false (matching every other e2e suite's
// environment), so tests that need it on pass
// { requireEmailVerification: true } to seedEnvironment() explicitly.
describe('email verification + forgot/reset password (e2e)', () => {
  let app: INestApplication;
  let fakeMail: FakeMailService;

  beforeAll(async () => {
    app = await createTestApp();
    fakeMail = app.get(MailService) as unknown as FakeMailService;
  });

  afterAll(async () => {
    await app.close();
    await closeFixturePool();
    await closeCleanupPool();
  });

  beforeEach(() => {
    fakeMail.clear();
  });

  const password = 'correct horse battery staple 1';

  describe('sign-up auto-send + verify-email', () => {
    let env: SeededEnvironment;

    beforeEach(async () => {
      env = await seedEnvironment({ requireEmailVerification: true });
    });

    afterEach(async () => {
      await cleanPlatformData(env.environmentId);
      await deleteEnvironment(env);
    });

    const host = () => `${env.slug}.stack.shipstack.development`;

    it('sign-up with requireEmailVerification=true sends a verification email automatically, and blocks sign-in until verified', async () => {
      const email = uniqueEmail('e2e-verify');

      const signUp = await request(app.getHttpServer())
        .post('/api/v1/auth/client/sign_ups')
        .set('Host', host())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

      expect(signUp.status).toBe(201);
      // No session yet — pending-verification, not COMPLETE (see
      // EmailPasswordSignUpStrategy.attempt()'s pending-verification branch).
      expect(signUp.body.status).toBe('NEEDS_FIRST_FACTOR');
      expect(signUp.body.verificationStatus).toBe('VERIFIED'); // see applyOutcome's own note: this field name is about the ATTEMPT step resolving, not email verification
      expect(signUp.body.identityId).toEqual(expect.any(String));

      // The auto-send actually happened — no separate resend-verification
      // call was needed.
      const token = fakeMail.lastVerificationTokenFor(email);
      expect(token).toEqual(expect.any(String));

      // Sign-in is blocked while unverified — AuthService.verifyPasswordCredential
      // throws ForbiddenException('Email not verified'), but
      // EmailPasswordStrategy.attempt() CATCHES that (same as it catches a
      // wrong password, confirmed earlier in auth-email-password.e2e-spec.ts)
      // and reports it as a failed OUTCOME, not an HTTP error — 201 with
      // status:NEEDS_FIRST_FACTOR / verificationStatus:FAILED, never a 403.
      // Confirmed by hand via a throwaway debug spec before asserting this.
      const blockedSignIn = await request(app.getHttpServer())
        .post('/api/v1/auth/client/sign_ins')
        .set('Host', host())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
      expect(blockedSignIn.status).toBe(201);
      expect(blockedSignIn.body.status).toBe('NEEDS_FIRST_FACTOR');
      expect(blockedSignIn.body.verificationStatus).toBe('FAILED');
      expect(blockedSignIn.body.identityId).toBeNull();

      // Verify with the real token.
      const verify = await request(app.getHttpServer())
        .post('/api/v1/auth/verify-email')
        .send({ token });
      expect(verify.status).toBe(201);
      expect(verify.body.ok).toBe(true);

      // Sign-in now succeeds.
      const signIn = await request(app.getHttpServer())
        .post('/api/v1/auth/client/sign_ins')
        .set('Host', host())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
      expect(signIn.status).toBe(201);
      expect(signIn.body.status).toBe('COMPLETE');
    });

    it('a used verification token cannot be reused', async () => {
      const email = uniqueEmail('e2e-verify');
      await request(app.getHttpServer())
        .post('/api/v1/auth/client/sign_ups')
        .set('Host', host())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

      const token = fakeMail.lastVerificationTokenFor(email);
      const first = await request(app.getHttpServer()).post('/api/v1/auth/verify-email').send({ token });
      expect(first.status).toBe(201);

      const second = await request(app.getHttpServer()).post('/api/v1/auth/verify-email').send({ token });
      expect(second.status).toBe(400);
    });

    it('an unknown/garbage verification token is rejected', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/auth/verify-email')
        .send({ token: 'not-a-real-token' });
      expect(res.status).toBe(400);
    });

    it('resend-verification sends a fresh email for an unverified identity, and is silently a no-op for an unknown or already-verified one (enumeration-safe)', async () => {
      const email = uniqueEmail('e2e-verify');
      await request(app.getHttpServer())
        .post('/api/v1/auth/client/sign_ups')
        .set('Host', host())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

      fakeMail.clear(); // discard the auto-send from sign-up itself

      const resend = await request(app.getHttpServer())
        .post('/api/v1/auth/resend-verification')
        .set('Host', host())
        .send({ email });
      expect(resend.status).toBe(201);
      expect(resend.body.ok).toBe(true);
      const token = fakeMail.lastVerificationTokenFor(email);
      expect(token).toEqual(expect.any(String));

      // Unknown email — still {ok:true}, no email sent, no error leaking
      // whether the address exists.
      fakeMail.clear();
      const resendUnknown = await request(app.getHttpServer())
        .post('/api/v1/auth/resend-verification')
        .set('Host', host())
        .send({ email: 'no-such-account@example.com' });
      expect(resendUnknown.status).toBe(201);
      expect(resendUnknown.body.ok).toBe(true);
      expect(fakeMail.verificationEmails).toHaveLength(0);

      // Already-verified — verify it with the token captured above, then
      // confirm a further resend no-ops.
      await request(app.getHttpServer()).post('/api/v1/auth/verify-email').send({ token });
      fakeMail.clear();
      const resendVerified = await request(app.getHttpServer())
        .post('/api/v1/auth/resend-verification')
        .set('Host', host())
        .send({ email });
      expect(resendVerified.status).toBe(201);
      expect(fakeMail.verificationEmails).toHaveLength(0);
    });
  });

  describe('sign-up with requireEmailVerification=false (default) needs no verification at all', () => {
    let env: SeededEnvironment;

    beforeEach(async () => {
      env = await seedEnvironment();
    });

    afterEach(async () => {
      await cleanPlatformData(env.environmentId);
      await deleteEnvironment(env);
    });

    it('sign-up completes immediately, no verification email sent, sign-in works right away', async () => {
      const email = uniqueEmail('e2e-noverify');
      const signUp = await request(app.getHttpServer())
        .post('/api/v1/auth/client/sign_ups')
        .set('Host', `${env.slug}.stack.shipstack.development`)
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });

      expect(signUp.status).toBe(201);
      expect(signUp.body.status).toBe('COMPLETE');
      expect(fakeMail.verificationEmails).toHaveLength(0);
    });
  });

  describe('forgot password / reset password', () => {
    let env: SeededEnvironment;

    beforeEach(async () => {
      env = await seedEnvironment();
    });

    afterEach(async () => {
      await cleanPlatformData(env.environmentId);
      await deleteEnvironment(env);
    });

    const host = () => `${env.slug}.stack.shipstack.development`;

    async function createAccount(email: string): Promise<void> {
      const res = await request(app.getHttpServer())
        .post('/api/v1/auth/client/sign_ups')
        .set('Host', host())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
      if (res.body.status !== 'COMPLETE') throw new Error(`createAccount fixture failed: ${JSON.stringify(res.body)}`);
    }

    it('full forgot -> reset -> sign-in-with-new-password flow, and the old password stops working', async () => {
      const email = uniqueEmail('e2e-reset');
      await createAccount(email);

      const request1 = await request(app.getHttpServer())
        .post('/api/v1/auth/password-reset/request')
        .set('Host', host())
        .send({ email });
      expect(request1.status).toBe(201);
      expect(request1.body.ok).toBe(true);

      const token = fakeMail.lastPasswordResetTokenFor(email);
      expect(token).toEqual(expect.any(String));

      const newPassword = 'a totally different passphrase 2';
      const confirm = await request(app.getHttpServer())
        .post('/api/v1/auth/password-reset/confirm')
        .send({ token, newPassword });
      expect(confirm.status).toBe(201);
      expect(confirm.body.ok).toBe(true);

      // New password works.
      const signInNew = await request(app.getHttpServer())
        .post('/api/v1/auth/client/sign_ins')
        .set('Host', host())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password: newPassword });
      expect(signInNew.status).toBe(201);
      expect(signInNew.body.status).toBe('COMPLETE');

      // Old password no longer works — reported as a failed OUTCOME, not
      // an HTTP error (same EmailPasswordStrategy.attempt() behavior
      // already confirmed in auth-email-password.e2e-spec.ts).
      const signInOld = await request(app.getHttpServer())
        .post('/api/v1/auth/client/sign_ins')
        .set('Host', host())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
      expect(signInOld.status).toBe(201);
      expect(signInOld.body.status).toBe('NEEDS_FIRST_FACTOR');
      expect(signInOld.body.verificationStatus).toBe('FAILED');
    });

    it('resetting the password revokes every active session for that identity', async () => {
      const email = uniqueEmail('e2e-reset');
      await createAccount(email);

      const agent = request.agent(app.getHttpServer());
      const signIn = await agent
        .post('/api/v1/auth/client/sign_ins')
        .set('Host', host())
        .send({ identifier: email, strategy: 'EMAIL_PASSWORD', password });
      const reloaded = await agent
        .get(`/api/v1/auth/client/sign_ins/${signIn.body.id}`)
        .set('Host', host());
      const accessToken = reloaded.body.accessToken;

      const verifyBeforeReset = await request(app.getHttpServer())
        .post('/api/v1/auth/verify')
        .set('Host', host())
        .auth(env.publishableKey, env.secretKey)
        .send({ accessToken });
      expect(verifyBeforeReset.body.valid).toBe(true);
      const sessionId = verifyBeforeReset.body.sessionId;

      await request(app.getHttpServer()).post('/api/v1/auth/password-reset/request').set('Host', host()).send({ email });
      const token = fakeMail.lastPasswordResetTokenFor(email);
      await request(app.getHttpServer())
        .post('/api/v1/auth/password-reset/confirm')
        .send({ token, newPassword: 'a totally different passphrase 2' });

      // The session row itself is revoked server-side (AuthService.passwordResetConfirm's
      // session.updateMany(...REVOKED)) — confirmed via GET
      // /auth/client/sessions/:id rather than re-checking the (still
      // cryptographically valid until natural expiry) access token, same
      // "logout doesn't retroactively kill an in-flight token" distinction
      // already established for regular logout.
      const sessionCheck = await agent
        .get(`/api/v1/auth/client/sessions/${sessionId}`)
        .set('Host', host());
      expect(sessionCheck.status).toBe(200);
      expect(sessionCheck.body.status).toBe('REVOKED');
    });

    it('forgot-password for an unknown email is silently a no-op (enumeration-safe)', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/auth/password-reset/request')
        .set('Host', host())
        .send({ email: 'no-such-account@example.com' });

      expect(res.status).toBe(201);
      expect(res.body.ok).toBe(true);
      expect(fakeMail.passwordResets).toHaveLength(0);
    });

    it('a used or unknown reset token is rejected on confirm', async () => {
      const email = uniqueEmail('e2e-reset');
      await createAccount(email);

      await request(app.getHttpServer()).post('/api/v1/auth/password-reset/request').set('Host', host()).send({ email });
      const token = fakeMail.lastPasswordResetTokenFor(email);

      const first = await request(app.getHttpServer())
        .post('/api/v1/auth/password-reset/confirm')
        .send({ token, newPassword: 'a totally different passphrase 2' });
      expect(first.status).toBe(201);

      const reused = await request(app.getHttpServer())
        .post('/api/v1/auth/password-reset/confirm')
        .send({ token, newPassword: 'yet another passphrase 3' });
      expect(reused.status).toBe(400);

      const garbage = await request(app.getHttpServer())
        .post('/api/v1/auth/password-reset/confirm')
        .send({ token: 'not-a-real-token', newPassword: 'yet another passphrase 4' });
      expect(garbage.status).toBe(400);
    });
  });
});
