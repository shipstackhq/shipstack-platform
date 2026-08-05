import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { createTestApp } from './support/app';
import { seedEnvironment, deleteEnvironment, closeFixturePool, SeededEnvironment } from './support/fixtures';
import { cleanPlatformData, closeCleanupPool } from './support/cleanup';

// Confirms the coded error envelope from
// docs/error-code-convention-task.md (`{errors: [{message, long_message,
// code}], clerk_trace_id}`) actually comes back over real HTTP, and that an
// exception NOT migrated to a code still gets the old flat shape
// (statusCode/timestamp/path/message) — the two must coexist, since
// migration is incremental across FAPI's ~77 throw sites, not a big-bang
// rewrite.
describe('coded error envelope (e2e)', () => {
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

  it('POST /api/v1/auth/client with no Host header at all returns the coded envelope (environment_unresolved)', async () => {
    const res = await request(app.getHttpServer()).post('/api/v1/auth/client').send({});

    expect(res.status).toBe(401);
    expect(res.body).toEqual({
      errors: [
        {
          message: 'Unable to resolve environment from Host header',
          long_message: 'Unable to resolve environment from Host header',
          code: 'environment_unresolved',
        },
      ],
      clerk_trace_id: expect.any(String),
    });
    // Old flat shape must NOT leak through on a coded response.
    expect(res.body.statusCode).toBeUndefined();
    expect(res.body.message).toBeUndefined();
  });

  it('POST /api/v1/auth/client with a Host header carrying an unknown slug returns the coded envelope (environment_unresolved)', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/client')
      .set('Host', 'unknown-slug.stack.shipstack.development')
      .send({});

    expect(res.status).toBe(401);
    expect(res.body.errors).toHaveLength(1);
    expect(res.body.errors[0]).toMatchObject({
      message: 'Unable to resolve environment from Host header',
      code: 'environment_unresolved',
    });
    expect(res.body.clerk_trace_id).toEqual(expect.any(String));
  });

  it('GET /api/v1/auth/client/sessions/:id with an unowned sessionId returns the coded envelope (session_not_found)', async () => {
    const agent = request.agent(app.getHttpServer());
    await agent.post('/api/v1/auth/client').set('Host', `${env.slug}.stack.shipstack.development`).send({});

    const res = await agent
      .get('/api/v1/auth/client/sessions/sess_does_not_exist')
      .set('Host', `${env.slug}.stack.shipstack.development`);

    expect(res.status).toBe(404);
    expect(res.body.errors[0]).toMatchObject({
      message: 'Session not found',
      code: 'session_not_found',
    });
  });

  it('an unmigrated validation error (invalid password-reset token) still returns the old flat shape, not the coded envelope', async () => {
    // passwordResetConfirm's BadRequestException was deliberately NOT
    // migrated (out of scope — see task doc) — this locks in that the
    // fallback path in AllExceptionsFilter still works for it, and that the
    // two shapes coexist rather than one clobbering the other.
    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/password-reset/confirm')
      .send({ token: 'not-a-real-token', newPassword: 'newpassword1' });

    expect(res.status).toBe(400);
    expect(res.body.statusCode).toBe(400);
    expect(res.body.message).toBe('Token invalid, expired, or already used');
    expect(res.body.errors).toBeUndefined();
  });
});
