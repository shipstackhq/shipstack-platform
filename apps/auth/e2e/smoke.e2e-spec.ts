import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { createTestApp } from './support/app';
import { seedEnvironment, deleteEnvironment, closeFixturePool, SeededEnvironment } from './support/fixtures';
import { cleanPlatformData, closeCleanupPool } from './support/cleanup';

// Proves the harness itself works end to end — real app bootstrap, real
// Postgres (shipstack_test), a real seeded Environment, a real HTTP request
// via supertest. No auth logic is exercised beyond "does GET /auth/client
// resolve an environment and return the expected anonymous-client shape" —
// that's deliberate: this test's only job is confirming every piece of
// infrastructure (DB connectivity, module bootstrap, guard resolution,
// fixture seeding/teardown) actually works before any real flow test is
// built on top of it.
describe('e2e harness smoke test', () => {
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

  it('GET /api/v1/auth/client resolves the seeded environment and returns an anonymous client', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/auth/client')
      .set('Host', `${env.slug}.stack.shipstack.development`);

    expect(res.status).toBe(200);
    expect(res.body.object).toBe('client');
    expect(res.body.clientId).toBeNull();
    expect(res.body.sessions).toEqual([]);
  });

  it('GET /api/v1/auth/client with a Host header carrying an unknown slug is rejected', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/auth/client')
      .set('Host', 'unknown-slug.stack.shipstack.development');

    expect(res.status).toBe(401);
    // Coded envelope (docs/error-code-convention-task.md) — see
    // errors.e2e-spec.ts for the dedicated coverage of this shape.
    expect(res.body.errors[0].code).toBe('environment_unresolved');
  });
});
