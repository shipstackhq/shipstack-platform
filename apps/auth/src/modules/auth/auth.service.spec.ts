import { HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';

jest.mock('argon2', () => ({
  hash: jest.fn(async (pw: string) => `hashed:${pw}`),
  verify: jest.fn(async (hash: string, pw: string) => hash === `hashed:${pw}`),
}));

function makeService() {
  const platform: any = {
    client: { create: jest.fn(), update: jest.fn(), findUnique: jest.fn() },
    session: { create: jest.fn(), update: jest.fn(), updateMany: jest.fn(), findFirst: jest.fn(), findUnique: jest.fn() },
    identity: { findUnique: jest.fn(), create: jest.fn(), findUniqueOrThrow: jest.fn(), update: jest.fn() },
    resetToken: { findUnique: jest.fn(), update: jest.fn() },
    verificationToken: { deleteMany: jest.fn(), create: jest.fn(), findUnique: jest.fn(), update: jest.fn() },
  };
  const console_: any = {
    environment: { findUniqueOrThrow: jest.fn(), findUnique: jest.fn() },
    plan: { findFirst: jest.fn() },
    $executeRawUnsafe: jest.fn(),
  };
  const identityToken: any = {
    signAccessToken: jest.fn(async () => 'signed.access.token'),
    resolveEnvironmentId: jest.fn(async () => 'env_1'),
    verifyAccessToken: jest.fn(),
  };
  const mail: any = { sendVerificationEmail: jest.fn(), sendPasswordReset: jest.fn() };

  const environment: any = { getConfig: jest.fn(), getPublicResource: jest.fn(), isEnabled: jest.fn() };

  const service = new AuthService(platform, console_, identityToken, mail, environment);
  return { service, platform, console_, identityToken, mail, environment };
}

// Shape returned by EnvironmentService.getConfig() — AuthService.getEnvConfig
// now delegates there (docs/environment-resource-task.md point 4) instead of
// querying console_.environment itself, so tests mock environment.getConfig
// directly rather than the raw Prisma call.
const ENV_CONFIG = {
  accessTokenTtl: 900,
  refreshTokenTtl: 3600,
  requireEmailVerification: false,
  password: {
    minLength: 8,
    requirements: 'letters_digits',
    preventLeakedPasswords: false,
    minPasswordStrength: null,
  },
  nameFields: { collect: false, required: false },
  allowSelfDeletion: true,
  authMethods: { emailPassword: true, google: true },
};

// Phase 9 cutover (docs/unified-attempt-architecture.md): register()/login()
// themselves were deleted along with the legacy /auth/register, /auth/login
// routes — superseded by AttemptsService/SignUpAttemptsService +
// EmailPasswordStrategy/EmailPasswordSignUpStrategy. Their shared
// credential-check/identity-creation logic (verifyPasswordCredential,
// createPasswordIdentity) was extracted in Phase 4 specifically so the new
// strategies could reuse it — no dedicated spec coverage exists for those
// two methods yet (the removed register()/login() tests above exercised
// them only indirectly); adding direct unit tests is a worthwhile follow-up,
// not done as part of this cutover.
describe('AuthService (fapi) — Phase 1 duplicated Client/Session lifecycle', () => {
  describe('logout', () => {
    it('ends only the matching session when sessionId is given', async () => {
      const { service, platform } = makeService();
      await service.logout('client_1', 'sess_1');
      expect(platform.session.updateMany).toHaveBeenCalledWith({
        where: { id: 'sess_1', clientId: 'client_1' },
        data: { status: 'ENDED' },
      });
    });

    it('ends all active sessions on the client when sessionId is omitted', async () => {
      const { service, platform } = makeService();
      await service.logout('client_1');
      expect(platform.session.updateMany).toHaveBeenCalledWith({
        where: { clientId: 'client_1', status: 'ACTIVE' },
        data: { status: 'ENDED' },
      });
    });
  });

  describe('verifyEmail', () => {
    it('rejects an invalid/expired/used token', async () => {
      const { service, platform } = makeService();
      platform.verificationToken.findUnique.mockResolvedValue(null);
      await expect(service.verifyEmail('bad-token')).rejects.toBeDefined();
    });

    it('marks the identity verified on a valid token', async () => {
      const { service, platform } = makeService();
      platform.verificationToken.findUnique.mockResolvedValue({
        id: 'vt_1', identityId: 'ident_1', expiresAt: new Date(Date.now() + 10000), usedAt: null,
      });
      platform.identity.update.mockResolvedValue({});
      platform.verificationToken.update.mockResolvedValue({});

      const result = await service.verifyEmail('good-token');
      expect(result).toEqual({ ok: true });
      expect(platform.identity.update).toHaveBeenCalledWith({ where: { id: 'ident_1' }, data: { emailVerified: true } });
    });
  });

  // ── Phase 2 additions ─────────────────────────────────────────────────────

  describe('verify', () => {
    it('rejects when the token is invalid/expired', async () => {
      const { service, identityToken } = makeService();
      identityToken.verifyAccessToken.mockResolvedValue(null);
      await expect(service.verify('bad.token', 'pk_test_1')).rejects.toThrow(expect.objectContaining({ status: HttpStatus.UNAUTHORIZED }));
    });

    it('rejects when the token issuer does not match the given publishableKey', async () => {
      const { service, identityToken } = makeService();
      identityToken.verifyAccessToken.mockResolvedValue({ sub: 'ident_1', iss: 'pk_other', sid: 'sess_1' });
      await expect(service.verify('tok', 'pk_test_1')).rejects.toThrow(expect.objectContaining({ status: HttpStatus.UNAUTHORIZED }));
    });

    it('returns shipstackId/publishableKey/sessionId/valid on a good token', async () => {
      const { service, identityToken } = makeService();
      identityToken.verifyAccessToken.mockResolvedValue({ sub: 'ident_1', iss: 'pk_test_1', sid: 'sess_1' });
      const result = await service.verify('tok', 'pk_test_1');
      expect(result).toEqual({ shipstackId: 'ident_1', publishableKey: 'pk_test_1', sessionId: 'sess_1', valid: true });
    });
  });

  describe('changePassword', () => {
    it('throws NotFoundException when the identity does not exist in this environment', async () => {
      const { service, platform } = makeService();
      platform.identity.findFirst = jest.fn().mockResolvedValue(null);
      await expect(
        service.changePassword({ shipstackId: 'ident_1', currentPassword: 'old', newPassword: 'newpassword1' }, 'env_1'),
      ).rejects.toBeDefined();
    });

    it('rejects an incorrect current password', async () => {
      const { service, platform } = makeService();
      platform.identity.findFirst = jest.fn().mockResolvedValue({ id: 'ident_1', credential: 'hashed:old' });
      await expect(
        service.changePassword({ shipstackId: 'ident_1', currentPassword: 'wrong', newPassword: 'newpassword1' }, 'env_1'),
      ).rejects.toThrow(expect.objectContaining({ status: HttpStatus.UNAUTHORIZED }));
    });

    it('updates the credential and revokes all sessions on success', async () => {
      const { service, platform, environment } = makeService();
      platform.identity.findFirst = jest.fn().mockResolvedValue({ id: 'ident_1', credential: 'hashed:old' });
      environment.getConfig.mockResolvedValue(ENV_CONFIG);
      platform.identity.update.mockResolvedValue({});
      platform.session.updateMany.mockResolvedValue({});

      const result = await service.changePassword(
        { shipstackId: 'ident_1', currentPassword: 'old', newPassword: 'newpassword1' }, 'env_1',
      );

      expect(result).toEqual({ ok: true });
      expect(platform.identity.update).toHaveBeenCalledWith({ where: { id: 'ident_1' }, data: { credential: 'hashed:newpassword1' } });
      expect(platform.session.updateMany).toHaveBeenCalledWith({ where: { identityId: 'ident_1' }, data: { status: 'REVOKED' } });
    });
  });

  describe('changePasswordSelf', () => {
    it('throws NotFoundException when the identity does not exist in this environment', async () => {
      const { service, platform } = makeService();
      platform.identity.findFirst = jest.fn().mockResolvedValue(null);
      await expect(
        service.changePasswordSelf('ident_1', 'env_1', 'old', 'newpassword1'),
      ).rejects.toBeDefined();
    });

    it('rejects an incorrect current password', async () => {
      const { service, platform } = makeService();
      platform.identity.findFirst = jest.fn().mockResolvedValue({ id: 'ident_1', credential: 'hashed:old' });
      await expect(
        service.changePasswordSelf('ident_1', 'env_1', 'wrong', 'newpassword1'),
      ).rejects.toThrow(expect.objectContaining({ status: HttpStatus.UNAUTHORIZED }));
    });

    it('updates the credential and revokes all sessions on success, using the explicit identityId (not a body-supplied one)', async () => {
      const { service, platform, environment } = makeService();
      platform.identity.findFirst = jest.fn().mockResolvedValue({ id: 'ident_1', credential: 'hashed:old' });
      environment.getConfig.mockResolvedValue(ENV_CONFIG);
      platform.identity.update.mockResolvedValue({});
      platform.session.updateMany.mockResolvedValue({});

      const result = await service.changePasswordSelf('ident_1', 'env_1', 'old', 'newpassword1');

      expect(result).toEqual({ ok: true });
      expect(platform.identity.findFirst).toHaveBeenCalledWith({ where: { id: 'ident_1', environmentId: 'env_1' } });
      expect(platform.identity.update).toHaveBeenCalledWith({ where: { id: 'ident_1' }, data: { credential: 'hashed:newpassword1' } });
      expect(platform.session.updateMany).toHaveBeenCalledWith({ where: { identityId: 'ident_1' }, data: { status: 'REVOKED' } });
    });
  });

  describe('changePassword (Tier C, delegates to changePasswordSelf)', () => {
    it('still works via the shipstackId-in-dto shape for backend-proxy callers', async () => {
      const { service, platform, environment } = makeService();
      platform.identity.findFirst = jest.fn().mockResolvedValue({ id: 'ident_1', credential: 'hashed:old' });
      environment.getConfig.mockResolvedValue(ENV_CONFIG);
      platform.identity.update.mockResolvedValue({});
      platform.session.updateMany.mockResolvedValue({});

      const result = await service.changePassword(
        { shipstackId: 'ident_1', currentPassword: 'old', newPassword: 'newpassword1' }, 'env_1',
      );

      expect(result).toEqual({ ok: true });
    });
  });

  describe('passwordResetRequest', () => {
    it('always returns {ok:true} even when no identity matches (no existence leak)', async () => {
      const { service, platform } = makeService();
      platform.identity.findUnique.mockResolvedValue(null);
      const result = await service.passwordResetRequest({ email: 'nobody@x.com' }, 'env_1');
      expect(result).toEqual({ ok: true });
    });

    it('creates a reset token and sends the email when the identity exists', async () => {
      const { service, platform, mail } = makeService();
      platform.identity.findUnique.mockResolvedValue({ id: 'ident_1', email: 'a@b.com' });
      platform.resetToken.deleteMany = jest.fn().mockResolvedValue({});
      platform.resetToken.create = jest.fn().mockResolvedValue({});

      const result = await service.passwordResetRequest({ email: 'a@b.com' }, 'env_1');
      expect(result).toEqual({ ok: true });
      expect(mail.sendPasswordReset).toHaveBeenCalledWith('a@b.com', expect.any(String));
    });
  });

  describe('logoutAll', () => {
    it('throws when the identity does not exist in this environment', async () => {
      const { service, platform } = makeService();
      platform.identity.findFirst = jest.fn().mockResolvedValue(null);
      await expect(service.logoutAll('ident_1', 'env_1')).rejects.toBeDefined();
    });

    it('revokes all active sessions for the identity', async () => {
      const { service, platform } = makeService();
      platform.identity.findFirst = jest.fn().mockResolvedValue({ id: 'ident_1' });
      platform.session.updateMany.mockResolvedValue({});
      const result = await service.logoutAll('ident_1', 'env_1');
      expect(result).toEqual({ ok: true });
      expect(platform.session.updateMany).toHaveBeenCalledWith({ where: { identityId: 'ident_1', status: 'ACTIVE' }, data: { status: 'REVOKED' } });
    });
  });

  describe('updateMe', () => {
    it('throws when the identity does not exist in this environment', async () => {
      const { service, platform } = makeService();
      platform.identity.findFirst = jest.fn().mockResolvedValue(null);
      await expect(service.updateMe('ident_1', 'env_1', { firstName: 'A' })).rejects.toBeDefined();
    });

    it('updates only the provided fields (firstName/lastName/avatar)', async () => {
      const { service, platform } = makeService();
      platform.identity.findFirst = jest.fn().mockResolvedValue({ id: 'ident_1' });
      platform.identity.update.mockResolvedValue({
        id: 'ident_1', email: 'a@b.com', firstName: 'New', lastName: 'Name', avatar: null,
      });

      const result = await service.updateMe('ident_1', 'env_1', { firstName: 'New', lastName: 'Name' });

      expect(platform.identity.update).toHaveBeenCalledWith({
        where: { id: 'ident_1' },
        data: { firstName: 'New', lastName: 'Name' },
      });
      expect(result).toEqual({ shipstackId: 'ident_1', email: 'a@b.com', firstName: 'New', lastName: 'Name', avatar: null });
    });
  });
});
