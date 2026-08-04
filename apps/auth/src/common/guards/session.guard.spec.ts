import { HttpStatus, UnauthorizedException } from '@nestjs/common';
import { sign as signJwt } from 'jsonwebtoken';
import { SessionGuard } from './session.guard';
import { BackendProxyDetector } from './backend-proxy-detector';
import { CLIENT_COOKIE } from '@/common/client-cookie';

function mockContext(request: any) {
  return {
    switchToHttp: () => ({ getRequest: () => request }),
  } as any;
}

describe('SessionGuard', () => {
  const environment = { id: 'env_1', publishableKey: 'pk_test_1', status: 'ACTIVE' };
  let console_: { environment: { findUnique: jest.Mock }; $queryRaw: jest.Mock };
  let clientResolver: { resolveClient: jest.Mock };
  let identityToken: { verifyAccessToken: jest.Mock };
  let guard: SessionGuard;

  const OLD_ENV = process.env.CLIENT_COOKIE_SECRET;
  beforeAll(() => {
    process.env.CLIENT_COOKIE_SECRET = 'test-secret';
  });
  afterAll(() => {
    process.env.CLIENT_COOKIE_SECRET = OLD_ENV;
  });

  function cookieFor(clientId: string, clientToken: string) {
    return signJwt({ id: clientId, rotating_token: clientToken }, process.env.CLIENT_COOKIE_SECRET!, {
      algorithm: 'HS256',
    });
  }

  beforeEach(() => {
    console_ = { environment: { findUnique: jest.fn().mockResolvedValue(environment) }, $queryRaw: jest.fn() };
    clientResolver = { resolveClient: jest.fn() };
    identityToken = { verifyAccessToken: jest.fn() };
    guard = new SessionGuard(console_ as any, new BackendProxyDetector(console_ as any), clientResolver as any, identityToken as any);
  });

  it('attaches req.client for a valid __client cookie', async () => {
    const client = { id: 'client_1', environmentId: 'env_1', revokedAt: null };
    clientResolver.resolveClient.mockResolvedValue(client);

    const request: any = {
      body: {},
      query: {},
      cookies: { [CLIENT_COOKIE]: cookieFor('client_1', 'tok_1') },
      headers: { host: 'my-slug.stack.shipstack.development' },
    };

    const result = await guard.canActivate(mockContext(request));

    expect(result).toBe(true);
    expect(request.client).toEqual(client);
    expect(clientResolver.resolveClient).toHaveBeenCalledWith('client_1', 'tok_1', 'env_1');
  });

  it('falls back to body clientId/clientToken when no cookie is present', async () => {
    const client = { id: 'client_2', environmentId: 'env_1', revokedAt: null };
    clientResolver.resolveClient.mockResolvedValue(client);

    const request: any = {
      body: { clientId: 'client_2', clientToken: 'tok_2' },
      query: {},
      cookies: {},
      headers: { host: 'my-slug.stack.shipstack.development' },
    };

    await guard.canActivate(mockContext(request));
    expect(clientResolver.resolveClient).toHaveBeenCalledWith('client_2', 'tok_2', 'env_1');
  });

  it('rejects when there is no client cookie and no body client credentials', async () => {
    const request: any = { body: {}, query: {}, cookies: {}, headers: { host: 'my-slug.stack.shipstack.development' } };
    await expect(guard.canActivate(mockContext(request))).rejects.toThrow(
      expect.objectContaining({ status: HttpStatus.UNAUTHORIZED }),
    );
    expect(clientResolver.resolveClient).not.toHaveBeenCalled();
  });

  it('propagates rejection when the client is revoked', async () => {
    clientResolver.resolveClient.mockRejectedValue(new UnauthorizedException('Client revoked'));
    const request: any = {
      body: {},
      query: {},
      cookies: { [CLIENT_COOKIE]: cookieFor('client_1', 'tok_1') },
      headers: { host: 'my-slug.stack.shipstack.development' },
    };
    await expect(guard.canActivate(mockContext(request))).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('propagates rejection when the client is expired', async () => {
    clientResolver.resolveClient.mockRejectedValue(new UnauthorizedException('Client expired'));
    const request: any = {
      body: {},
      query: {},
      cookies: { [CLIENT_COOKIE]: cookieFor('client_1', 'tok_1') },
      headers: { host: 'my-slug.stack.shipstack.development' },
    };
    await expect(guard.canActivate(mockContext(request))).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('propagates rejection on token mismatch/replay detection', async () => {
    clientResolver.resolveClient.mockRejectedValue(new UnauthorizedException('Token reuse detected'));
    const request: any = {
      body: {},
      query: {},
      cookies: { [CLIENT_COOKIE]: cookieFor('client_1', 'stale_tok') },
      headers: { host: 'my-slug.stack.shipstack.development' },
    };
    await expect(guard.canActivate(mockContext(request))).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('best-effort attaches req.identity when a valid __session token is present', async () => {
    const client = { id: 'client_1', environmentId: 'env_1', revokedAt: null };
    clientResolver.resolveClient.mockResolvedValue(client);
    identityToken.verifyAccessToken.mockResolvedValue({ sub: 'identity_1' });

    const request: any = {
      body: {},
      query: {},
      cookies: { [CLIENT_COOKIE]: cookieFor('client_1', 'tok_1'), __session: 'some.jwt.token' },
      headers: { host: 'my-slug.stack.shipstack.development' },
    };

    await guard.canActivate(mockContext(request));
    expect(request.identity).toEqual({ sub: 'identity_1' });
  });

  it('does not fail the request when __session verification fails (deferred enforcement)', async () => {
    const client = { id: 'client_1', environmentId: 'env_1', revokedAt: null };
    clientResolver.resolveClient.mockResolvedValue(client);
    identityToken.verifyAccessToken.mockResolvedValue(null);

    const request: any = {
      body: {},
      query: {},
      cookies: { [CLIENT_COOKIE]: cookieFor('client_1', 'tok_1'), __session: 'bad.jwt.token' },
      headers: { host: 'my-slug.stack.shipstack.development' },
    };

    const result = await guard.canActivate(mockContext(request));
    expect(result).toBe(true);
    expect(request.identity).toBeUndefined();
  });
});
