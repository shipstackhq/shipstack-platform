import { HttpStatus } from '@nestjs/common';
import { EnvironmentGuard } from './environment.guard';
import { BackendProxyDetector } from './backend-proxy-detector';

function mockContext(request: any) {
  return {
    switchToHttp: () => ({ getRequest: () => request }),
  } as any;
}

describe('EnvironmentGuard', () => {
  let console_: { environment: { findUnique: jest.Mock }; $queryRaw: jest.Mock };
  let guard: EnvironmentGuard;

  beforeEach(() => {
    console_ = { environment: { findUnique: jest.fn() }, $queryRaw: jest.fn() };
    guard = new EnvironmentGuard(console_ as any, new BackendProxyDetector(console_ as any));
  });

  it('attaches req.environment for a Host header that resolves to a valid, active environment', async () => {
    const environment = { id: 'env_1', publishableKey: 'pk_test_1', status: 'ACTIVE' };
    console_.environment.findUnique.mockResolvedValue(environment);

    const request: any = { body: {}, query: {}, headers: { host: 'my-slug.stack.shipstack.development' } };
    const result = await guard.canActivate(mockContext(request));

    expect(result).toBe(true);
    expect(request.environment).toEqual(environment);
    expect(console_.environment.findUnique).toHaveBeenCalledWith({ where: { slug: 'my-slug' } });
  });

  it('rejects when the Host header does not resolve to any slug', async () => {
    const request: any = { body: {}, query: {}, headers: { host: 'fapi.shipstack.development' } };
    await expect(guard.canActivate(mockContext(request))).rejects.toThrow(
      expect.objectContaining({ status: HttpStatus.UNAUTHORIZED }),
    );
    expect(console_.environment.findUnique).not.toHaveBeenCalled();
  });

  it('rejects when the Host header has no host at all', async () => {
    const request: any = { body: {}, query: {}, headers: {} };
    await expect(guard.canActivate(mockContext(request))).rejects.toThrow(
      expect.objectContaining({ status: HttpStatus.UNAUTHORIZED }),
    );
  });

  it('rejects when the resolved slug does not match any environment', async () => {
    console_.environment.findUnique.mockResolvedValue(null);
    const request: any = { body: {}, query: {}, headers: { host: 'unknown-slug.stack.shipstack.development' } };
    await expect(guard.canActivate(mockContext(request))).rejects.toThrow(
      expect.objectContaining({ status: HttpStatus.UNAUTHORIZED }),
    );
  });

  it('rejects when the resolved environment is suspended', async () => {
    console_.environment.findUnique.mockResolvedValue({ id: 'env_1', status: 'SUSPENDED' });
    const request: any = { body: {}, query: {}, headers: { host: 'my-slug.stack.shipstack.development' } };
    await expect(guard.canActivate(mockContext(request))).rejects.toThrow(
      expect.objectContaining({ status: HttpStatus.UNAUTHORIZED }),
    );
  });

  it('leaves isBackendProxy false when no Authorization header is present', async () => {
    const environment = { id: 'env_1', publishableKey: 'pk_test_1', status: 'ACTIVE' };
    console_.environment.findUnique.mockResolvedValue(environment);

    const request: any = { body: {}, query: {}, headers: { host: 'my-slug.stack.shipstack.development' } };
    await guard.canActivate(mockContext(request));

    expect(request.isBackendProxy).toBe(false);
    expect(console_.$queryRaw).not.toHaveBeenCalled();
  });

  it('sets isBackendProxy true for a valid secretKey via Authorization: Basic, alongside Host-header resolution', async () => {
    const environment = { id: 'env_1', publishableKey: 'pk_test_1', status: 'ACTIVE' };
    console_.environment.findUnique.mockResolvedValue(environment);
    console_.$queryRaw.mockResolvedValue([{ id: 'env_1', secret_key: 'hashed_secret' }]);
    jest.spyOn(require('argon2'), 'verify').mockResolvedValue(true);

    const auth = `Basic ${Buffer.from('pk_test_1:sk_real_secret').toString('base64')}`;
    const request: any = {
      body: {},
      query: {},
      headers: { host: 'my-slug.stack.shipstack.development', authorization: auth },
    };
    const result = await guard.canActivate(mockContext(request));

    expect(result).toBe(true);
    expect(request.environment).toEqual(environment);
    expect(request.isBackendProxy).toBe(true);
  });

  it('sets req.isDevBrowserRequest based on the __shipstack_db_jwt query param', async () => {
    const environment = { id: 'env_1', publishableKey: 'pk_test_1', status: 'ACTIVE' };
    console_.environment.findUnique.mockResolvedValue(environment);

    const request: any = {
      body: {},
      query: { __shipstack_db_jwt: 'dvb_123' },
      headers: { host: 'my-slug.stack.shipstack.development' },
    };
    await guard.canActivate(mockContext(request));

    expect(request.isDevBrowserRequest).toBe(true);
  });
});
