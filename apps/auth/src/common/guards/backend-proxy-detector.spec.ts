import { HttpStatus } from '@nestjs/common';
import { BackendProxyDetector } from './backend-proxy-detector';
import * as argon2 from 'argon2';

jest.mock('argon2', () => ({
  verify: jest.fn(),
}));

function basicAuthHeader(publishableKey: string, secretKey: string) {
  return `Basic ${Buffer.from(`${publishableKey}:${secretKey}`).toString('base64')}`;
}

describe('BackendProxyDetector', () => {
  let console_: { $queryRaw: jest.Mock };
  let detector: BackendProxyDetector;

  beforeEach(() => {
    jest.clearAllMocks();
    console_ = { $queryRaw: jest.fn() };
    detector = new BackendProxyDetector(console_ as any);
  });

  it('returns false (never throws) when no Authorization header is present', async () => {
    const result = await detector.detect({ headers: {} }, 'pk_test_1');
    expect(result).toBe(false);
    expect(console_.$queryRaw).not.toHaveBeenCalled();
  });

  it('returns false when the header is present but not Basic', async () => {
    const request = { headers: { authorization: 'Bearer sometoken' } };
    const result = await detector.detect(request, 'pk_test_1');
    expect(result).toBe(false);
    expect(console_.$queryRaw).not.toHaveBeenCalled();
  });

  it('returns true for a valid secretKey', async () => {
    console_.$queryRaw.mockResolvedValue([{ id: 'env_1', secret_key: 'hashed_secret' }]);
    (argon2.verify as jest.Mock).mockResolvedValue(true);

    const request = { headers: { authorization: basicAuthHeader('pk_test_1', 'sk_real_secret') } };
    const result = await detector.detect(request, 'pk_test_1');

    expect(result).toBe(true);
    expect(argon2.verify).toHaveBeenCalledWith('hashed_secret', 'sk_real_secret');
  });

  it('throws for an invalid secretKey (does not silently fall back to false)', async () => {
    console_.$queryRaw.mockResolvedValue([{ id: 'env_1', secret_key: 'hashed_secret' }]);
    (argon2.verify as jest.Mock).mockResolvedValue(false);

    const request = { headers: { authorization: basicAuthHeader('pk_test_1', 'sk_wrong') } };
    await expect(detector.detect(request, 'pk_test_1')).rejects.toThrow(
      expect.objectContaining({ status: HttpStatus.UNAUTHORIZED }),
    );
  });

  it('throws when the environment has no secretKey row at all', async () => {
    console_.$queryRaw.mockResolvedValue([]);
    const request = { headers: { authorization: basicAuthHeader('pk_test_1', 'sk_anything') } };
    await expect(detector.detect(request, 'pk_test_1')).rejects.toThrow(
      expect.objectContaining({ status: HttpStatus.UNAUTHORIZED }),
    );
  });
});
