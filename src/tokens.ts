import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const tokenPattern = /^[A-Za-z0-9_-]{43}$/;

/** The returned token is a bearer secret. Persist tokenHash, never token. */
export function createOpaqueToken(): { token: string; tokenHash: string } {
  const token = randomBytes(32).toString('base64url');
  return { token, tokenHash: createHash('sha256').update(token).digest('hex') };
}

export function hashOpaqueToken(token: string): string | null {
  if (!tokenPattern.test(token) || Buffer.from(token, 'base64url').toString('base64url') !== token) return null;
  return createHash('sha256').update(token).digest('hex');
}

export function matchesOpaqueToken(token: string, storedHash: string): boolean {
  const candidate = hashOpaqueToken(token);
  return candidate !== null && /^[a-f0-9]{64}$/.test(storedHash)
    && timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(storedHash, 'hex'));
}
