import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export function createRecoveryCodes(count = 10): string[] {
  if (!Number.isInteger(count) || count < 1 || count > 20) throw new RangeError('Choose between 1 and 20 codes.');
  return Array.from({ length: count }, () => randomBytes(16).toString('hex').toUpperCase().match(/.{4}/g)!.join('-'));
}

export function normalizeRecoveryCode(code: string): string | null {
  const normalized = code.trim().replaceAll('-', '').toUpperCase();
  return /^[A-F0-9]{32}$/.test(normalized) ? normalized : null;
}

export function hashRecoveryCode(code: string): string | null {
  const normalized = normalizeRecoveryCode(code);
  return normalized ? createHash('sha256').update(normalized).digest('hex') : null;
}

/** Delete or mark the matched record consumed atomically before granting access. */
export function matchesRecoveryCode(code: string, storedHash: string): boolean {
  const candidate = hashRecoveryCode(code);
  return candidate !== null && /^[a-f0-9]{64}$/.test(storedHash)
    && timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(storedHash, 'hex'));
}
