import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function encodeBase32(value: Buffer): string {
  let bits = '';
  for (const byte of value) bits += byte.toString(2).padStart(8, '0');
  let encoded = '';
  for (let index = 0; index < bits.length; index += 5) encoded += alphabet[Number.parseInt(bits.slice(index, index + 5).padEnd(5, '0'), 2)];
  return encoded;
}

function decodeBase32(value: string): Buffer {
  const normalized = value.toUpperCase().replace(/=+$/, '');
  if (value.length > 128 || !/^[A-Z2-7]+$/.test(normalized) || ![0, 2, 4, 5, 7].includes(normalized.length % 8)) throw new Error('Invalid base32 secret.');
  let bits = '';
  for (const character of normalized) bits += alphabet.indexOf(character).toString(2).padStart(5, '0');
  const bytes: number[] = [];
  let index = 0;
  for (; index + 8 <= bits.length; index += 8) bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  if (bytes.length < 16 || /1/.test(bits.slice(index))) throw new Error('Secret must encode at least 128 bits without non-zero padding.');
  return Buffer.from(bytes);
}

export function createTotpSecret(): string { return encodeBase32(randomBytes(20)); }

export function createTotpProvisioningUri(input: { secret: string; issuer: string; accountName: string }): string {
  decodeBase32(input.secret);
  if (!input.issuer.trim() || !input.accountName.trim() || input.issuer.includes(':') || input.accountName.includes(':') || input.issuer.length > 128 || input.accountName.length > 256) throw new Error('Issuer and account name must be non-empty labels without colons.');
  const query = new URLSearchParams({ secret: input.secret.toUpperCase().replace(/=+$/, ''), issuer: input.issuer, algorithm: 'SHA1', digits: '6', period: '30' });
  return `otpauth://totp/${encodeURIComponent(`${input.issuer}:${input.accountName}`)}?${query.toString()}`;
}

/** HOTP counter used by a six-digit, SHA-1, 30-second TOTP configuration. */
export function generateTotpCode(secret: string, timeStep: number): string {
  if (!Number.isSafeInteger(timeStep) || timeStep < 0) throw new RangeError('Time step must be a non-negative safe integer.');
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(timeStep));
  const digest = createHmac('sha1', decodeBase32(secret)).update(counter).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fff_ffff;
  return String(binary % 1_000_000).padStart(6, '0');
}

/** Persist the returned step with an atomic compare-and-set to prevent replay. */
export function findAcceptedTotpTimeStep(secret: string, code: string, now: Date, window = 1, lastAcceptedTimeStep = -1): number | null {
  if (!Number.isInteger(window) || window < 0 || window > 2) throw new RangeError('Window must be between zero and two steps.');
  if (!Number.isSafeInteger(lastAcceptedTimeStep) || lastAcceptedTimeStep < -1) throw new RangeError('Last accepted step is invalid.');
  const instant = now.getTime();
  if (!Number.isFinite(instant) || instant < 0) throw new RangeError('A valid non-negative timestamp is required.');
  if (!/^\d{6}$/.test(code)) return null;
  const currentStep = Math.floor(instant / 30_000);
  const candidate = Buffer.from(code);
  let accepted: number | null = null;
  for (let offset = -window; offset <= window; offset++) {
    const step = currentStep + offset;
    if (step < 0 || step <= lastAcceptedTimeStep) continue;
    if (timingSafeEqual(Buffer.from(generateTotpCode(secret, step)), candidate)) accepted = step;
  }
  return accepted;
}
