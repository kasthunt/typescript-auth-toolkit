import { describe, expect, it } from 'vitest';
import { createTotpSecret, createTotpProvisioningUri, generateTotpCode, findAcceptedTotpTimeStep } from '../src/index.js';

// Public RFC 4226/6238 test key: ASCII 12345678901234567890, encoded as base32.
const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

describe('TOTP interoperability and replay boundaries', () => {
  it.each(['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'])('matches RFC 4226 counter vector %s', (expected) => {
    const vectors = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
    expect(generateTotpCode(secret, vectors.indexOf(expected))).toBe(expected);
  });
  it.each([[59, '287082'], [1_111_111_109, '081804'], [1_111_111_111, '050471'], [1_234_567_890, '005924'], [2_000_000_000, '279037'], [20_000_000_000, '353130']] as const)('matches the six-digit truncation of RFC 6238 at %s seconds', (seconds, expected) => {
    expect(generateTotpCode(secret, Math.floor(seconds / 30))).toBe(expected);
  });
  it('creates unique 160-bit authenticator secrets', () => {
    const values = Array.from({ length: 100 }, createTotpSecret);
    expect(new Set(values).size).toBe(100);
    values.forEach(value => expect(value).toMatch(/^[A-Z2-7]{32}$/));
  });
  it('encodes provisioning labels and fixes interoperable algorithm parameters', () => {
    const uri = new URL(createTotpProvisioningUri({ secret, issuer: 'Toolkit Demo', accountName: 'developer@example.test' }));
    expect(uri.protocol).toBe('otpauth:'); expect(uri.hostname).toBe('totp');
    expect(decodeURIComponent(uri.pathname)).toBe('/Toolkit Demo:developer@example.test');
    expect(Object.fromEntries(uri.searchParams)).toEqual({ secret, issuer: 'Toolkit Demo', algorithm: 'SHA1', digits: '6', period: '30' });
  });
  it('accepts lowercase/padded base32 input', () => {
    const input = 'JBSWY3DPEHPK3PXPJBSWY3DPEA======';
    const uri = new URL(createTotpProvisioningUri({ secret: input.toLowerCase(), issuer: 'Demo', accountName: 'user' }));
    expect(uri.searchParams.get('secret')).toBe(input.replace(/=+$/, ''));
    expect(generateTotpCode(input.toLowerCase(), 10)).toBe(generateTotpCode(input, 10));
  });
  it.each(['', 'short', 'A'.repeat(129), 'A'.repeat(27) + '3', 'AAAAA!', 'A'.repeat(25)])('rejects malformed or short secret %s', value => {
    expect(() => generateTotpCode(value, 1)).toThrow();
  });
  it.each([-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])('rejects invalid counters %s', value => expect(() => generateTotpCode(secret, value)).toThrow(RangeError));
  it.each([{ issuer: '', accountName: 'user' }, { issuer: 'demo', accountName: ' ' }, { issuer: 'demo:extra', accountName: 'user' }, { issuer: 'demo', accountName: 'user:extra' }, { issuer: 'x'.repeat(129), accountName: 'user' }, { issuer: 'demo', accountName: 'x'.repeat(257) }])('rejects ambiguous or oversized provisioning labels', labels => {
    expect(() => createTotpProvisioningUri({ secret, ...labels })).toThrow();
  });
  it('allows bounded clock skew and returns the accepted counter', () => {
    const now = new Date(3_000_000);
    expect(findAcceptedTotpTimeStep(secret, generateTotpCode(secret, 100), now)).toBe(100);
    expect(findAcceptedTotpTimeStep(secret, generateTotpCode(secret, 99), now)).toBe(99);
    expect(findAcceptedTotpTimeStep(secret, generateTotpCode(secret, 101), now)).toBe(101);
    expect(findAcceptedTotpTimeStep(secret, generateTotpCode(secret, 98), now)).toBeNull();
    expect(findAcceptedTotpTimeStep(secret, generateTotpCode(secret, 99), now, 0)).toBeNull();
  });
  it('does not accept a previously consumed counter or an earlier one', () => {
    const now = new Date(3_000_000);
    expect(findAcceptedTotpTimeStep(secret, generateTotpCode(secret, 100), now, 1, 100)).toBeNull();
    expect(findAcceptedTotpTimeStep(secret, generateTotpCode(secret, 99), now, 1, 100)).toBeNull();
    expect(findAcceptedTotpTimeStep(secret, generateTotpCode(secret, 101), now, 1, 100)).toBe(101);
  });
  it('handles epoch zero without constructing a negative counter', () => expect(findAcceptedTotpTimeStep(secret, '755224', new Date(0))).toBe(0));
  it.each(['', '12345', '1234567', ' 287082', '２８７０８２', 'abcdef'])('rejects malformed code %s', code => expect(findAcceptedTotpTimeStep(secret, code, new Date(59_000))).toBeNull());
  it.each([-1, 3, 0.5, NaN])('rejects unbounded windows %s', window => expect(() => findAcceptedTotpTimeStep(secret, '287082', new Date(59_000), window)).toThrow(RangeError));
  it.each([-2, 1.5, Infinity])('rejects invalid replay bounds %s', last => expect(() => findAcceptedTotpTimeStep(secret, '287082', new Date(59_000), 1, last)).toThrow(RangeError));
  it.each([new Date(NaN), new Date(-1)])('rejects invalid times', now => expect(() => findAcceptedTotpTimeStep(secret, '287082', now)).toThrow(RangeError));
});
