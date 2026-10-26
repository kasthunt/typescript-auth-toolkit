import { describe, expect, it } from 'vitest';
import { createRecoveryCodes, normalizeRecoveryCode, hashRecoveryCode, matchesRecoveryCode } from '../src/index.js';

describe('recovery codes', () => {
  it('creates ten independent, 128-bit codes by default', () => {
    const codes = createRecoveryCodes(); expect(codes).toHaveLength(10); expect(new Set(codes).size).toBe(10);
    codes.forEach(code => expect(code).toMatch(/^(?:[A-F0-9]{4}-){7}[A-F0-9]{4}$/));
  });
  it('normalizes display separators and casing without accepting arbitrary text', () => {
    const code = createRecoveryCodes(1)[0]!, stored = hashRecoveryCode(code)!;
    expect(normalizeRecoveryCode(` ${code.toLowerCase()} `)).toBe(code.replaceAll('-', ''));
    expect(matchesRecoveryCode(` ${code.toLowerCase()} `, stored)).toBe(true);
    expect(matchesRecoveryCode(createRecoveryCodes(1)[0]!, stored)).toBe(false);
  });
  it.each(['', '----', 'z'.repeat(32), 'A'.repeat(31), 'A'.repeat(33), 'A'.repeat(16) + ' ' + 'A'.repeat(16)])('rejects malformed recovery codes', code => {
    expect(normalizeRecoveryCode(code)).toBeNull(); expect(hashRecoveryCode(code)).toBeNull(); expect(matchesRecoveryCode(code, '0'.repeat(64))).toBe(false);
  });
  it.each([-1, 0, 21, 0.5, Infinity])('rejects invalid counts', count => expect(() => createRecoveryCodes(count)).toThrow(RangeError));
  it.each(['', 'invalid', 'a'.repeat(63), 'Z'.repeat(64)])('rejects malformed stored hashes', hash => expect(matchesRecoveryCode(createRecoveryCodes(1)[0]!, hash)).toBe(false));
});
