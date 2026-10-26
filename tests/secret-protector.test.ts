import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AesGcmSecretProtector } from '../src/index.js';

describe('authenticated secret encryption', () => {
  it('round-trips a secret with independent nonces and key version', () => {
    const protector = new AesGcmSecretProtector(randomBytes(32), 'key-2026');
    const first = protector.protect('synthetic-secret', 'user-1:totp'), second = protector.protect('synthetic-secret', 'user-1:totp');
    expect(first.keyVersion).toBe('key-2026'); expect(first.ciphertext).not.toContain('synthetic-secret'); expect(first.ciphertext).not.toBe(second.ciphertext);
    expect(protector.reveal(first, 'user-1:totp')).toBe('synthetic-secret');
  });
  it('does not allow ciphertext to move between account/record contexts', () => {
    const protector = new AesGcmSecretProtector(randomBytes(32));
    expect(() => protector.reveal(protector.protect('secret', 'user-1:totp'), 'user-2:totp')).toThrow();
  });
  it('rejects a different encryption key or unavailable key version', () => {
    const protector = new AesGcmSecretProtector(randomBytes(32)), value = protector.protect('secret', 'record');
    expect(() => new AesGcmSecretProtector(randomBytes(32)).reveal(value, 'record')).toThrow();
    expect(() => protector.reveal({ ...value, keyVersion: 'v2' }, 'record')).toThrow('unavailable');
  });
  it.each([0, 16, 31, 33])('rejects invalid key length %s', length => expect(() => new AesGcmSecretProtector(randomBytes(length))).toThrow(RangeError));
  it.each(['', 'spaces not allowed', 'x'.repeat(65)])('rejects invalid key versions', version => expect(() => new AesGcmSecretProtector(randomBytes(32), version)).toThrow());
  it('copies the input key so external mutation cannot change it', () => {
    const key = randomBytes(32), protector = new AesGcmSecretProtector(key), value = protector.protect('secret', 'record');
    key.fill(0); expect(protector.reveal(value, 'record')).toBe('secret');
  });
  it.each(['', 'x'.repeat(1025)])('requires bounded non-empty contexts and secrets', invalid => {
    const protector = new AesGcmSecretProtector(randomBytes(32));
    expect(() => protector.protect('secret', invalid)).toThrow(); expect(() => protector.protect(invalid, 'record')).toThrow();
  });
  it.each(['', 'a.b', 'a.b.c.d', 'a.!.c', `${'a'.repeat(2049)}.a.a`, 'YQ.YQ.YQ'])('rejects malformed encrypted envelopes', ciphertext => {
    expect(() => new AesGcmSecretProtector(randomBytes(32)).reveal({ keyVersion: 'v1', ciphertext }, 'record')).toThrow();
  });
  it.each([0, 1, 2])('detects tampering with envelope part %s', part => {
    const protector = new AesGcmSecretProtector(randomBytes(32)), value = protector.protect('secret', 'record');
    const fields = value.ciphertext.split('.'), bytes = Buffer.from(fields[part]!, 'base64url');
    bytes[0] = bytes[0]! ^ 1; fields[part] = bytes.toString('base64url');
    expect(() => protector.reveal({ ...value, ciphertext: fields.join('.') }, 'record')).toThrow();
  });
});
