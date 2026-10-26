import argon2 from 'argon2';
import { describe, expect, it } from 'vitest';
import { hashPassword, verifyPassword, needsPasswordRehash } from '../src/index.js';

describe('Argon2id password utilities', () => {
  it('hashes with independent salts and verifies the original password', async () => {
    const password = 'synthetic password used only in tests';
    const first = await hashPassword(password), second = await hashPassword(password);
    expect(first).toMatch(/^\$argon2id\$v=19\$/);
    expect(new Set(first.split('$')[3]!.split(','))).toEqual(new Set(['m=65536', 't=3', 'p=1']));
    expect(first).not.toBe(second); expect(first).not.toContain(password);
    expect(await verifyPassword(first, password)).toBe(true);
    expect(await verifyPassword(first, 'wrong password')).toBe(false);
    expect(needsPasswordRehash(first)).toBe(false);
  });
  it('preserves whitespace and Unicode exactly', async () => {
    const hash = await hashPassword('  café 🔐  ');
    expect(await verifyPassword(hash, '  café 🔐  ')).toBe(true);
    expect(await verifyPassword(hash, 'café 🔐')).toBe(false);
    expect(await verifyPassword(hash, '  cafe\u0301 🔐  ')).toBe(false);
  });
  it.each(['', 'x'.repeat(1025), '🔐'.repeat(257)])('rejects empty or oversized inputs', value => expect(() => hashPassword(value)).toThrow(RangeError));
  it('bounds byte length during verification too', async () => {
    const hash = await hashPassword('example');
    expect(await verifyPassword(hash, '')).toBe(false);
    expect(await verifyPassword(hash, 'x'.repeat(1025))).toBe(false);
  });
  it.each(['', 'plaintext', '$argon2i$v=19$m=65536,t=3,p=1$YWJjZGVmZ2hpamts$YWJjZGVmZ2hpamts', 'x'.repeat(513), '$argon2id$v=19$m=999999,t=3,p=1$YWJjZGVmZ2hpamts$YWJjZGVmZ2hpamts', '$argon2id$v=19$m=65536,m=3,p=1$YWJjZGVmZ2hpamts$YWJjZGVmZ2hpamts'])('fails closed for unsupported hashes and excessive cost', async hash => {
    expect(await verifyPassword(hash, 'example')).toBe(false); expect(needsPasswordRehash(hash)).toBe(true);
  });
  it('detects older accepted cost settings', async () => {
    const hash = await argon2.hash('synthetic', { type: argon2.argon2id, memoryCost: 8192, timeCost: 1, parallelism: 1 });
    expect(await verifyPassword(hash, 'synthetic')).toBe(true); expect(needsPasswordRehash(hash)).toBe(true);
  });
  it('handles corrupt encoded hash values', async () => {
    const hash = '$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAA';
    expect(await verifyPassword(hash, 'synthetic')).toBe(false);
  });
});
