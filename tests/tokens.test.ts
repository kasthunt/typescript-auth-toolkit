import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createOpaqueToken, hashOpaqueToken, matchesOpaqueToken } from '../src/index.js';

describe('opaque bearer tokens', () => {
  it('creates independent 256-bit values and storage hashes', () => {
    const tokens = Array.from({ length: 100 }, createOpaqueToken);
    expect(new Set(tokens.map(value => value.token)).size).toBe(100);
    for (const { token, tokenHash } of tokens) {
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/); expect(Buffer.from(token, 'base64url')).toHaveLength(32);
      expect(tokenHash).toBe(createHash('sha256').update(token).digest('hex'));
      expect(hashOpaqueToken(token)).toBe(tokenHash); expect(matchesOpaqueToken(token, tokenHash)).toBe(true);
    }
  });
  it('rejects the wrong token without treating hashes as bearer tokens', () => {
    const first = createOpaqueToken(), second = createOpaqueToken();
    expect(matchesOpaqueToken(second.token, first.tokenHash)).toBe(false);
    expect(matchesOpaqueToken(first.tokenHash, first.tokenHash)).toBe(false);
  });
  it.each(['', 'short', 'A'.repeat(42), 'A'.repeat(44), 'A'.repeat(42) + '!', 'A'.repeat(42) + 'B'])('rejects malformed or non-canonical tokens', token => {
    expect(hashOpaqueToken(token)).toBeNull(); expect(matchesOpaqueToken(token, '0'.repeat(64))).toBe(false);
  });
  it.each(['', 'invalid', '0'.repeat(63), 'G'.repeat(64)])('rejects malformed stored hashes', hash => expect(matchesOpaqueToken(createOpaqueToken().token, hash)).toBe(false));
});
