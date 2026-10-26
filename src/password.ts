import argon2 from 'argon2';

// Public example defaults, independent of any application's deployment policy.
const options = { type: argon2.argon2id, memoryCost: 65_536, timeCost: 3, parallelism: 1 } as const;
const validPassword = (password: string) => password.length > 0 && Buffer.byteLength(password, 'utf8') <= 1024;

function supportedHash(hash: string): boolean {
  if (hash.length > 512) return false;
  const match = /^\$argon2id\$v=19\$((?:[mtp]=\d{1,6},){2}[mtp]=\d{1,6})\$[A-Za-z0-9+/]{16,128}\$[A-Za-z0-9+/]{16,128}$/.exec(hash);
  if (!match) return false;
  const params = new Map(match[1]!.split(',').map(entry => { const [key, value] = entry.split('='); return [key, Number(value)]; }));
  if (params.size !== 3) return false;
  const memory = params.get('m')!, time = params.get('t')!, lanes = params.get('p')!;
  return memory >= 4096 && memory <= 131_072 && time >= 1 && time <= 5 && lanes >= 1 && lanes <= 4;
}

/** Hash without trimming, truncating or normalizing the supplied password. */
export function hashPassword(password: string): Promise<string> {
  if (!validPassword(password)) throw new RangeError('Password must contain 1–1024 UTF-8 bytes.');
  return argon2.hash(password, options);
}

/** Only feed stored, trusted database hashes here. Invalid inputs fail closed. */
export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  if (!validPassword(password) || !supportedHash(hash)) return false;
  try { return await argon2.verify(hash, password); } catch { return false; }
}

export function needsPasswordRehash(hash: string): boolean {
  if (!supportedHash(hash)) return true;
  try { return argon2.needsRehash(hash, options); } catch { return true; }
}
