import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export type ProtectedSecret = { ciphertext: string; keyVersion: string };

/** Caller owns key storage/rotation. Context binds ciphertext to its intended record. */
export class AesGcmSecretProtector {
  private readonly key: Buffer;
  public constructor(key: Uint8Array, private readonly keyVersion = 'v1') {
    if (key.length !== 32) throw new RangeError('AES-256-GCM requires a 32-byte key.');
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(keyVersion)) throw new Error('Invalid key version.');
    this.key = Buffer.from(key);
  }

  private aad(context: string): Buffer {
    if (!context || Buffer.byteLength(context, 'utf8') > 1024) throw new Error('A non-empty record context is required.');
    return Buffer.from(JSON.stringify(['auth-toolkit-secret', this.keyVersion, context]));
  }

  public protect(secret: string, context: string): ProtectedSecret {
    if (!secret || Buffer.byteLength(secret, 'utf8') > 1024) throw new RangeError('Secret must contain 1–1024 UTF-8 bytes.');
    const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', this.key, nonce);
    cipher.setAAD(this.aad(context));
    const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
    return { ciphertext: [nonce, cipher.getAuthTag(), encrypted].map(value => value.toString('base64url')).join('.'), keyVersion: this.keyVersion };
  }

  public reveal(value: ProtectedSecret, context: string): string {
    if (value.keyVersion !== this.keyVersion) throw new Error('The required key version is unavailable.');
    const fields = value.ciphertext.split('.');
    if (fields.length !== 3 || value.ciphertext.length > 2048 || fields.some(field => !/^[A-Za-z0-9_-]+$/.test(field))) throw new Error('Invalid encrypted secret.');
    const [nonce, tag, ciphertext] = fields.map(field => Buffer.from(field, 'base64url'));
    if (nonce!.length !== 12 || tag!.length !== 16 || !ciphertext!.length) throw new Error('Invalid encrypted secret.');
    const decipher = createDecipheriv('aes-256-gcm', this.key, nonce!);
    decipher.setAAD(this.aad(context));
    decipher.setAuthTag(tag!);
    return Buffer.concat([decipher.update(ciphertext!), decipher.final()]).toString('utf8');
  }
}
