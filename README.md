# TypeScript Auth Toolkit

[![CI](https://github.com/kasthunt/typescript-auth-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/kasthunt/typescript-auth-toolkit/actions/workflows/ci.yml)

Small, typed building blocks for authentication code you can read, test, and adapt.

This project isolates reusable authentication utilities from application code. It has no framework, database, cloud account, or environment-variable requirement. The runnable example uses temporary synthetic values and never prints passwords, tokens, recovery codes, or MFA secrets.

## What is included

| Utility | Behaviour |
| --- | --- |
| Passwords | Argon2id hashing, verification, bounded accepted costs, and rehash detection |
| Opaque tokens | 256-bit random bearer values with SHA-256 storage hashes |
| TOTP | Authenticator provisioning, six-digit codes, bounded clock skew, and replay-counter handling |
| Recovery codes | Random 128-bit codes, display normalization, and hash comparison |
| Secret protection | AES-256-GCM encryption with random nonces, record-bound authenticated context, and key versions |

The toolkit leaves account policy and persistence to its caller. It does not issue login sessions, authorize users, run an HTTP server, or connect to an identity provider. Passing the tests is not a security certification.

## Run it

Use Node.js 22 or 24 and npm. Argon2 uses native bindings; a supported prebuilt binary or the upstream build prerequisites are required.

```sh
git clone https://github.com/kasthunt/typescript-auth-toolkit.git
cd typescript-auth-toolkit
npm ci
npm run check
```

`check` runs typechecking, lint, tests, compilation, and the demo. `npm run demo` prints seven successful checks using fresh in-memory values. No services need to be started.

```text
passwordAccepted          true
wrongPasswordRejected     true
opaqueTokenMatched        true
totpAccepted              true
totpReplayBlocked         true
encryptedSecretRecovered  true
recoveryCodeMatched       true
```

## Examples

The package is available from this repository; no npm registry release is implied. After `npm run build`, import from `./dist/index.js` when trying these snippets in the repository root.

### Hash a password

```ts
import { hashPassword, verifyPassword, needsPasswordRehash } from './dist/index.js';

const storedHash = await hashPassword('synthetic example password');
const accepted = await verifyPassword(storedHash, 'synthetic example password');
const upgrade = needsPasswordRehash(storedHash);
```

Passwords are preserved exactly, including whitespace and Unicode. The 1–1024 UTF-8 byte limit bounds input size; your application should enforce its own password-selection policy. Public example costs are 64 MiB, three iterations, and one lane. Verification accepts only bounded Argon2id encodings. Use hashes from trusted storage, not an HTTP-supplied hash field.

### Create a bearer token

```ts
import { createOpaqueToken, matchesOpaqueToken } from './dist/index.js';

const { token, tokenHash } = createOpaqueToken();
// Deliver token once through your application's secure channel.
// Persist tokenHash with its purpose, subject, expiry, and consumption state.
const accepted = matchesOpaqueToken(token, tokenHash);
```

The token contains no user or tenant identifier. Matching a hash alone does not enforce expiry, authorization, revocation, or one-time use. Those checks belong in a transaction around the stored record.

### Verify a TOTP code

```ts
import { createTotpSecret, createTotpProvisioningUri, findAcceptedTotpTimeStep } from './dist/index.js';

const secret = createTotpSecret();
const provisioningUri = createTotpProvisioningUri({
  secret,
  issuer: 'Toolkit Demo',
  accountName: 'developer@example.test',
});
// Display the URI/QR only during authorized enrollment. Do not log it.

// Inside your application's verification transaction:
const acceptedStep = findAcceptedTotpTimeStep(secret, '123456', new Date(), 1, -1);
// null means rejected. Otherwise atomically persist acceptedStep before granting access.
```

TOTP uses HMAC-SHA-1, six digits, and a 30-second step. The default acceptance window is one adjacent step in each direction. Set the final argument to the persisted last accepted step; `-1` means none has been accepted. A database compare-and-set or equivalent lock is necessary so two concurrent requests cannot consume the same step. A pure function cannot provide that guarantee by itself.

### Protect a stored MFA secret

```ts
import { randomBytes } from 'node:crypto';
import { AesGcmSecretProtector } from './dist/index.js';

// Ephemeral demo key. In an application, load this from your key-management system.
const protector = new AesGcmSecretProtector(randomBytes(32), 'key-v1');
const encrypted = protector.protect('synthetic secret', 'account-123:totp');
const plaintext = protector.reveal(encrypted, 'account-123:totp');
```

Keep encryption keys separate from encrypted records. Use a stable record context containing every isolation boundary your application needs. Changing the key, version, context, nonce, tag, or ciphertext prevents successful decryption. Retain access to older keys during an intentional rotation; this class holds one key version at a time.

### Store recovery codes

```ts
import { createRecoveryCodes, hashRecoveryCode, matchesRecoveryCode } from './dist/index.js';

const codes = createRecoveryCodes();
const storedHashes = codes.map(code => hashRecoveryCode(code)!);
// Show the codes once. Store their hashes with unconsumed state.
const matched = matchesRecoveryCode(codes[0]!, storedHashes[0]!);
// Atomically consume the matched record before granting recovery access.
```

SHA-256 is appropriate here because generated tokens and recovery codes have high entropy. Passwords use Argon2id instead.

## Repository layout

```text
src/                 Small public library; no application imports
tests/               Protocol vectors, invalid inputs, replay and tampering checks
examples/demo.ts     Runnable synthetic demonstration
docs/integration.md  Storage contracts and application responsibilities
.github/workflows/   Node 22/24 checks on Linux, Windows, and macOS
```

## Verification

```sh
npm run test:coverage
npm pack --dry-run
```

The test suite includes [RFC 4226 counter vectors](https://www.rfc-editor.org/rfc/rfc4226) and the six-digit SHA-1 truncation of [RFC 6238 time vectors](https://www.rfc-editor.org/rfc/rfc6238). Password hashing delegates to [node-argon2](https://github.com/ranisalt/node-argon2); encryption and randomness use Node's crypto module.

The initial version has 119 tests covering interoperability, malformed inputs, replay bounds, and encryption tampering. CI enforces coverage thresholds alongside typechecking and linting.

## Scope and contributions

This repository contains only generic authentication utilities and synthetic examples. Application-specific policies, database schemas, integrations, private configuration, and deployment history are outside its scope. See [integration notes](docs/integration.md), [security reporting](SECURITY.md), and [contribution guidance](CONTRIBUTING.md).

Licensed under [MIT](LICENSE).
