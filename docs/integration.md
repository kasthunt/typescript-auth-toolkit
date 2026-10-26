# Integration contract

The library performs cryptographic operations. Your application decides who may authenticate, which factors are required, and how state changes are committed.

## Data responsibilities

| Value | Persist | Keep out of logs |
| --- | --- | --- |
| Password | Argon2id hash only | Plaintext password |
| Bearer token | Hash, purpose, subject, expiry, consumed/revoked state | Raw token |
| TOTP secret | Encrypted envelope and key version; last accepted step separately | Secret, provisioning URI, OTP |
| Recovery code | Hash and consumed state | Raw code |
| Encryption key | External key-management storage | Key bytes |

Random-token and recovery-code hashes are not interchangeable with password hashes. Their sources have substantially more entropy than human-chosen passwords.

## TOTP enrollment

1. Reauthenticate the account owner before creating or replacing a factor.
2. Generate a secret and encrypt it using the account's stable context.
3. Show the provisioning URI only to that authenticated account owner.
4. Require a valid code before marking the factor active.
5. Create recovery codes, show them once, and persist only their hashes.

## Atomic consumption

For a TOTP verification, load the active factor and last accepted step while holding the appropriate database lock. Call `findAcceptedTotpTimeStep`. Update only if the persisted step remains unchanged and the new step is greater. Grant access only after that transaction commits. Use the same transaction discipline to consume recovery codes and single-use bearer tokens.

The optional `lastAcceptedTimeStep` argument avoids accepting an already known counter, but a stale value from two concurrent reads is not a replay defense. The demo does not supply a persistent store or an authentication endpoint.

## Application controls

Applications must provide account status checks, throttling and attempt budgets, generic sign-in failures, and any policy for locked or compromised accounts. Where browser sessions are used, enforce TLS, secure cookie attributes, CSRF protection, session rotation, logout/revocation, idle expiry, and absolute expiry. These concerns depend on the application and are not implemented by this utility library.

TOTP is a shared-secret factor and is not phishing resistant. Choose factors appropriate to the application's requirements. Do not log provisioning URLs, submitted codes, bearer values, or decrypted secrets when handling failures.

## Key lifecycle

The caller supplies a 32-byte encryption key and a version label. Ciphertext is bound to both that version and the exact caller-supplied context using authenticated associated data. For rotation, select the correct protector for the stored key version, decrypt with it, then encrypt with the new key. Recover or retain older keys until existing records have been intentionally migrated.

## Input and cost bounds

The public password defaults are example library settings, not a deployment-policy export. Benchmark them under realistic concurrency before choosing resource budgets. Verification rejects hashes above the library's accepted cost bounds before invoking Argon2. Only feed trusted stored hashes to verification; untrusted users must not choose the stored hash or its cost parameters.

## Project boundary

The project has independent source files, package metadata, tests, and Git history. It includes no application database adapters, authorization rules, third-party provider setup, tenant-routing format, account records, infrastructure files, or environment credentials.
