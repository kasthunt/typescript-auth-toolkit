import { randomBytes } from 'node:crypto';
import { AesGcmSecretProtector, createOpaqueToken, createRecoveryCodes, createTotpSecret, findAcceptedTotpTimeStep, generateTotpCode, hashPassword, hashRecoveryCode, matchesOpaqueToken, matchesRecoveryCode, verifyPassword } from '../src/index.js';

// This demonstration uses ephemeral synthetic values and prints no bearer secrets.
const passwordHash = await hashPassword('synthetic demo password 🔐');
const { token, tokenHash } = createOpaqueToken();
const secret = createTotpSecret(), now = new Date();
const code = generateTotpCode(secret, Math.floor(now.getTime() / 30_000));
const acceptedStep = findAcceptedTotpTimeStep(secret, code, now);
const replayBlocked = acceptedStep !== null && findAcceptedTotpTimeStep(secret, code, now, 1, acceptedStep) === null;
const protector = new AesGcmSecretProtector(randomBytes(32), 'demo-key-v1');
const envelope = protector.protect(secret, 'synthetic-user:totp');
const recoveryCode = createRecoveryCodes(1)[0]!;

const checks = {
  passwordAccepted: await verifyPassword(passwordHash, 'synthetic demo password 🔐'),
  wrongPasswordRejected: !(await verifyPassword(passwordHash, 'wrong')),
  opaqueTokenMatched: matchesOpaqueToken(token, tokenHash),
  totpAccepted: acceptedStep !== null,
  totpReplayBlocked: replayBlocked,
  encryptedSecretRecovered: protector.reveal(envelope, 'synthetic-user:totp') === secret,
  recoveryCodeMatched: matchesRecoveryCode(recoveryCode, hashRecoveryCode(recoveryCode)!),
};
console.table(checks);
if (Object.values(checks).some(value => !value)) process.exitCode = 1;
