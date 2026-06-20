import { describe, it, expect } from 'vitest';
import { runEcBlindSignatureDemo, verifyEcBlindSignature } from './ecblind';

describe('Schnorr blind signature over Ed25519', () => {
  it('produces a signature that verifies', async () => {
    const t = await runEcBlindSignatureDemo('blind schnorr request');
    expect(t.verified).toBe(true);
    expect(verifyEcBlindSignature(t.signatureRHex, t.publicKeyHex, t.messageText, t.signatureSHex)).toBe(true);
  });

  it('blinds the signer commitment: R0 != R\'', async () => {
    const t = await runEcBlindSignatureDemo('blind schnorr request');
    expect(t.blindedCommitmentHex).not.toBe(t.signerNonceCommitmentHex);
    // The blinded challenge handed to the signer differs from the real challenge.
    expect(t.blindedChallengeHex).not.toBe(t.challengeHex);
  });

  it('rejects a tampered signature scalar', async () => {
    const t = await runEcBlindSignatureDemo('blind schnorr request');
    const tampered = (BigInt(`0x${t.signatureSHex}`) + 1n).toString(16).padStart(64, '0');
    expect(verifyEcBlindSignature(t.signatureRHex, t.publicKeyHex, t.messageText, tampered)).toBe(false);
  });

  it('rejects a signature checked against a different message', async () => {
    const t = await runEcBlindSignatureDemo('original message');
    expect(verifyEcBlindSignature(t.signatureRHex, t.publicKeyHex, 'different message', t.signatureSHex)).toBe(false);
  });

  it('returns false for malformed inputs instead of throwing', () => {
    expect(verifyEcBlindSignature('not-hex', 'not-hex', 'm', 'zz')).toBe(false);
  });
});
