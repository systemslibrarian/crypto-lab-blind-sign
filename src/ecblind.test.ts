import { describe, it, expect, vi } from 'vitest';
import { runEcBlindSignatureDemo, verifyEcBlindSignature } from './ecblind';
import { ed25519 } from '@noble/curves/ed25519.js';
import { expectedTranscript, signerScalars, invalidDomainEquations } from './ecblind-vector';

describe('Schnorr blind signature over Ed25519', () => {
  it('matches the independently derived fixed transcript byte-for-byte', async () => {
    let cursor = 0;
    const originalEntropy = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
    const entropy = vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(
      function<T extends ArrayBufferView | null>(target: T): T {
      // Noble also requests 16 random bytes to blind internal multiplication.
      // Keep that protection real; only the four protocol scalar draws are fixed.
      if (target instanceof Uint8Array && target.length === 16) {
        return originalEntropy(target) as T;
      }
      const scalar = signerScalars[cursor++];
      if (scalar === undefined) throw new Error('unexpected extra entropy request');
      if (!(target instanceof Uint8Array) || target.length !== 32) {
        throw new Error('unexpected entropy shape');
      }
      const hex = scalar.toString(16).padStart(64, '0');
      target.set(Uint8Array.from(hex.match(/../g)!, (pair) => parseInt(pair, 16)));
      return target;
    });
    try {
      expect(await runEcBlindSignatureDemo(expectedTranscript.messageText)).toEqual(expectedTranscript);
      expect(cursor).toBe(4);
      expect(verifyEcBlindSignature(
        expectedTranscript.signatureRHex, expectedTranscript.publicKeyHex,
        expectedTranscript.messageText, expectedTranscript.signatureSHex
      )).toBe(true);
    } finally {
      entropy.mockRestore();
    }
  });
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

  it('rejects zero, out-of-range and noncanonical signature scalars without throwing', async () => {
    const t = await runEcBlindSignatureDemo('canonical scalar control');
    expect(t.verified).toBe(true);
    const order = ed25519.Point.Fn.ORDER;
    const aliases = [
      '0'.repeat(64),
      order.toString(16).padStart(64, '0'),
      (BigInt('0x' + t.signatureSHex) + order).toString(16).padStart(64, '0'),
      '0' + t.signatureSHex,
      '0x' + t.signatureSHex,
      'g'.repeat(64),
    ];
    for (const scalar of aliases) {
      expect(verifyEcBlindSignature(t.signatureRHex, t.publicKeyHex, t.messageText, scalar)).toBe(false);
    }
  });

  it('rejects the identity-key equation that verifies an arbitrary unsigned message', () => {
    expect(verifyEcBlindSignature(
      ed25519.Point.BASE.toHex(), ed25519.Point.ZERO.toHex(),
      'arbitrary message with no signer', '1'.padStart(64, '0')
    )).toBe(false);
  });

  it('rejects independently constructed equations with order-two and mixed-order keys', () => {
    for (const t of invalidDomainEquations) {
      // These satisfy the old equation. A random invalid signature could be
      // rejected by that equation alone and would not exercise domain checks.
      expect(verifyEcBlindSignature(
        t.signatureRHex, t.publicKeyHex, t.messageText, t.signatureSHex
      ), t.label).toBe(false);
    }
  });

  it('rejects small-order and mixed-order points while retaining a valid signer control', async () => {
    const t = await runEcBlindSignatureDemo('prime-order point control');
    const orderTwo = ed25519.Point.fromHex('ec' + 'ff'.repeat(30) + '7f', false);
    expect(orderTwo.isSmallOrder()).toBe(true);
    const mixed = ed25519.Point.BASE.add(orderTwo);
    expect(mixed.isTorsionFree()).toBe(false);
    expect(verifyEcBlindSignature(t.signatureRHex, t.publicKeyHex, t.messageText, t.signatureSHex)).toBe(true);
    for (const point of [orderTwo, mixed]) {
      expect(verifyEcBlindSignature(t.signatureRHex, point.toHex(), t.messageText, t.signatureSHex)).toBe(false);
      expect(verifyEcBlindSignature(point.toHex(), t.publicKeyHex, t.messageText, t.signatureSHex)).toBe(false);
    }
  });
});
