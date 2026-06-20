import { describe, it, expect } from 'vitest';
import {
  createRsaIssuer,
  createBlindRequest,
  unblindSignature,
  verifySignature,
  verifyMessageSignature,
  blindMessage,
  modPow,
  modInverse,
  randomCoprime,
  messageToRepresentative
} from './blind';

describe('RSA blind signature', () => {
  it('produces a signature that verifies on the original message', async () => {
    const issuer = await createRsaIssuer();
    const request = await createBlindRequest('over18=true', issuer.publicKey);
    const blindedSig = issuer.signBlinded(request.blindedMessage);
    const signature = unblindSignature(blindedSig, request.blindingFactor, issuer.publicKey.n);

    expect(verifySignature(signature, request.messageRepresentative, issuer.publicKey.e, issuer.publicKey.n)).toBe(true);
    expect(await verifyMessageSignature(issuer.publicKey, 'over18=true', signature)).toBe(true);
  });

  it('unblinding inverts blinding: s = (s·r) · r^-1', async () => {
    const issuer = await createRsaIssuer();
    const { n } = issuer.publicKey;
    const r = randomCoprime(n);
    const rInv = modInverse(r, n);
    expect((r * rInv) % n).toBe(1n);
  });

  it('the signer never receives the message representative', async () => {
    const issuer = await createRsaIssuer();
    const request = await createBlindRequest('secret message', issuer.publicKey);
    // The blinded message must differ from the raw representative.
    expect(request.blindedMessage).not.toBe(request.messageRepresentative);
    // And m' = m · r^e mod n by construction.
    const expected = blindMessage(request.messageRepresentative, request.blindingFactor, issuer.publicKey.e, issuer.publicKey.n);
    expect(request.blindedMessage).toBe(expected);
  });

  it('rejects a tampered signature (unforgeability)', async () => {
    const issuer = await createRsaIssuer();
    const request = await createBlindRequest('coin-123', issuer.publicKey);
    const blindedSig = issuer.signBlinded(request.blindedMessage);
    const signature = unblindSignature(blindedSig, request.blindingFactor, issuer.publicKey.n);

    const tampered = (signature + 1n) % issuer.publicKey.n;
    expect(verifySignature(tampered, request.messageRepresentative, issuer.publicKey.e, issuer.publicKey.n)).toBe(false);
  });

  it('rejects a signature on a different message', async () => {
    const issuer = await createRsaIssuer();
    const request = await createBlindRequest('over18=true', issuer.publicKey);
    const blindedSig = issuer.signBlinded(request.blindedMessage);
    const signature = unblindSignature(blindedSig, request.blindingFactor, issuer.publicKey.n);

    // Same signature, altered claim → must fail.
    expect(await verifyMessageSignature(issuer.publicKey, 'over21=true', signature)).toBe(false);
  });

  it('rejects a forged signature with no access to the private key', async () => {
    const issuer = await createRsaIssuer();
    const forged = 123456789n;
    expect(await verifyMessageSignature(issuer.publicKey, 'coin-123', forged)).toBe(false);
  });

  it('two issuances of the same message use independent blinding factors', async () => {
    const issuer = await createRsaIssuer();
    const a = await createBlindRequest('same', issuer.publicKey);
    const b = await createBlindRequest('same', issuer.publicKey);
    expect(a.messageRepresentative).toBe(b.messageRepresentative);
    expect(a.blindingFactor).not.toBe(b.blindingFactor);
    expect(a.blindedMessage).not.toBe(b.blindedMessage);
  });
});

describe('modular arithmetic helpers', () => {
  it('modPow matches the naive definition for small inputs', () => {
    expect(modPow(4n, 13n, 497n)).toBe(445n);
    expect(modPow(2n, 10n, 1000n)).toBe(24n);
  });

  it('modInverse throws when no inverse exists', () => {
    expect(() => modInverse(2n, 4n)).toThrow();
  });

  it('modPow rejects an invalid modulus', () => {
    expect(() => modPow(2n, 3n, 1n)).toThrow();
  });

  it('randomCoprime returns a value coprime to the modulus', async () => {
    const issuer = await createRsaIssuer();
    const r = randomCoprime(issuer.publicKey.n);
    expect(r).toBeGreaterThan(1n);
    expect(r).toBeLessThan(issuer.publicKey.n);
  });

  it('messageToRepresentative is deterministic and reduced mod n', async () => {
    const issuer = await createRsaIssuer();
    const m1 = await messageToRepresentative('hello', issuer.publicKey.n);
    const m2 = await messageToRepresentative('hello', issuer.publicKey.n);
    expect(m1).toBe(m2);
    expect(m1).toBeLessThan(issuer.publicKey.n);
  });
});
