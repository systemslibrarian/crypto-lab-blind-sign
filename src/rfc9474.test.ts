import { describe, it, expect } from 'vitest';
import { modInverse } from './blind';
import {
  blind,
  blindSign,
  finalize,
  prepare,
  verify,
  runRfc9474Demo,
  createRfc9474Issuer,
  bytesToHex,
  hexToBytes,
  type Rfc9474Variant
} from './rfc9474';
import vectors from './rfc9474-vectors.json';

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

const VARIANT_KEYS: Rfc9474Variant[] = [
  'RSABSSA-SHA384-PSS-Randomized',
  'RSABSSA-SHA384-PSSZERO-Deterministic'
];

// Note: RFC 9474 §4.2 writes EMSA-PSS-ENCODE(msg, bit_len(n)), but that is
// inconsistent with the RSASSA-PSS-VERIFY it invokes in Finalize (RFC 8017
// uses modBits - 1). These official Appendix A vectors only reproduce with
// emBits = bit_len(n) - 1, which is what our implementation uses.
describe('RFC 9474 official test vectors (Appendix A)', () => {
  for (const variant of VARIANT_KEYS) {
    const v = vectors[variant];

    it(`${variant}: reproduces encoded_msg, blinded_msg, blind_sig, and sig byte-for-byte`, async () => {
      const n = bytesToBigInt(hexToBytes(v.n));
      const e = bytesToBigInt(hexToBytes(v.e));
      const d = bytesToBigInt(hexToBytes(v.d));
      const modulusLen = v.n.length / 2;
      const preparedMsg = hexToBytes(v.prepared_msg);
      const salt = hexToBytes(v.salt);
      const inv = bytesToBigInt(hexToBytes(v.inv));
      const r = modInverse(inv, n); // vectors give inv = r^-1; recover r

      const blinded = await blind({ n, e, modulusLen }, preparedMsg, variant, { r, salt });
      expect(bytesToHex(blinded.encodedMsg)).toBe(v.encoded_msg);
      expect(bytesToHex(blinded.blindedMsg)).toBe(v.blinded_msg);
      expect(blinded.inv).toBe(inv);

      const blindSigBytes = blindSign(blinded.blindedMsg, { n, e, d, modulusLen });
      expect(bytesToHex(blindSigBytes)).toBe(v.blind_sig);

      const sig = finalize(blindSigBytes, inv, n, modulusLen);
      expect(bytesToHex(sig)).toBe(v.sig);
    });
  }
});

describe('RFC 9474 prepare', () => {
  it('randomized variant prepends a 32-byte prefix', () => {
    const msg = new TextEncoder().encode('hello');
    const { inputMsg, prefix } = prepare(msg, 'RSABSSA-SHA384-PSS-Randomized');
    expect(prefix.length).toBe(32);
    expect(inputMsg.length).toBe(32 + msg.length);
  });

  it('deterministic variant leaves the message unchanged', () => {
    const msg = new TextEncoder().encode('hello');
    const { inputMsg, prefix } = prepare(msg, 'RSABSSA-SHA384-PSSZERO-Deterministic');
    expect(prefix.length).toBe(0);
    expect(bytesToHex(inputMsg)).toBe(bytesToHex(msg));
  });
});

describe('RFC 9474 round-trip via native WebCrypto verify', () => {
  for (const variant of VARIANT_KEYS) {
    it(`${variant}: a blind-signed message verifies with crypto.subtle.verify`, async () => {
      const t = await runRfc9474Demo(variant, 'access token request');
      expect(t.verified).toBe(true);
    });

    it(`${variant}: a tampered signature is rejected`, async () => {
      const issuer = await createRfc9474Issuer();
      const t = await runRfc9474Demo(variant, 'access token request', issuer);
      const tampered = t.signature.slice();
      tampered[tampered.length - 1] ^= 0x01;
      expect(await verify(t.publicKey, t.inputMsg, tampered, variant)).toBe(false);
    });

    it(`${variant}: a signature does not verify against a different message`, async () => {
      const t = await runRfc9474Demo(variant, 'original message');
      const other = new TextEncoder().encode('different message');
      expect(await verify(t.publicKey, other, t.signature, variant)).toBe(false);
    });
  }
});
