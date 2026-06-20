import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';

const CURVE_ORDER = ed25519.CURVE.n;
const BASE = ed25519.Point.BASE;
type EdPoint = typeof BASE;

/**
 * Full transcript of a blind Schnorr signature over the Ed25519 group. Every
 * intermediate value is exposed so the UI can walk through the protocol and so
 * the math can be checked independently in tests.
 *
 * Protocol (requester = Alice, signer = S with secret x, public P = x·G):
 *   1. S picks nonce k, sends commitment R0 = k·G.
 *   2. Alice picks blinding scalars α, β and forms R' = R0 + α·G + β·P.
 *   3. Alice computes challenge c = H(R', P, m) and blinded challenge c' = c + β.
 *   4. S returns partial signature s0 = k + c'·x.
 *   5. Alice unblinds: s = s0 + α. The pair (R', s) verifies as s·G = R' + c·P.
 * The signer only ever sees (R0, c', s0) — never the message m or the final (R', s).
 */
export interface EcBlindTranscript {
  messageText: string;
  publicKeyHex: string;
  signerNonceCommitmentHex: string; // R0
  alphaHex: string;
  betaHex: string;
  blindedCommitmentHex: string; // R'
  challengeHex: string; // c
  blindedChallengeHex: string; // c'
  partialSignatureHex: string; // s0 (signer output)
  signatureRHex: string; // R' (final signature first half)
  signatureSHex: string; // s  (final signature second half)
  verified: boolean;
}

export async function runEcBlindSignatureDemo(message: string): Promise<EcBlindTranscript> {
  const signerSecret = randomScalar();
  const signerPublic = BASE.multiply(signerSecret);

  const nonce = randomScalar();
  const nonceCommitment = BASE.multiply(nonce); // R0

  const alpha = randomScalar();
  const beta = randomScalar();

  // R' = R0 + α·G + β·P
  const blindedCommitment = nonceCommitment
    .add(BASE.multiply(alpha))
    .add(signerPublic.multiply(beta));

  const challenge = hashChallenge(blindedCommitment, signerPublic, utf8(message)); // c
  const blindedChallenge = mod(challenge + beta, CURVE_ORDER); // c'

  const partialSignature = mod(nonce + blindedChallenge * signerSecret, CURVE_ORDER); // s0
  const unblindedS = mod(partialSignature + alpha, CURVE_ORDER); // s

  const verified = verifyEcBlindSignature(
    bytesToHex(blindedCommitment.toRawBytes()),
    bytesToHex(signerPublic.toRawBytes()),
    message,
    toHexScalar(unblindedS)
  );

  return {
    messageText: message,
    publicKeyHex: bytesToHex(signerPublic.toRawBytes()),
    signerNonceCommitmentHex: bytesToHex(nonceCommitment.toRawBytes()),
    alphaHex: toHexScalar(alpha),
    betaHex: toHexScalar(beta),
    blindedCommitmentHex: bytesToHex(blindedCommitment.toRawBytes()),
    challengeHex: toHexScalar(challenge),
    blindedChallengeHex: toHexScalar(blindedChallenge),
    partialSignatureHex: toHexScalar(partialSignature),
    signatureRHex: bytesToHex(blindedCommitment.toRawBytes()),
    signatureSHex: toHexScalar(unblindedS),
    verified
  };
}

/**
 * Independently verify a blind Schnorr signature (R, s) on `message` under
 * public key P: checks s·G == R + H(R, P, m)·P. Returns false for any forged or
 * tampered (R, s, m, P) — this is what powers the tamper demonstration.
 */
export function verifyEcBlindSignature(
  signatureRHex: string,
  publicKeyHex: string,
  message: string,
  signatureSHex: string
): boolean {
  let R: EdPoint;
  let P: EdPoint;
  let s: bigint;
  try {
    R = ed25519.Point.fromHex(signatureRHex);
    P = ed25519.Point.fromHex(publicKeyHex);
    s = mod(BigInt(`0x${signatureSHex}`), CURVE_ORDER);
  } catch {
    return false;
  }
  const c = hashChallenge(R, P, utf8(message));
  const left = BASE.multiply(s);
  const right = R.add(P.multiply(c));
  return left.equals(right);
}

function hashChallenge(R: EdPoint, P: EdPoint, message: Uint8Array): bigint {
  const input = concatBytes(R.toRawBytes(), P.toRawBytes(), message);
  const digest = sha512(input);
  return mod(bytesToBigInt(digest), CURVE_ORDER);
}

function randomScalar(): bigint {
  while (true) {
    const bytes = ed25519.utils.randomPrivateKey();
    const scalar = mod(bytesToBigInt(bytes), CURVE_ORDER);
    if (scalar !== 0n) {
      return scalar;
    }
  }
}

function toHexScalar(value: bigint): string {
  return value.toString(16).padStart(64, '0');
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function mod(value: bigint, modulus: bigint): bigint {
  return ((value % modulus) + modulus) % modulus;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const length = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}
