import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';

const CURVE_ORDER = ed25519.CURVE.n;
const BASE = ed25519.Point.BASE;

export interface EcBlindTranscript {
  publicKeyHex: string;
  message: string;
  signerNonceCommitmentHex: string;
  blindedChallengeHex: string;
  partialSignatureHex: string;
  unblindedSignatureHex: string;
  signatureRHex: string;
  signatureSHex: string;
  verified: boolean;
  comparison: {
    rsaSummary: string;
    ecSummary: string;
  };
}

export async function runEcBlindSignatureDemo(message: string): Promise<EcBlindTranscript> {
  const signerSecret = randomScalar();
  const signerPublic = BASE.multiply(signerSecret);

  const nonce = randomScalar();
  const nonceCommitment = BASE.multiply(nonce);

  const alpha = randomScalar();
  const beta = randomScalar();

  const blindedCommitment = nonceCommitment
    .add(BASE.multiply(alpha))
    .add(signerPublic.multiply(beta));

  const challenge = hashChallenge(blindedCommitment, signerPublic, utf8(message));
  const blindedChallenge = mod(challenge + beta, CURVE_ORDER);

  const partialSignature = mod(nonce + blindedChallenge * signerSecret, CURVE_ORDER);
  const unblindedS = mod(partialSignature + alpha, CURVE_ORDER);

  const verified = verifySchnorr(blindedCommitment, signerPublic, challenge, unblindedS);

  return {
    publicKeyHex: bytesToHex(signerPublic.toRawBytes()),
    message,
    signerNonceCommitmentHex: bytesToHex(nonceCommitment.toRawBytes()),
    blindedChallengeHex: toHexScalar(blindedChallenge),
    partialSignatureHex: toHexScalar(partialSignature),
    unblindedSignatureHex: `${bytesToHex(blindedCommitment.toRawBytes())}:${toHexScalar(unblindedS)}`,
    signatureRHex: bytesToHex(blindedCommitment.toRawBytes()),
    signatureSHex: toHexScalar(unblindedS),
    verified,
    comparison: {
      rsaSummary: 'RSA blind signatures require large 2048-bit modulus arithmetic and expensive modular exponentiation.',
      ecSummary: 'Ed25519 blind Schnorr uses 32-byte keys and fast curve-scalar multiplication for smaller payloads.'
    }
  };
}

function verifySchnorr(R: ed25519.Point, P: ed25519.Point, e: bigint, s: bigint): boolean {
  const left = BASE.multiply(s);
  const right = R.add(P.multiply(e));
  return left.equals(right);
}

function hashChallenge(R: ed25519.Point, P: ed25519.Point, message: Uint8Array): bigint {
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
