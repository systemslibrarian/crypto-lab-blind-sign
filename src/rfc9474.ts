// RFC 9474 — RSA Blind Signatures.
//
// WebCrypto deliberately exposes neither the raw RSA primitive (signing an
// arbitrary integer) nor EMSA-PSS encoding as a separate step, so this module
// implements EMSA-PSS-ENCODE + MGF1 with SHA-384 and drives the bare modular
// exponentiation with BigInt. The *final* signature is a standard RSASSA-PSS
// signature, so it is verified with the browser's native `crypto.subtle.verify`
// — an independent, standards-compliant oracle.
//
// This implementation is checked byte-for-byte against the official RFC 9474
// Appendix A test vectors (see rfc9474.test.ts).

import { modPow, modInverse, randomCoprime } from './blind';

const HASH = 'SHA-384';
const HLEN = 48; // SHA-384 output length in bytes

export type Rfc9474Variant =
  | 'RSABSSA-SHA384-PSS-Randomized'
  | 'RSABSSA-SHA384-PSSZERO-Deterministic';

export interface VariantParams {
  saltLen: number; // sLen in bytes
  randomize: boolean; // prepend a 32-byte random prefix (PrepareRandomize)
}

export const VARIANTS: Record<Rfc9474Variant, VariantParams> = {
  'RSABSSA-SHA384-PSS-Randomized': { saltLen: 48, randomize: true },
  'RSABSSA-SHA384-PSSZERO-Deterministic': { saltLen: 0, randomize: false }
};

export interface Rfc9474PublicKey {
  n: bigint;
  e: bigint;
  modulusLen: number; // length in bytes of n
  cryptoKey: CryptoKey; // for native RSASSA-PSS verification
}

export interface Rfc9474SecretKey {
  n: bigint;
  e: bigint;
  d: bigint;
  modulusLen: number;
}

export interface Rfc9474Issuer {
  publicKey: Rfc9474PublicKey;
  /** BlindSign: s = (m')^d mod n, with the RFC's s^e == m' fault check. */
  blindSign(blindedMsg: Uint8Array): Uint8Array;
}

// ── EMSA-PSS (RFC 8017 §9.1.1) ────────────────────────────────
async function sha384(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest(HASH, data as BufferSource));
}

/** MGF1 mask generation function with SHA-384. */
export async function mgf1(seed: Uint8Array, maskLen: number): Promise<Uint8Array> {
  const out = new Uint8Array(maskLen);
  let offset = 0;
  let counter = 0;
  while (offset < maskLen) {
    const c = new Uint8Array(4);
    let n = counter;
    for (let i = 3; i >= 0; i--) {
      c[i] = n & 0xff;
      n >>>= 8;
    }
    const block = await sha384(concatBytes(seed, c));
    const take = Math.min(HLEN, maskLen - offset);
    out.set(block.subarray(0, take), offset);
    offset += take;
    counter++;
  }
  return out;
}

/**
 * EMSA-PSS-ENCODE. `emBits` is `bit_len(n) - 1` to match RSASSA-PSS-VERIFY
 * (RFC 8017 §8.1.2) and WebCrypto — see the note in rfc9474.test.ts about the
 * RFC 9474 text reading `bit_len(n)`.
 */
export async function emsaPssEncode(
  message: Uint8Array,
  emBits: number,
  saltLen: number,
  salt?: Uint8Array
): Promise<Uint8Array> {
  const emLen = Math.ceil(emBits / 8);
  const mHash = await sha384(message);
  if (emLen < HLEN + saltLen + 2) {
    throw new Error('encoding error: emLen too small');
  }
  const usedSalt = salt ?? randomBytes(saltLen);
  const mPrime = concatBytes(new Uint8Array(8), mHash, usedSalt); // 8 zero octets
  const h = await sha384(mPrime);
  const ps = new Uint8Array(emLen - saltLen - HLEN - 2);
  const db = concatBytes(ps, Uint8Array.of(0x01), usedSalt);
  const dbMask = await mgf1(h, emLen - HLEN - 1);
  const maskedDb = db.map((b, i) => b ^ dbMask[i]);
  // Clear the leftmost (8*emLen - emBits) bits of the leftmost octet.
  maskedDb[0] &= 0xff >> (8 * emLen - emBits);
  return concatBytes(maskedDb, h, Uint8Array.of(0xbc));
}

// ── RFC 9474 protocol functions ───────────────────────────────
export interface PreparedMessage {
  inputMsg: Uint8Array;
  prefix: Uint8Array; // empty for the deterministic variant
}

/** Prepare: identity, or prepend a 32-byte random prefix (PrepareRandomize). */
export function prepare(msg: Uint8Array, variant: Rfc9474Variant, prefix?: Uint8Array): PreparedMessage {
  if (!VARIANTS[variant].randomize) {
    return { inputMsg: msg, prefix: new Uint8Array(0) };
  }
  const p = prefix ?? randomBytes(32);
  return { inputMsg: concatBytes(p, msg), prefix: p };
}

export interface BlindResult {
  encodedMsg: Uint8Array;
  m: bigint;
  salt: Uint8Array;
  r: bigint;
  inv: bigint; // r^-1 mod n
  x: bigint; // r^e mod n
  z: bigint; // m * x mod n
  blindedMsg: Uint8Array;
}

/**
 * Blind: EMSA-PSS-encode the input message, then multiplicatively blind it.
 * `r` and `salt` may be injected for deterministic testing; otherwise random.
 */
export async function blind(
  pub: { n: bigint; e: bigint; modulusLen: number },
  inputMsg: Uint8Array,
  variant: Rfc9474Variant,
  opts?: { r?: bigint; salt?: Uint8Array }
): Promise<BlindResult> {
  const emBits = bitLength(pub.n) - 1;
  const salt = opts?.salt ?? randomBytes(VARIANTS[variant].saltLen);
  const encodedMsg = await emsaPssEncode(inputMsg, emBits, VARIANTS[variant].saltLen, salt);
  const m = bytesToBigInt(encodedMsg);
  if (gcd(m, pub.n) !== 1n) {
    throw new Error('invalid input: encoded message not coprime with n');
  }
  const r = opts?.r ?? randomCoprime(pub.n);
  const inv = modInverse(r, pub.n);
  const x = modPow(r, pub.e, pub.n);
  const z = (m * x) % pub.n;
  return { encodedMsg, m, salt, r, inv, x, z, blindedMsg: intToBytes(z, pub.modulusLen) };
}

/** BlindSign with the RFC's fault check (s^e must round-trip to m'). */
export function blindSign(blindedMsg: Uint8Array, sk: Rfc9474SecretKey): Uint8Array {
  const m = bytesToBigInt(blindedMsg);
  const s = modPow(m, sk.d, sk.n);
  if (modPow(s, sk.e, sk.n) !== m) {
    throw new Error('signing failure: fault check failed');
  }
  return intToBytes(s, sk.modulusLen);
}

/** Finalize: unblind to s = z * r^-1 mod n and return the signature bytes. */
export function finalize(blindSig: Uint8Array, inv: bigint, n: bigint, modulusLen: number): Uint8Array {
  if (blindSig.length !== modulusLen) {
    throw new Error('unexpected input size');
  }
  const z = bytesToBigInt(blindSig);
  const s = (z * inv) % n;
  return intToBytes(s, modulusLen);
}

/** Native RSASSA-PSS verification of a finalized signature. */
export async function verify(
  pub: Rfc9474PublicKey,
  inputMsg: Uint8Array,
  signature: Uint8Array,
  variant: Rfc9474Variant
): Promise<boolean> {
  return crypto.subtle.verify(
    { name: 'RSA-PSS', saltLength: VARIANTS[variant].saltLen },
    pub.cryptoKey,
    signature as BufferSource,
    inputMsg as BufferSource
  );
}

/** Create an RFC 9474 signing authority with a fresh RSA-PSS / SHA-384 keypair. */
export async function createRfc9474Issuer(modulusLength = 2048): Promise<Rfc9474Issuer> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: HASH
    },
    true,
    ['sign', 'verify']
  );

  const pub = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const priv = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  if (!pub.n || !pub.e || !priv.d) {
    throw new Error('Failed to export RSA-PSS key material');
  }

  const n = base64UrlToBigInt(pub.n);
  const e = base64UrlToBigInt(pub.e);
  const d = base64UrlToBigInt(priv.d);
  const modulusLen = modulusLength / 8;
  const sk: Rfc9474SecretKey = { n, e, d, modulusLen };

  return {
    publicKey: { n, e, modulusLen, cryptoKey: keyPair.publicKey },
    blindSign: (blindedMsg: Uint8Array): Uint8Array => blindSign(blindedMsg, sk)
  };
}

// ── Full end-to-end transcript for the UI ─────────────────────
export interface Rfc9474Transcript {
  variant: Rfc9474Variant;
  messageText: string;
  prefixHex: string;
  preparedMsgHex: string;
  saltHex: string;
  encodedMsgHex: string;
  blindedMsgHex: string;
  blindSigHex: string;
  signatureHex: string;
  verified: boolean;
  // intermediates for the tamper demo
  publicKey: Rfc9474PublicKey;
  inputMsg: Uint8Array;
  signature: Uint8Array;
}

export async function runRfc9474Demo(
  variant: Rfc9474Variant,
  messageText: string,
  issuer?: Rfc9474Issuer
): Promise<Rfc9474Transcript> {
  const auth = issuer ?? (await createRfc9474Issuer());
  const msg = new TextEncoder().encode(messageText);

  const prepared = prepare(msg, variant);
  const blinded = await blind(auth.publicKey, prepared.inputMsg, variant);
  const blindSigBytes = auth.blindSign(blinded.blindedMsg);
  const signature = finalize(blindSigBytes, blinded.inv, auth.publicKey.n, auth.publicKey.modulusLen);
  const verified = await verify(auth.publicKey, prepared.inputMsg, signature, variant);

  return {
    variant,
    messageText,
    prefixHex: bytesToHex(prepared.prefix),
    preparedMsgHex: bytesToHex(prepared.inputMsg),
    saltHex: bytesToHex(blinded.salt),
    encodedMsgHex: bytesToHex(blinded.encodedMsg),
    blindedMsgHex: bytesToHex(blinded.blindedMsg),
    blindSigHex: bytesToHex(blindSigBytes),
    signatureHex: bytesToHex(signature),
    verified,
    publicKey: auth.publicKey,
    inputMsg: prepared.inputMsg,
    signature
  };
}

// ── byte / bigint utilities ───────────────────────────────────
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const matches = hex.match(/../g);
  return matches ? Uint8Array.from(matches, (b) => parseInt(b, 16)) : new Uint8Array(0);
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function intToBytes(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const length = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  if (length > 0) crypto.getRandomValues(bytes);
  return bytes;
}

function bitLength(value: bigint): number {
  return value.toString(2).length;
}

function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) {
    [x, y] = [y, x % y];
  }
  return x;
}

function base64UrlToBigInt(input: string): bigint {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '==='.slice((base64.length + 3) % 4);
  const bytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
  return bytesToBigInt(bytes);
}
