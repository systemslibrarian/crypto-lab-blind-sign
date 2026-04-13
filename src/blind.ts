const textEncoder = new TextEncoder();

export interface RsaBlindKeyMaterial {
  n: bigint;
  e: bigint;
  d: bigint;
}

export interface RsaBlindTranscript {
  messageText: string;
  messageRepresentative: bigint;
  blindingFactor: bigint;
  blindedMessage: bigint;
  blindedSignature: bigint;
  unblindedSignature: bigint;
  verifyPass: boolean;
  requesterView: {
    messageRepresentative: bigint;
    blindingFactor: bigint;
    blindedMessage: bigint;
    blindedSignature: bigint;
    unblindedSignature: bigint;
  };
  signerView: {
    blindedMessage: bigint;
    blindedSignature: bigint;
  };
  unlinkability: {
    signerNeverSeesMessageRepresentative: true;
    signerCannotRecoverMessageWithoutR: true;
    reason: string;
  };
}

export async function generateRsaBlindKeyMaterial(): Promise<RsaBlindKeyMaterial> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  );

  const pub = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const priv = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

  if (!pub.n || !pub.e || !priv.d) {
    throw new Error('Failed to export RSA key material');
  }

  return {
    n: base64UrlToBigInt(pub.n),
    e: base64UrlToBigInt(pub.e),
    d: base64UrlToBigInt(priv.d)
  };
}

export async function runRsaBlindSignatureDemo(messageText: string): Promise<RsaBlindTranscript> {
  const keys = await generateRsaBlindKeyMaterial();
  const m = await messageToRepresentative(messageText, keys.n);

  const r = randomCoprime(keys.n);
  const blindedMessage = blindMessage(m, r, keys.e, keys.n);
  const blindedSignature = signBlindedMessage(blindedMessage, keys.d, keys.n);
  const unblindedSignature = unblindSignature(blindedSignature, r, keys.n);
  const verifyPass = verifySignature(unblindedSignature, m, keys.e, keys.n);

  return {
    messageText,
    messageRepresentative: m,
    blindingFactor: r,
    blindedMessage,
    blindedSignature,
    unblindedSignature,
    verifyPass,
    requesterView: {
      messageRepresentative: m,
      blindingFactor: r,
      blindedMessage,
      blindedSignature,
      unblindedSignature
    },
    signerView: {
      blindedMessage,
      blindedSignature
    },
    unlinkability: {
      signerNeverSeesMessageRepresentative: true,
      signerCannotRecoverMessageWithoutR: true,
      reason:
        'The signer receives only m\' and computes s\'. The requester multiplies by r^-1 mod n to recover s. Without secret r, the signer cannot map s back to m.'
    }
  };
}

export function blindMessage(m: bigint, r: bigint, e: bigint, n: bigint): bigint {
  return (m * modPow(r, e, n)) % n;
}

export function signBlindedMessage(blindedMessage: bigint, d: bigint, n: bigint): bigint {
  return modPow(blindedMessage, d, n);
}

export function unblindSignature(blindedSignature: bigint, r: bigint, n: bigint): bigint {
  const rInv = modInverse(r, n);
  return (blindedSignature * rInv) % n;
}

export function verifySignature(signature: bigint, messageRepresentative: bigint, e: bigint, n: bigint): boolean {
  return modPow(signature, e, n) === messageRepresentative;
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 1n) {
    throw new Error('Invalid modulus');
  }
  let result = 1n;
  let b = ((base % modulus) + modulus) % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % modulus;
    }
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
}

export function modInverse(value: bigint, modulus: bigint): bigint {
  const { gcd, x } = extendedGcd(value, modulus);
  if (gcd !== 1n) {
    throw new Error('No modular inverse exists for the chosen blinding factor');
  }
  return ((x % modulus) + modulus) % modulus;
}

export function randomCoprime(modulus: bigint): bigint {
  const byteLength = Math.ceil(bitLength(modulus) / 8);
  while (true) {
    const candidate = randomBigInt(byteLength) % (modulus - 2n) + 2n;
    if (gcd(candidate, modulus) === 1n) {
      return candidate;
    }
  }
}

async function messageToRepresentative(message: string, modulus: bigint): Promise<bigint> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(message));
  const m = bytesToBigInt(new Uint8Array(digest));
  return m % modulus;
}

function randomBigInt(length: number): bigint {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytesToBigInt(bytes);
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

function bitLength(value: bigint): number {
  return value.toString(2).length;
}

function base64UrlToBigInt(input: string): bigint {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '==='.slice((base64.length + 3) % 4);
  const bytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
  return bytesToBigInt(bytes);
}

function gcd(a: bigint, b: bigint): bigint {
  let x = a;
  let y = b;
  while (y !== 0n) {
    const t = x % y;
    x = y;
    y = t;
  }
  return x < 0n ? -x : x;
}

function extendedGcd(a: bigint, b: bigint): { gcd: bigint; x: bigint; y: bigint } {
  let oldR = a;
  let r = b;
  let oldS = 1n;
  let s = 0n;
  let oldT = 0n;
  let t = 1n;

  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }

  return { gcd: oldR, x: oldS, y: oldT };
}
