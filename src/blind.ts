export interface RsaBlindSession {
  publicKeyPem: string;
  n: bigint;
  e: bigint;
  d: bigint;
}

export async function generateRsaBlindSession(): Promise<RsaBlindSession> {
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

  const jwkPrivate = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const jwkPublic = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const n = base64UrlToBigInt(jwkPublic.n ?? '');
  const e = base64UrlToBigInt(jwkPublic.e ?? '');
  const d = base64UrlToBigInt(jwkPrivate.d ?? '');

  return {
    publicKeyPem: JSON.stringify(jwkPublic),
    n,
    e,
    d
  };
}

function base64UrlToBigInt(input: string): bigint {
  if (!input) {
    throw new Error('Missing JWK value');
  }
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '==='.slice((base64.length + 3) % 4);
  const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}
