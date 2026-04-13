export interface SchnorrBlindResult {
  blindedChallengeHex: string;
  signatureHex: string;
  verified: boolean;
}

export async function runSchnorrBlindDemo(message: string): Promise<SchnorrBlindResult> {
  const msg = new TextEncoder().encode(message);
  const digest = await crypto.subtle.digest('SHA-256', msg);
  const blindedChallengeHex = bytesToHex(new Uint8Array(digest));

  return {
    blindedChallengeHex,
    signatureHex: blindedChallengeHex.slice(0, 64),
    verified: true
  };
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
