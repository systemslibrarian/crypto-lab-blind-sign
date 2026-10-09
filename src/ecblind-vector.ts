// Independent Python affine Edwards25519 arithmetic and hashlib SHA-512.
// RFC8032 section5.1 field/basepoint parameters; custom teaching transcript
// uses big-endian challenge reduction, not the RFC8032 signature encoding.
export const signerScalars = [7n, 11n, 13n, 17n];
export const expectedTranscript = {
  "messageText": "fixed blind Schnorr transcript",
  "publicKeyHex": "b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1",
  "signerNonceCommitmentHex": "1337036ac32d8f30d4589c3c1c595812ce0fff40e37c6f5a97ab213f318290ad",
  "alphaHex": "000000000000000000000000000000000000000000000000000000000000000d",
  "betaHex": "0000000000000000000000000000000000000000000000000000000000000011",
  "blindedCommitmentHex": "de44400980908606cde8bb086bcf4eec8dd668a433549929443007ee5579efdf",
  "challengeHex": "0ba3d889c1432b643451423168d4a95140df71f4bed727a88957d5ffd4d05af2",
  "blindedChallengeHex": "0ba3d889c1432b643451423168d4a95140df71f4bed727a88957d5ffd4d05b03",
  "partialSignatureHex": "017aebc448d62fbd6e38cf59ddd0a1385dc13c58090c056c090aea7b00e5597f",
  "signatureRHex": "de44400980908606cde8bb086bcf4eec8dd668a433549929443007ee5579efdf",
  "signatureSHex": "017aebc448d62fbd6e38cf59ddd0a1385dc13c58090c056c090aea7b00e5598c",
  "verified": true
};

// Independent constructed equations outside the signer prime-order domain.
export const invalidDomainEquations = [
  {
    "label": "order-two key",
    "publicKeyHex": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "signatureRHex": "5866666666666666666666666666666666666666666666666666666666666666",
    "signatureSHex": "0000000000000000000000000000000000000000000000000000000000000001",
    "messageText": "invalid domain independent control 0"
  },
  {
    "label": "mixed-order key and commitment",
    "publicKeyHex": "9599999999999999999999999999999999999999999999999999999999999999",
    "signatureRHex": "359dbf604a3b3bedc20d5408b9d4770fbe52c922979b3178d02ab8d41c9c3a4e",
    "signatureSHex": "0b2c517ecc6ce7020b1b7184c378a90a774b9d3e6a6c7cc1cc2ec5301ff51da2",
    "messageText": "invalid domain independent control 0"
  }
];
