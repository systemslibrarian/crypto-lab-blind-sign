[![crypto-lab portfolio](https://img.shields.io/badge/crypto--lab-portfolio-blue?style=flat-square)](https://systemslibrarian.github.io/crypto-lab/)

# crypto-lab-blind-sign

## What It Is
This browser lab demonstrates blind signature workflows using `RSASSA-PKCS1-v1_5` key generation through WebCrypto, `BigInt` modular arithmetic for RSA blinding/unblinding, and a Schnorr blind signature flow over `Ed25519`. The demo walks the full blind, sign, unblind, and verify lifecycle with concrete transcripts for requester and signer views. It also includes applied simulations for Chaum-style e-cash, anonymous voting tokens, and anonymous attribute credentials. Blind signatures solve the problem of obtaining a valid signature on a message without revealing the message to the signer at issuance time. The security model shown in code is unlinkability between issuance and later presentation, plus unforgeability from the signer key and signature verification equations.

## When to Use It
- Use blind signatures for e-cash issuance when a bank must authorize spendable tokens without learning which token a user will later spend.
- Use blind-signed voting tokens when an authority must enforce one-person-one-token while staying unable to link token issuance to a specific ballot.
- Use blind-signed eligibility credentials when an issuer should attest claims like `over18=true` without seeing future verifier presentation context.
- Use blind signatures for anti-abuse access tokens when services need issuer-approved tokens but want separation between issuer logs and redemption logs.
- Do not use blind signatures when accountability and signer-side auditability of exact signed content are mandatory, because the signer intentionally does not see the final message.

## Live Demo
https://systemslibrarian.github.io/crypto-lab-blind-sign/
The demo lets you run a direct blind/sign/unblind/verify workflow and inspect requester versus signer transcripts side by side. You can also run the RSA vs EC comparison panel with timing measurements, issue and spend blind-signed coins in the e-cash simulator, and test tokenized anonymous ballot submission in the voting exhibit.

## What Can Go Wrong
- Blinding factor reuse: reusing the same `r` across requests can create correlation across blinded messages and erode unlinkability.
- Invalid blinding factor math: if `gcd(r, n) != 1`, unblinding fails and careless recovery logic can leak protocol state or cause signature rejection loops.
- Weak challenge binding in Schnorr blind signatures: if the challenge hash is not bound to commitment, public key, and message together, signature malleability or forgery avenues appear.
- Unsafely signing arbitrary blinded payloads: issuers that do not enforce issuance policy can become signature or token laundering oracles.
- Broken double-spend controls in e-cash deployments: if serial uniqueness tracking is missing or inconsistent, the same blind-signed coin can be redeemed multiple times.

## Real-World Usage
- GNU Taler: uses Chaumian blind signatures so exchanges issue digital cash without learning which specific coins customers later spend.
- Cashu: implements Chaumian e-cash mints where blinded outputs are signed by the mint and later redeemed with payer privacy.
- Privacy Pass (blind RSA deployments): uses blinded token issuance so anti-bot issuers can sign tokens without seeing the final redeemable token value.
- Apple Private Access Tokens: uses the Privacy Pass model with blinded token issuance to separate attestation issuance from redemption identity.

> *"So whether you eat or drink or whatever you do, do it all
> for the glory of God." — 1 Corinthians 10:31*