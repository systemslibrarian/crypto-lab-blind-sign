# crypto-lab-blind-sign

## What It Is
This browser lab demonstrates blind signature workflows across three engines: a textbook RSA blind signature (`BigInt` modular arithmetic for blinding/unblinding), the standardized **RFC 9474 blind RSA** construction (full EMSA-PSS encoding with SHA-384, finalized signatures verified by the browser's native `crypto.subtle.verify`), and a Schnorr blind signature flow over `Ed25519`. The demo walks the full blind, sign, unblind, and verify lifecycle one real step at a time, with concrete transcripts for requester and signer views, an explicit "why blinding works" derivation, an optional small-numbers mode that runs the same primitives over a readable toy RSA key so learners can watch the blinding factor cancel, and an envelope animation of the blind/stamp/unblind mechanism. It also includes applied exhibits for Chaum-style e-cash, anonymous voting tokens, and anonymous attribute credentials in which the merchant, ballot box, and verifier each perform a genuine signature check against the issuer's persistent public key. Blind signatures solve the problem of obtaining a valid signature on a message without revealing the message to the signer at issuance time. The security model shown in code is unlinkability between issuance and later presentation, plus unforgeability from the signer key and signature verification equations — and every exhibit includes a negative case (tampered or forged inputs) that the verifier rejects.

The RFC 9474 engine is checked **byte-for-byte against the official Appendix A test vectors** for both the `RSABSSA-SHA384-PSS-Randomized` and `RSABSSA-SHA384-PSSZERO-Deterministic` variants. (Note: RFC 9474 §4.2 writes `EMSA-PSS-ENCODE(msg, bit_len(n))`, but the official vectors and the `RSASSA-PSS-VERIFY` it invokes require `emBits = bit_len(n) - 1`, which is what this implementation uses.)

## When to Use It
- Use blind signatures for e-cash issuance when a bank must authorize spendable tokens without learning which token a user will later spend.
- Use blind-signed voting tokens when an authority must enforce one-person-one-token while staying unable to link token issuance to a specific ballot.
- Use blind-signed eligibility credentials when an issuer should attest claims like `over18=true` without seeing future verifier presentation context.
- Use blind signatures for anti-abuse access tokens when services need issuer-approved tokens but want separation between issuer logs and redemption logs.
- Do not use blind signatures when accountability and signer-side auditability of exact signed content are mandatory, because the signer intentionally does not see the final message.
- Do NOT treat this as production code — it is a teaching demo and the textbook RSA/Schnorr engines are written for clarity, not for hardened or constant-time deployment.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-blind-sign](https://systemslibrarian.github.io/crypto-lab-blind-sign/)**

The protocol exhibit runs blind → sign → unblind → verify **one real step at a time**: each button executes its own modular arithmetic, the signer view only ever holds blinded values, and a *Tamper & re-verify* action flips one bit of the signature to show verification rejecting it. To build intuition it layers three teaching aids on top of the real math: a **"Why does blinding work?"** callout that walks the homomorphic identity `Sign(m·r^e) = m^d·r` explicitly and shows the blinding factor cancelling under `r^-1`; a **"Small numbers" mode** that runs the identical primitives over a genuine toy RSA key (`n = 61·53 = 3233`, `e = 17`, `d = 2753`) so every value — `m`, `r`, `m·r^e`, `s'`, `s` — is a short integer you can read in full and watch `r` cancel by hand; and an **envelope animation** in which the blinding factor `r` (shown as a colored envelope) seals `m`, the signer applies a `^d` stamp, and the same envelope peels away to reveal the recovered signature. A **"New to RSA?"** disclosure defines `n`, `e`, `d`, and the sign/verify exponentiations before the transcript equations appear. The applied exhibits are cryptographically real, not mocked — the e-cash merchant, ballot box, and credential verifier each call `verifySignature` against the issuer's persistent public key. Every exhibit includes a negative case: forged coins and ballot tokens fail the signature check (unforgeability), a re-spent coin fails the freshness check (no double spend), and an altered credential claim fails because the signature is bound to the exact attribute. The RFC 9474 exhibit adds a **"Why the extra padding?"** note bridging the textbook model to EMSA-PSS with a one-line gloss on SHA-384, MGF1, salt, and the message prefix. A dedicated Schnorr-blind (Ed25519) exhibit walks the elliptic-curve variant with its α/β blinding scalars — mapped back to RSA's single `r` as "same idea, different group" — and the RSA vs EC panel reports measured timings for both engines.

## What Can Go Wrong
- Blinding factor reuse: reusing the same `r` across requests can create correlation across blinded messages and erode unlinkability.
- Invalid blinding factor math: if `gcd(r, n) != 1`, unblinding fails and careless recovery logic can leak protocol state or cause signature rejection loops.
- Weak challenge binding in Schnorr blind signatures: if the challenge hash is not bound to commitment, public key, and message together, signature malleability or forgery avenues appear.
- Unsafely signing arbitrary blinded payloads: issuers that do not enforce issuance policy can become signature or token laundering oracles.
- Broken double-spend controls in e-cash deployments: if serial uniqueness tracking is missing or inconsistent, the same blind-signed coin can be redeemed multiple times.

## Real-World Usage
- GNU Taler: uses Chaumian blind signatures so exchanges issue digital cash without learning which specific coins customers later spend.
- Cashu: implements Chaumian e-cash mints where blinded outputs are signed by the mint and later redeemed with payer privacy.
- Privacy Pass (blind RSA deployments): uses RFC 9474 blinded token issuance so anti-bot issuers can sign tokens without seeing the final redeemable token value.
- Apple Private Access Tokens: uses the Privacy Pass / RFC 9474 model with blinded token issuance to separate attestation issuance from redemption identity.
- RFC 9474 (RSA Blind Signatures): the IETF standard implemented in the "RFC 9474 Blind RSA" exhibit, defining the EMSA-PSS-based blind RSA variants used above.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-blind-sign
cd crypto-lab-blind-sign
npm install
npm run dev
```

## Related Demos
- [crypto-lab-ring-sign](https://systemslibrarian.github.io/crypto-lab-ring-sign/) — another privacy-preserving signature, providing signer anonymity and unlinkability via ring signatures.
- [crypto-lab-rsa-forge](https://systemslibrarian.github.io/crypto-lab-rsa-forge/) — the RSA primitive (OAEP/PSS/PKCS#1) underlying the RSA blind signature construction.
- [crypto-lab-ed25519-forge](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/) — the EdDSA/Schnorr signature scheme that the Schnorr-blind exhibit builds on.
- [crypto-lab-pairing-gate](https://systemslibrarian.github.io/crypto-lab-pairing-gate/) — BLS signatures, another advanced signature primitive with aggregation.
- [crypto-lab-psi-gate](https://systemslibrarian.github.io/crypto-lab-psi-gate/) — privacy-preserving protocol over ristretto255 in the same unlinkability family.

## Tests
- `npm test` — run the Vitest suite (31 tests: textbook RSA and Schnorr correctness/unblinding/tamper-rejection, the toy small-numbers blind signature over a genuine RSA key (`e·d ≡ 1 mod φ(n)`, `s == m^d`), the modular-arithmetic helpers, and RFC 9474 byte-exact conformance against the official Appendix A vectors plus native WebCrypto round-trips for both variants)
- `npm run build` — type-check and produce the production bundle

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
