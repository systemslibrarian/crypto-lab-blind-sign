/**
 * Claim assertions — the headline verdicts, counters and failure paths of every
 * exhibit, checked against the values the page itself rendered.
 *
 * Two rules shape this file:
 *   1. Recompute, don't restate. The toy exhibit publishes its whole key
 *      (n = 61·53, e = 17, d = 2753), so every integer it prints is re-derived
 *      here with independent BigInt arithmetic — m·r^e, (m')^d, r^-1, s·r^-1,
 *      s^e — and the verdict is checked against that, not against "VALID".
 *   2. Prefer cross-path agreement. Where the page computes one thing two ways
 *      (s = s'·r^-1 vs the directly computed m^d; the requester's m' vs the
 *      signer's m'; the compare table cell vs the compare log), assert the two
 *      agree — a single wrong operand then cannot pass.
 */
import { expect, test, type Page } from '@playwright/test';

// ── independent modular arithmetic, for re-deriving what the page printed ──
function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let r = 1n;
  let b = ((base % m) + m) % m;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    e >>= 1n;
    b = (b * b) % m;
  }
  return r;
}

function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) [x, y] = [y, x % y];
  return x;
}

function grab(log: string, re: RegExp, what: string): string {
  const m = re.exec(log);
  expect(m, `could not find ${what} in transcript:\n${log}`).toBeTruthy();
  return m![1];
}

const bg = (log: string, re: RegExp, what: string): bigint => BigInt(grab(log, re, what));

const text = (page: Page, sel: string): Promise<string> => page.locator(sel).innerText();

/** Truncated display form produced by shortStr(): 12 hex … 12 hex. */
const TRUNC = String.raw`[0-9a-f]{12}…[0-9a-f]{12}`;

// ════════════════════════════════════════════════════════════════
// Exhibit 1 — the protocol, small-numbers mode (every value re-derived)
// ════════════════════════════════════════════════════════════════

test('toy mode: every printed integer is re-derivable from the published toy key, and the two ways of computing s agree', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('input[name="protocol-mode"][value="toy"]').check();

  await page.locator('#protocol-blind').click();
  await expect(page.locator('#protocol-sign')).toBeEnabled();
  // The signer's view immediately after blinding: one number, plus the claim.
  const sigAfterBlind = await text(page, '#signer-log');
  expect(sigAfterBlind).toContain('Signer has not seen m or r.');

  await page.locator('#protocol-sign').click();
  await expect(page.locator('#protocol-unblind')).toBeEnabled();
  await page.locator('#protocol-unblind').click();
  await expect(page.locator('#protocol-verify')).toBeEnabled();
  await page.locator('#protocol-verify').click();
  await expect(page.locator('#protocol-verdict')).toHaveText('VALID');

  const req = await text(page, '#requester-log');
  const sig = await text(page, '#signer-log');

  // The key the page publishes is the key the page must have used.
  const key = /n = 61·53 = (\d+),\s+e = (\d+),\s+d = (\d+)/.exec(req);
  expect(key, `toy key line missing:\n${req}`).toBeTruthy();
  const n = BigInt(key![1]);
  const e = BigInt(key![2]);
  const d = BigInt(key![3]);
  expect(n).toBe(61n * 53n);
  // e·d ≡ 1 (mod φ(n)) — the key really is a valid RSA key pair.
  expect((e * d) % (60n * 52n)).toBe(1n);

  const m = bg(req, /^m\s+= message[^=\n]*= (\d+)/m, 'm');
  const r = bg(req, /^r\s+= random, gcd\(r,n\)=1[^=\n]*= (\d+)/m, 'r');
  const re_ = bg(req, /^r\^e mod n[^=\n]*= (\d+)/m, 'r^e');
  const blinded = bg(req, /^m' = m · r\^e mod n[^=\n]*= (\d+)/m, "m'");
  const rInv = bg(req, /^r\^-1 mod n[^=\n]*= (\d+)/m, 'r^-1');
  const s = bg(req, /^s = s' · r\^-1 mod n[^=\n]*= (\d+)/m, 's');
  const direct = bg(req, /^check m\^d mod n directly[^=\n]*= (\d+)/m, 'm^d');
  const verified = bg(req, /^verify: s\^e mod n[^=\n]*= (\d+)/m, 's^e');

  const blindedSigner = bg(sig, /Signer input:\s+m' = (\d+)/, "signer's m'");
  const sPrime = bg(sig, /Signer output: s' = \(m'\)\^d mod n = (\d+)/, "s'");
  const nSigner = bg(sig, /\(modulus n = (\d+)\)/, "signer's n");

  // Ranges and the coprimality the label claims.
  expect(m).toBeGreaterThan(0n);
  expect(m).toBeLessThan(n);
  expect(r).toBeGreaterThanOrEqual(2n);
  expect(r).toBeLessThan(n);
  expect(gcd(r, n)).toBe(1n);

  // Every step, recomputed.
  expect(re_).toBe(modPow(r, e, n));
  expect(blinded).toBe((m * re_) % n);
  expect((r * rInv) % n).toBe(1n); // the "since r·r^-1 ≡ 1 mod n" annotation
  expect(rInv).toBeGreaterThan(0n);
  expect(rInv).toBeLessThan(n);
  expect(sPrime).toBe(modPow(blinded, d, n));
  expect(s).toBe((sPrime * rInv) % n);
  expect(verified).toBe(modPow(s, e, n));
  expect(verified).toBe(m);

  // Cross-path agreement: the unblinded signature and the directly computed
  // m^d are the same number. This is the exhibit's "r is gone" claim.
  expect(direct).toBe(modPow(m, d, n));
  expect(s).toBe(direct);
  expect(req).toContain('← identical, r is gone');
  expect(req).toMatch(/equals m \(\d+\)\?\s+→\s+true/);
  expect(grab(req, /equals m \((\d+)\)\?/, 'the m quoted by the verify line')).toBe(m.toString());

  // Cross-view agreement: the signer's m' is the requester's m', and the signer
  // never sees m or r. Blinding is the whole point of the exhibit.
  expect(blindedSigner).toBe(blinded);
  expect(nSigner).toBe(n);
  // Right after blinding the signer held exactly one number: m'.
  expect(new Set(sigAfterBlind.match(/\d+/g) ?? [])).toEqual(new Set([blinded.toString()]));
  // After signing its whole view is exactly three — m', s' and the public n.
  // Nothing else reaches it, so m and r cannot be read off the panel.
  expect(new Set(sig.match(/\d+/g) ?? [])).toEqual(
    new Set([blinded, sPrime, n].map((v) => v.toString())),
  );

  await expect(page.locator('#protocol-status')).toHaveText('Verify complete — signature is valid.');
});

test('toy mode: tampering adds one to s, the verifier lands somewhere else, and the verdict is REJECTED', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('input[name="protocol-mode"][value="toy"]').check();
  await page.locator('#protocol-blind').click();
  await expect(page.locator('#protocol-sign')).toBeEnabled();
  await page.locator('#protocol-sign').click();
  await page.locator('#protocol-unblind').click();
  await page.locator('#protocol-verify').click();
  await expect(page.locator('#protocol-verdict')).toHaveText('VALID');

  await page.locator('#protocol-tamper').click();
  await expect(page.locator('#protocol-verdict')).toHaveText('REJECTED');

  const req = await text(page, '#requester-log');
  const key = /n = 61·53 = (\d+),\s+e = (\d+),\s+d = (\d+)/.exec(req);
  expect(key, `toy key line missing:\n${req}`).toBeTruthy();
  const n = BigInt(key![1]);
  const e = BigInt(key![2]);
  const m = bg(req, /^m\s+= message[^=\n]*= (\d+)/m, 'm');
  const s = bg(req, /^s = s' · r\^-1 mod n[^=\n]*= (\d+)/m, 's');
  const forged = bg(req, /^Tampered signature s\+1[^=\n]*= (\d+)/m, 'the tampered signature');
  const check = bg(req, /^verify: \(s\+1\)\^e mod n[^=\n]*= (\d+)/m, 'the tampered verification');
  const needed = bg(req, /\(needed (\d+)\)/, 'the value the verifier needed');

  // The tamper really is s+1 mod n, and the check really is (s+1)^e mod n.
  expect(forged).toBe((s + 1n) % n);
  expect(check).toBe(modPow(forged, e, n));
  // …which is NOT m, so the equation fails and the page says so.
  expect(needed).toBe(m);
  expect(check).not.toBe(m);
  expect(req).toMatch(/verify: \(s\+1\)\^e mod n[^\n]*→\s+false/);
  await expect(page.locator('#protocol-status')).toHaveText(
    'Tampered signature rejected — this is unforgeability.',
  );
});

// ════════════════════════════════════════════════════════════════
// Exhibit 1 — real 2048-bit mode
// ════════════════════════════════════════════════════════════════

test('real mode: the signer only ever holds blinded values, and the recovered signature verifies', async ({
  page,
}) => {
  test.slow();
  await page.goto('.');
  await expect(page.locator('input[name="protocol-mode"][value="real"]')).toBeChecked();

  await page.locator('#protocol-blind').click();
  await expect(page.locator('#protocol-sign')).toBeEnabled({ timeout: 60000 });

  let req = await text(page, '#requester-log');
  const mDisp = grab(req, new RegExp(String.raw`^m\s+= H\(message\) mod n = (0x${TRUNC})`, 'm'), 'm');
  const rDisp = grab(req, new RegExp(String.raw`^r\s+= random, gcd\(r,n\)=1 = (0x${TRUNC})`, 'm'), 'r');
  const mPrimeDisp = grab(req, new RegExp(String.raw`^m' = m · r\^e mod n\s+= (0x${TRUNC})`, 'm'), "m'");
  expect(new Set([mDisp, rDisp, mPrimeDisp]).size).toBe(3); // three distinct values

  let sig = await text(page, '#signer-log');
  // Cross-view agreement, and the exhibit's core claim: the signer's view holds
  // the blinded message and NOT the message representative or the blinding factor.
  expect(grab(sig, new RegExp(String.raw`Signer receives only: m' = (0x${TRUNC})`), "signer's m'")).toBe(
    mPrimeDisp,
  );
  expect(sig).not.toContain(mDisp);
  expect(sig).not.toContain(rDisp);

  await page.locator('#protocol-sign').click();
  await expect(page.locator('#protocol-unblind')).toBeEnabled();
  sig = await text(page, '#signer-log');
  const sPrimeDisp = grab(
    sig,
    new RegExp(String.raw`Signer output: s' = \(m'\)\^d mod n = (0x${TRUNC})`),
    "s'",
  );
  expect(grab(sig, new RegExp(String.raw`Signer input:\s+m' = (0x${TRUNC})`), "signer's m'")).toBe(mPrimeDisp);
  expect(sig).not.toContain(mDisp);
  expect(sig).not.toContain(rDisp);

  await page.locator('#protocol-unblind').click();
  await expect(page.locator('#protocol-verify')).toBeEnabled();
  req = await text(page, '#requester-log');
  const sDisp = grab(req, new RegExp(String.raw`^s = s' · r\^-1 mod n = (0x${TRUNC})`, 'm'), 's');
  // Unblinding actually changed the value — s is not the signer's s'.
  expect(sDisp).not.toBe(sPrimeDisp);
  // …and the signer's transcript never gains it.
  expect(await text(page, '#signer-log')).not.toContain(sDisp);

  await page.locator('#protocol-verify').click();
  await expect(page.locator('#protocol-verdict')).toHaveText('VALID');
  req = await text(page, '#requester-log');
  expect(req).toMatch(/verify: s\^e mod n == m\s+→\s+true/);
  await expect(page.locator('#protocol-status')).toHaveText('Verify complete — signature is valid.');

  // Tamper: s+1, and the truncated display proves it is the same number plus one.
  await page.locator('#protocol-tamper').click();
  await expect(page.locator('#protocol-verdict')).toHaveText('REJECTED');
  req = await text(page, '#requester-log');
  const forgedDisp = grab(
    req,
    new RegExp(String.raw`^Tampered signature s\+1 = (0x${TRUNC})`, 'm'),
    'the tampered signature',
  );
  expect(forgedDisp.slice(0, 14)).toBe(sDisp.slice(0, 14)); // 0x + leading 12 hex unchanged
  expect(BigInt(`0x${forgedDisp.slice(-12)}`)).toBe(BigInt(`0x${sDisp.slice(-12)}`) + 1n);
  expect(req).toMatch(/verify: \(s\+1\)\^e mod n == m\s+→\s+false/);
  await expect(page.locator('#protocol-status')).toHaveText(
    'Tampered signature rejected — this is unforgeability.',
  );
});

test('the envelope walks idle → wrapped → stamped → unwrapped, and the step buttons unlock in order', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('input[name="protocol-mode"][value="toy"]').check();
  const svg = page.locator('.envelope-svg');
  const stages: string[] = [];

  await expect(svg).toHaveAttribute('data-stage', 'idle');
  for (const id of ['#protocol-sign', '#protocol-unblind', '#protocol-verify', '#protocol-tamper']) {
    await expect(page.locator(id)).toBeDisabled();
  }

  await page.locator('#protocol-blind').click();
  await expect(page.locator('#protocol-sign')).toBeEnabled();
  stages.push((await svg.getAttribute('data-stage')) ?? '');
  await expect(page.locator('#protocol-unblind')).toBeDisabled();

  await page.locator('#protocol-sign').click();
  await expect(page.locator('#protocol-unblind')).toBeEnabled();
  stages.push((await svg.getAttribute('data-stage')) ?? '');
  await expect(page.locator('#protocol-verify')).toBeDisabled();

  await page.locator('#protocol-unblind').click();
  await expect(page.locator('#protocol-verify')).toBeEnabled();
  stages.push((await svg.getAttribute('data-stage')) ?? '');
  await expect(page.locator('#protocol-tamper')).toBeDisabled();

  await page.locator('#protocol-verify').click();
  await expect(page.locator('#protocol-tamper')).toBeEnabled();
  expect(stages).toEqual(['wrapped', 'stamped', 'unwrapped']);

  // Switching number mode invalidates the run rather than leaving a stale verdict.
  await page.locator('input[name="protocol-mode"][value="real"]').check();
  await expect(svg).toHaveAttribute('data-stage', 'idle');
  await expect(page.locator('#protocol-verdict')).toHaveText('');
  await expect(page.locator('#requester-log')).toHaveText('Click 1 · Blind to start.');
  await expect(page.locator('#signer-log')).toHaveText('Signer has not received a blinded request yet.');
  for (const id of ['#protocol-sign', '#protocol-unblind', '#protocol-verify', '#protocol-tamper']) {
    await expect(page.locator(id)).toBeDisabled();
  }
});

// ════════════════════════════════════════════════════════════════
// Exhibit 2 — RFC 9474 blind RSA, verified by the browser itself
// ════════════════════════════════════════════════════════════════

async function runRfc(page: Page): Promise<void> {
  await page.locator('#rfc-blind').click();
  await expect(page.locator('#rfc-sign')).toBeEnabled({ timeout: 60000 });
  await page.locator('#rfc-sign').click();
  await expect(page.locator('#rfc-finalize')).toBeEnabled();
  await page.locator('#rfc-finalize').click();
  await expect(page.locator('#rfc-tamper')).toBeEnabled({ timeout: 60000 });
}

test('RFC 9474 randomized: the browser natively accepts the finalized signature, and the issuer saw none of the padding', async ({
  page,
}) => {
  test.slow();
  await page.goto('.');
  await page.locator('#tab-rfc9474').click();

  await page.locator('#rfc-blind').click();
  await expect(page.locator('#rfc-sign')).toBeEnabled({ timeout: 60000 });
  // The signer's view before it signs — the claim it makes about what it holds.
  const sigAfterBlind = await text(page, '#rfc-signer-log');
  expect(sigAfterBlind).toContain('Signer sees neither the message nor the PSS salt.');

  await page.locator('#rfc-sign').click();
  await expect(page.locator('#rfc-finalize')).toBeEnabled();
  await page.locator('#rfc-finalize').click();
  await expect(page.locator('#rfc-tamper')).toBeEnabled({ timeout: 60000 });

  await expect(page.locator('#rfc-verdict')).toHaveText('VALID');
  await expect(page.locator('#rfc-status')).toHaveText('Finalized — natively verified valid.');

  const req = await text(page, '#rfc-requester-log');
  const sig = await text(page, '#rfc-signer-log');

  expect(grab(req, /^variant = (\S+)/m, 'variant')).toBe('RSABSSA-SHA384-PSS-Randomized');
  const prefix = grab(req, new RegExp(String.raw`^prefix \(32-byte random\) = (${TRUNC})`, 'm'), 'prefix');
  const saltLen = grab(req, /^salt \((\d+)-byte\)/m, 'salt length');
  expect(saltLen).toBe('48'); // SHA-384 output length, per the variant
  const salt = grab(req, new RegExp(String.raw`^salt \(48-byte\)\s+= (${TRUNC})`, 'm'), 'salt');
  const encoded = grab(req, new RegExp(String.raw`^encoded_msg \(EMSA-PSS\)\s+= (${TRUNC})`, 'm'), 'encoded_msg');
  const blindedMsg = grab(req, new RegExp(String.raw`^blinded_msg = m·r\^e\s+= (${TRUNC})`, 'm'), 'blinded_msg');
  const finalSig = grab(
    req,
    new RegExp(String.raw`^signature = blind_sig·r\^-1 = (${TRUNC})`, 'm'),
    'the finalized signature',
  );

  // The headline: an independent verifier — the browser's own RSA-PSS
  // implementation — accepted it.
  expect(req).toMatch(/native crypto\.subtle\.verify \(RSA-PSS\) → true/);

  // Cross-view agreement, and the blinding claim the panel makes in prose.
  expect(grab(sig, new RegExp(String.raw`Signer input:\s+blinded_msg = (${TRUNC})`), "signer's blinded_msg")).toBe(
    blindedMsg,
  );
  const blindSig = grab(sig, new RegExp(String.raw`Signer output: blind_sig\s+= (${TRUNC})`), 'blind_sig');
  expect(
    grab(
      sigAfterBlind,
      new RegExp(String.raw`Signer receives only blinded_msg = (${TRUNC})`),
      "the signer's blinded_msg",
    ),
  ).toBe(blindedMsg);
  // Neither the pre-sign nor the post-sign signer view ever carries the prefix,
  // the salt, the PSS encoding, or the finished signature.
  for (const view of [sigAfterBlind, sig]) {
    for (const secret of [prefix, salt, encoded, finalSig]) expect(view).not.toContain(secret);
  }
  // Finalizing changed the value: the published signature is not what the issuer returned.
  expect(finalSig).not.toBe(blindSig);
});

test('RFC 9474: the tamper flips exactly one bit of the real signature and the native verifier rejects it', async ({
  page,
}) => {
  test.slow();
  await page.goto('.');
  await page.locator('#tab-rfc9474').click();
  await runRfc(page);
  await expect(page.locator('#rfc-verdict')).toHaveText('VALID');

  const finalSig = grab(
    await text(page, '#rfc-requester-log'),
    new RegExp(String.raw`^signature = blind_sig·r\^-1 = (${TRUNC})`, 'm'),
    'the finalized signature',
  );

  await page.locator('#rfc-tamper').click();
  await expect(page.locator('#rfc-verdict')).toHaveText('REJECTED', { timeout: 30000 });

  const req = await text(page, '#rfc-requester-log');
  const tampered = grab(
    req,
    new RegExp(String.raw`^tampered signature \(1 bit flipped\) = (${TRUNC})`, 'm'),
    'the tampered signature',
  );
  // "1 bit flipped" must be literally true: same bytes except the low bit of the last one.
  expect(tampered.slice(0, -1)).toBe(finalSig.slice(0, -1));
  expect(parseInt(tampered.slice(-1), 16)).toBe(parseInt(finalSig.slice(-1), 16) ^ 1);
  expect(req).toMatch(/native crypto\.subtle\.verify → false/);
  expect(req).toContain('The browser rejects the altered signature: unforgeability.');
  await expect(page.locator('#rfc-status')).toHaveText('Tampered signature rejected by the native verifier.');
});

test('RFC 9474 deterministic: no prefix, zero-length salt, still natively valid — and switching variant resets the run', async ({
  page,
}) => {
  test.slow();
  await page.goto('.');
  await page.locator('#tab-rfc9474').click();
  await runRfc(page);
  await expect(page.locator('#rfc-verdict')).toHaveText('VALID');

  await page.locator('input[name="rfc-variant"][value="RSABSSA-SHA384-PSSZERO-Deterministic"]').check();
  // A variant change must invalidate the finished run rather than leave a stale VALID.
  await expect(page.locator('#rfc-verdict')).toHaveText('');
  await expect(page.locator('#rfc-requester-log')).toHaveText(
    'Variant changed. Click 1 · Prepare & Blind to start.',
  );
  for (const id of ['#rfc-sign', '#rfc-finalize', '#rfc-tamper']) {
    await expect(page.locator(id)).toBeDisabled();
  }

  await runRfc(page);
  await expect(page.locator('#rfc-verdict')).toHaveText('VALID');
  const req = await text(page, '#rfc-requester-log');
  expect(grab(req, /^variant = (\S+)/m, 'variant')).toBe('RSABSSA-SHA384-PSSZERO-Deterministic');
  expect(req).toMatch(/^prefix\s+= \(none — deterministic\)/m);
  expect(grab(req, /^salt \((\d+)-byte\)/m, 'salt length')).toBe('0');
  expect(req).toMatch(/^salt \(0-byte\)\s+= \(empty\)/m);
  expect(req).toMatch(/native crypto\.subtle\.verify \(RSA-PSS\) → true/);
});

// ════════════════════════════════════════════════════════════════
// Exhibit 3 — Chaum e-cash: two independent checks
// ════════════════════════════════════════════════════════════════

test('e-cash: the merchant runs two independent checks — a double spend fails on freshness while the signature is still valid', async ({
  page,
}) => {
  test.slow();
  await page.goto('.');
  await page.locator('#tab-cash').click();

  await page.locator('#cash-issue').click();
  await expect(page.locator('#cash-spend')).toBeEnabled({ timeout: 60000 });
  const serial = grab(await text(page, '#cash-log'), /Coin serial:\s+(COIN-[0-9a-f]{16})/, 'the coin serial');

  // Attempting a double spend before spending is refused with guidance, not a verdict.
  await page.locator('#cash-respend').click();
  await expect(page.locator('#cash-status')).toHaveText(
    'Spend the coin once before attempting a double spend.',
  );
  await expect(page.locator('#cash-verdict')).toHaveText('');

  await page.locator('#cash-spend').click();
  await expect(page.locator('#cash-verdict')).toHaveText('ACCEPTED');
  let log = await text(page, '#cash-log');
  expect(log).toContain(`Spend ${serial}`);
  expect(log).toMatch(/signature valid\?\s+true\s+\(bank's key authorizes it\)/);
  expect(log).toMatch(/serial unseen\?\s+true\s+\(no double spend\)/);
  await expect(page.locator('#cash-status')).toHaveText('Merchant accepted the coin.');

  await page.locator('#cash-respend').click();
  await expect(page.locator('#cash-verdict')).toHaveText('DOUBLE SPEND');
  log = await text(page, '#cash-log');
  expect(log).toContain(`Re-spend ${serial}`);
  // The teaching point: the signature check STILL passes; only freshness fails.
  expect(log).toMatch(/signature valid\?\s+true\s+\(still a genuine coin!\)/);
  expect(log).toMatch(/serial unseen\?\s+false\s+\(already in the spent registry\)/);
  await expect(page.locator('#cash-status')).toHaveText(
    'Double-spend detected — serial already redeemed.',
  );

  // A forged coin fails the other check: the signature, before freshness matters.
  await page.locator('#cash-forge').click();
  await expect(page.locator('#cash-verdict')).toHaveText('REJECTED');
  log = await text(page, '#cash-log');
  const fake = grab(log, /Spend forged (FAKE-[0-9a-f]{16})/, 'the forged serial');
  expect(fake).not.toBe(serial);
  expect(log).toMatch(/signature valid\?\s+false\s+\(no bank key → cannot forge\)/);
  expect(log).toContain('→ rejected before the serial is even checked.');
  await expect(page.locator('#cash-status')).toHaveText('Forged coin rejected — signature does not verify.');

  // A second coin from the SAME bank still verifies — the merchant checks against
  // the issuer's persistent public key, as the README claims. (Issuing resets the
  // log, so the old serial disappearing is the signal that issuance finished.)
  await page.locator('#cash-issue').click();
  await expect(page.locator('#cash-log')).not.toContainText(serial, { timeout: 60000 });
  const serial2 = grab(await text(page, '#cash-log'), /Coin serial:\s+(COIN-[0-9a-f]{16})/, 'the second serial');
  expect(serial2).not.toBe(serial);
  await expect(page.locator('#cash-verdict')).toHaveText('');
  await page.locator('#cash-spend').click();
  await expect(page.locator('#cash-verdict')).toHaveText('ACCEPTED');
  log = await text(page, '#cash-log');
  expect(log).toContain(`Spend ${serial2}`);
  expect(log).toMatch(/signature valid\?\s+true\s+\(bank's key authorizes it\)/);
  expect(log).toMatch(/serial unseen\?\s+true\s+\(no double spend\)/);
});

// ════════════════════════════════════════════════════════════════
// Exhibit 4 — anonymous voting
// ════════════════════════════════════════════════════════════════

test('voting: the chosen option is what gets counted, one token votes once, and a forged token is rejected', async ({
  page,
}) => {
  test.slow();
  await page.goto('.');
  await page.locator('#tab-voting').click();

  await page.locator('#vote-issue').click();
  await expect(page.locator('#vote-submit')).toBeEnabled({ timeout: 60000 });
  const token = grab(await text(page, '#vote-log'), /Token: (BALLOT-[0-9a-f]{16})/, 'the ballot token');

  await page.locator('#vote-choice').selectOption('Option B');
  await page.locator('#vote-submit').click();
  await expect(page.locator('#vote-verdict')).toHaveText('COUNTED');
  // The status must name the option actually selected, not a default.
  await expect(page.locator('#vote-status')).toHaveText('Anonymous vote for Option B accepted.');
  let log = await text(page, '#vote-log');
  expect(log).toContain(`Submit vote "Option B" with ${token}`);
  expect(log).toMatch(/token signature valid\?\s+true\s+\(eligible voter\)/);
  expect(log).toMatch(/token unused\?\s+true\s+\(one person, one vote\)/);

  // One person, one vote: the same token is refused on freshness, not eligibility.
  await page.locator('#vote-submit').click();
  await expect(page.locator('#vote-verdict')).toHaveText('ALREADY VOTED');
  await expect(page.locator('#vote-status')).toHaveText('Vote rejected: token already used.');
  log = await text(page, '#vote-log');
  const second = log.slice(log.lastIndexOf(`Submit vote "Option B" with ${token}`));
  expect(second).toMatch(/token signature valid\?\s+true/);
  expect(second).toMatch(/token unused\?\s+false/);

  await page.locator('#vote-forge').click();
  await expect(page.locator('#vote-verdict')).toHaveText('REJECTED');
  log = await text(page, '#vote-log');
  const fake = grab(log, /Submit vote with forged (FAKE-[0-9a-f]{16})/, 'the forged token');
  expect(fake).not.toBe(token);
  expect(log).toMatch(/token signature valid\?\s+false\s+\(no authority key → cannot forge\)/);
  expect(log).toContain('→ rejected; ballot stuffing prevented.');
  await expect(page.locator('#vote-status')).toHaveText(
    'Forged token rejected — not signed by the authority.',
  );
});

// ════════════════════════════════════════════════════════════════
// Exhibit 5 — anonymous credentials
// ════════════════════════════════════════════════════════════════

test('credentials: the same signature that validates over18 fails on over21 — the signature is bound to the exact claim', async ({
  page,
}) => {
  test.slow();
  await page.goto('.');
  await page.locator('#tab-credentials').click();

  await page.locator('#cred-issue').click();
  await expect(page.locator('#cred-present')).toBeEnabled({ timeout: 60000 });

  await page.locator('#cred-present').click();
  await expect(page.locator('#cred-verdict')).toHaveText('VALID');
  let log = await text(page, '#cred-log');
  expect(log).toContain('Present "attribute:over18=true"');
  expect(log).toMatch(/issuer signature valid\?\s+true/);
  await expect(page.locator('#cred-status')).toHaveText('Verifier accepted the claim.');

  await page.locator('#cred-forge').click();
  await expect(page.locator('#cred-verdict')).toHaveText('REJECTED');
  log = await text(page, '#cred-log');
  // The forgery reuses the *same* signature against a *different* claim — the
  // only variable that changed is the claim, so the rejection is attributable.
  expect(log).toContain('Present altered "attribute:over21=true" reusing the over18 signature');
  expect(log).toMatch(/issuer signature valid\?\s+false\s+\(signature is bound to the signed claim\)/);
  expect(log).toContain('→ rejected; attributes cannot be upgraded.');
  await expect(page.locator('#cred-status')).toHaveText(
    'Altered claim rejected — signature is bound to the exact attribute.',
  );
});

// ════════════════════════════════════════════════════════════════
// Exhibit 6 — blind Schnorr over Ed25519
// ════════════════════════════════════════════════════════════════

test('blind Schnorr: the curve equation verifies, and adding one to the scalar breaks it', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab-schnorr').click();

  await page.locator('#schnorr-run').click();
  await expect(page.locator('#schnorr-verdict')).toHaveText('VALID', { timeout: 30000 });
  await expect(page.locator('#schnorr-status')).toHaveText(
    'Blind Schnorr complete — signature is valid.',
  );

  const log = await text(page, '#schnorr-log');
  for (const label of ['P  (public key)', 'R0 (signer commit)', 'α', 'β', "R' = R0 + αG + βP", "c  = H(R',P,m)"]) {
    expect(log, `transcript is missing "${label}"`).toContain(label);
  }
  expect(log).toMatch(/verify: s·G == R' \+ c·P\s+→\s+true/);
  // Distinct blinding scalars, and blinding actually moved the commitment and
  // the challenge — otherwise the "blind" in blind Schnorr is decorative.
  const alpha = grab(log, new RegExp(String.raw`^α\s+= (${TRUNC})`, 'm'), 'α');
  const beta = grab(log, new RegExp(String.raw`^β\s+= (${TRUNC})`, 'm'), 'β');
  const r0 = grab(log, new RegExp(String.raw`^R0 \(signer commit\)\s+= (${TRUNC})`, 'm'), 'R0');
  const rPrime = grab(log, new RegExp(String.raw`^R' = R0 \+ αG \+ βP\s+= (${TRUNC})`, 'm'), "R'");
  const c = grab(log, new RegExp(String.raw`^c\s+= H\(R',P,m\)\s+= (${TRUNC})`, 'm'), 'c');
  const cPrime = grab(log, new RegExp(String.raw`^c' = c \+ β\s+\(to signer\) = (${TRUNC})`, 'm'), "c'");
  const s0 = grab(log, new RegExp(String.raw`^s0 = k \+ c'·x \(signer\) = (${TRUNC})`, 'm'), 's0');
  const s = grab(log, new RegExp(String.raw`^s\s+= s0 \+ α\s+\(unblind\) = (${TRUNC})`, 'm'), 's');
  expect(alpha).not.toBe(beta);
  expect(rPrime).not.toBe(r0);
  expect(cPrime).not.toBe(c);
  expect(s).not.toBe(s0);
  expect(log).toContain("The signer only saw (R0, c′, s0) — never m, R′, or s.");

  await page.locator('#schnorr-tamper').click();
  await expect(page.locator('#schnorr-verdict')).toHaveText('REJECTED');
  const after = await text(page, '#schnorr-log');
  const tampered = grab(after, new RegExp(String.raw`^Tampered s\+1 = (${TRUNC})`, 'm'), 'the tampered scalar');
  // The tamper is genuinely s+1: the leading 12 hex digits are untouched and the
  // trailing 12 have incremented.
  expect(tampered.slice(0, 12)).toBe(s.slice(0, 12));
  expect(BigInt(`0x${tampered.slice(-12)}`)).toBe(BigInt(`0x${s.slice(-12)}`) + 1n);
  expect(after).toMatch(/verify: \(s\+1\)·G == R' \+ c·P\s+→\s+false/);
  expect(after).toContain('Altering the scalar breaks the curve equation: rejected.');
  await expect(page.locator('#schnorr-status')).toHaveText('Tampered Schnorr signature rejected.');
});

// ════════════════════════════════════════════════════════════════
// Exhibit 7 — RSA vs EC comparison
// ════════════════════════════════════════════════════════════════

test('comparison: both engines really run, the table cells agree with the log, and the timings are measured', async ({
  page,
}) => {
  test.slow();
  await page.goto('.');
  await page.locator('#tab-compare').click();

  await expect(page.locator('#cmp-rsa-time')).toHaveText('—');
  await expect(page.locator('#cmp-ec-time')).toHaveText('—');

  await page.locator('#compare-run').click();
  await expect(page.locator('#cmp-rsa-ok')).toHaveText('valid', { timeout: 60000 });
  await expect(page.locator('#cmp-ec-ok')).toHaveText('valid');

  const rsaTime = await text(page, '#cmp-rsa-time');
  const ecTime = await text(page, '#cmp-ec-time');
  // Rendered by toFixed(2) from a real performance.now() delta, not a placeholder.
  expect(rsaTime).toMatch(/^\d+\.\d{2} ms$/);
  expect(ecTime).toMatch(/^\d+\.\d{2} ms$/);
  expect(parseFloat(rsaTime)).toBeGreaterThan(0);
  expect(parseFloat(ecTime)).toBeGreaterThan(0);

  // The table's verdict cells and the log's booleans are the same two facts
  // rendered twice; they must not disagree.
  const log = await text(page, '#compare-log');
  expect(grab(log, /RSA verify: (true|false)/, 'the RSA verdict')).toBe('true');
  expect(grab(log, /EC verify:\s+(true|false)/, 'the EC verdict')).toBe('true');
});

// ════════════════════════════════════════════════════════════════
// Navigation the README promises a reader can drive
// ════════════════════════════════════════════════════════════════

test('all seven exhibits are reachable, exactly one at a time, by click and by arrow key', async ({ page }) => {
  await page.goto('.');
  const tabs = page.locator('[role="tab"]');
  await expect(tabs).toHaveCount(7);

  const ids = await tabs.evaluateAll((els) => els.map((e) => e.getAttribute('aria-controls') ?? ''));
  expect(ids).toEqual(['protocol', 'rfc9474', 'cash', 'voting', 'credentials', 'schnorr', 'compare']);

  for (const id of ids) {
    await page.locator(`#tab-${id}`).click();
    await expect(page.locator(`#${id}`)).toHaveClass(/\bactive\b/);
    // Exactly one panel and exactly one selected tab at a time.
    expect(await page.locator('.panel.active').count()).toBe(1);
    expect(await page.locator('[role="tab"][aria-selected="true"]').count()).toBe(1);
    await expect(page.locator(`#tab-${id}`)).toHaveAttribute('aria-selected', 'true');
    // Roving tabindex: only the selected tab is in the tab order.
    expect(await page.locator('[role="tab"]:not([tabindex="-1"])').count()).toBe(1);
  }

  // Arrow keys move the selection and wrap around.
  await page.locator('#tab-compare').press('ArrowRight');
  await expect(page.locator('#tab-protocol')).toHaveAttribute('aria-selected', 'true');
  await page.locator('#tab-protocol').press('ArrowLeft');
  await expect(page.locator('#tab-compare')).toHaveAttribute('aria-selected', 'true');
  await page.locator('#tab-compare').press('Home');
  await expect(page.locator('#tab-protocol')).toHaveAttribute('aria-selected', 'true');
  await page.locator('#tab-protocol').press('End');
  await expect(page.locator('#tab-compare')).toHaveAttribute('aria-selected', 'true');
});
