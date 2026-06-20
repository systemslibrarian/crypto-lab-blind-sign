import './style.css';
import {
  createRsaIssuer,
  createBlindRequest,
  unblindSignature,
  verifySignature,
  verifyMessageSignature,
  type RsaIssuer,
  type BlindRequest
} from './blind';
import { runEcBlindSignatureDemo, verifyEcBlindSignature, type EcBlindTranscript } from './ecblind';
import {
  createRfc9474Issuer,
  prepare as rfcPrepare,
  blind as rfcBlind,
  finalize as rfcFinalize,
  verify as rfcVerify,
  bytesToHex,
  VARIANTS,
  type Rfc9474Variant,
  type Rfc9474Issuer,
  type BlindResult
} from './rfc9474';

type Theme = 'dark' | 'light';

const state = {
  ecash: {
    bank: null as RsaIssuer | null,
    coin: null as { serial: string; signature: bigint } | null,
    spent: new Set<string>()
  },
  voting: {
    authority: null as RsaIssuer | null,
    token: null as { id: string; signature: bigint } | null,
    consumed: new Set<string>()
  },
  credential: {
    issuer: null as RsaIssuer | null,
    credential: null as { claim: string; signature: bigint } | null
  },
  ec: null as EcBlindTranscript | null
};

// ── Tabs ──────────────────────────────────────────────────────
const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
const panels = Array.from(document.querySelectorAll<HTMLElement>('[role="tabpanel"]'));

function activateTab(tab: HTMLButtonElement): void {
  const panelId = tab.dataset.panel;
  if (!panelId) return;

  for (const t of tabs) {
    t.classList.remove('active');
    t.setAttribute('aria-selected', 'false');
    t.setAttribute('tabindex', '-1');
  }
  for (const p of panels) {
    p.classList.remove('active');
  }

  tab.classList.add('active');
  tab.setAttribute('aria-selected', 'true');
  tab.removeAttribute('tabindex');
  tab.focus();

  document.getElementById(panelId)?.classList.add('active');
}

for (const tab of tabs) {
  tab.addEventListener('click', () => activateTab(tab));
}

const tablist = document.querySelector<HTMLElement>('[role="tablist"]');
if (tablist) {
  tablist.addEventListener('keydown', (e: KeyboardEvent) => {
    const current = tabs.findIndex((t) => t.getAttribute('aria-selected') === 'true');
    let next = -1;

    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
      e.preventDefault();
      next = (current + 1) % tabs.length;
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
      e.preventDefault();
      next = (current - 1 + tabs.length) % tabs.length;
    } else if (e.key === 'Home') {
      e.preventDefault();
      next = 0;
    } else if (e.key === 'End') {
      e.preventDefault();
      next = tabs.length - 1;
    }

    if (next >= 0) {
      activateTab(tabs[next]);
    }
  });
}

renderExhibits();
wireProtocolExhibit();
wireRfc9474Exhibit();
wireCashExhibit();
wireVotingExhibit();
wireCredentialExhibit();
wireSchnorrExhibit();
wireCompareExhibit();
setupThemeToggle();

// ── Shared helpers ────────────────────────────────────────────
function announce(message: string): void {
  const region = document.getElementById('aria-live-polite');
  if (region) {
    region.textContent = '';
    void region.offsetWidth;
    region.textContent = message;
  }
}

function setupThemeToggle(): void {
  const button = document.getElementById('theme-toggle') as HTMLButtonElement | null;
  const icon = document.getElementById('theme-icon');
  if (!button) return;

  const sync = (): void => {
    const current = currentTheme();
    if (icon) icon.textContent = current === 'dark' ? '🌙' : '☀️';
    button.setAttribute('aria-label', current === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  };

  button.addEventListener('click', () => {
    const next: Theme = currentTheme() === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    sync();
    announce(`Theme switched to ${next} mode`);
  });

  sync();
}

function currentTheme(): Theme {
  return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

/** Renders a colored PASS / FAIL verdict into a verdict element. */
function setVerdict(id: string, ok: boolean | null, label: string): void {
  const el = document.getElementById(id);
  if (!el) return;
  if (ok === null) {
    el.className = 'verdict';
    el.textContent = '';
    return;
  }
  el.className = `verdict ${ok ? 'pass' : 'fail'}`;
  el.textContent = label;
}

function enable(id: string, on: boolean): void {
  const el = document.getElementById(id) as HTMLButtonElement | null;
  if (el) el.disabled = !on;
}

/** Guards an async click handler against double-fire and toggles aria-busy. */
function withBusy(btn: HTMLButtonElement, fn: () => Promise<void>): () => Promise<void> {
  return async (): Promise<void> => {
    if (btn.disabled || btn.hasAttribute('aria-busy')) return;
    btn.setAttribute('aria-busy', 'true');
    try {
      await fn();
    } finally {
      btn.removeAttribute('aria-busy');
    }
  };
}

// ── Exhibit markup ────────────────────────────────────────────
function renderExhibits(): void {
  setHtml(
    'protocol',
    `
    <div class="card">
      <h2>Exhibit 1 &mdash; The Protocol</h2>
      <p>Run blind &rarr; sign &rarr; unblind &rarr; verify one real step at a time. Each button actually executes its
        arithmetic — the signer only ever touches blinded values. Then tamper with the result to watch verification reject it.</p>
      <div class="button-row" role="group" aria-label="Protocol steps">
        <button class="btn primary" id="protocol-blind" aria-label="Step 1: Blind the message">1 · Blind</button>
        <button class="btn" id="protocol-sign" aria-label="Step 2: Signer signs blinded message" disabled>2 · Sign</button>
        <button class="btn" id="protocol-unblind" aria-label="Step 3: Unblind the signature" disabled>3 · Unblind</button>
        <button class="btn" id="protocol-verify" aria-label="Step 4: Verify the unblinded signature" disabled>4 · Verify</button>
        <button class="btn danger" id="protocol-tamper" aria-label="Tamper with the signature and re-verify" disabled>Tamper &amp; re-verify</button>
      </div>
      <div class="protocol-grid">
        <div class="card inset" id="requester-view">
          <h3>Requester (Alice) View</h3>
          <pre id="requester-log" aria-label="Requester protocol transcript">Click 1 · Blind to start.</pre>
        </div>
        <div class="card inset" id="signer-view">
          <h3>Signer (Bank) View</h3>
          <pre id="signer-log" aria-label="Signer protocol transcript">Signer has not received a blinded request yet.</pre>
        </div>
      </div>
      <div class="flow-track" aria-hidden="true">
        <span class="flow-pill" id="flow-pill">blinding factor wraps message</span>
      </div>
      <div class="result-row">
        <span class="status-line" id="protocol-status" role="status" aria-live="polite"></span>
        <span class="verdict" id="protocol-verdict" aria-live="polite"></span>
      </div>
    </div>
  `
  );

  setHtml(
    'rfc9474',
    `
    <div class="card">
      <h2>Exhibit 2 &mdash; RFC 9474 Blind RSA (production)</h2>
      <p>The standardized blind-RSA protocol behind <strong>Privacy Pass</strong> and <strong>Apple Private Access
        Tokens</strong>. Where the textbook exhibit signs a bare <code>H(m) mod n</code>, RFC 9474 signs a full
        <strong>EMSA-PSS</strong> encoding (SHA-384 + MGF1 + salt). The finished signature is an ordinary RSASSA-PSS
        signature, so step 3 verifies it with the browser's own <code>crypto.subtle.verify</code> — an independent,
        standards-compliant check. This engine reproduces the RFC's official Appendix&nbsp;A test vectors byte-for-byte.</p>
      <fieldset class="variant-group">
        <legend>Variant</legend>
        <label><input type="radio" name="rfc-variant" value="RSABSSA-SHA384-PSS-Randomized" checked />
          Randomized &mdash; SHA-384 PSS, 48-byte salt + 32-byte message prefix (recommended)</label>
        <label><input type="radio" name="rfc-variant" value="RSABSSA-SHA384-PSSZERO-Deterministic" />
          Deterministic &mdash; PSSZERO, zero-length salt, no prefix</label>
      </fieldset>
      <div class="button-row" role="group" aria-label="RFC 9474 steps">
        <button class="btn primary" id="rfc-blind" aria-label="Step 1: Prepare and blind the message">1 · Prepare &amp; Blind</button>
        <button class="btn" id="rfc-sign" aria-label="Step 2: Issuer blind-signs" disabled>2 · Blind-Sign</button>
        <button class="btn" id="rfc-finalize" aria-label="Step 3: Finalize and verify natively" disabled>3 · Finalize &amp; Verify</button>
        <button class="btn danger" id="rfc-tamper" aria-label="Tamper with the signature and re-verify" disabled>Tamper &amp; re-verify</button>
      </div>
      <div class="protocol-grid">
        <div class="card inset">
          <h3>Requester (Alice) View</h3>
          <pre id="rfc-requester-log" aria-label="RFC 9474 requester transcript">Click 1 · Prepare &amp; Blind to start.</pre>
        </div>
        <div class="card inset">
          <h3>Signer (Issuer) View</h3>
          <pre id="rfc-signer-log" aria-label="RFC 9474 signer transcript">Signer has not received a blinded request yet.</pre>
        </div>
      </div>
      <div class="result-row">
        <span class="status-line" id="rfc-status" role="status" aria-live="polite"></span>
        <span class="verdict" id="rfc-verdict" aria-live="polite"></span>
      </div>
    </div>
  `
  );

  setHtml(
    'cash',
    `
    <div class="card">
      <h2>Exhibit 3 &mdash; Chaum's E-Cash</h2>
      <p>Issue a blind-signed coin, then spend it. The merchant runs <strong>two independent checks</strong>: the bank's
        signature must verify (unforgeability) <em>and</em> the serial must be unseen (no double spend). DigiCash launched
        in 1989; the privacy worked, the economics did not.</p>
      <div class="button-row" role="group" aria-label="E-Cash actions">
        <button class="btn primary" id="cash-issue" aria-label="Issue a new blind-signed coin">Issue Coin</button>
        <button class="btn" id="cash-spend" aria-label="Spend the coin at a merchant" disabled>Spend Coin</button>
        <button class="btn" id="cash-respend" aria-label="Attempt to spend the same coin again" disabled>Attempt Double Spend</button>
        <button class="btn danger" id="cash-forge" aria-label="Attempt to spend a forged coin" disabled>Spend Forged Coin</button>
      </div>
      <div class="result-row">
        <span class="status-line" id="cash-status" role="status" aria-live="polite"></span>
        <span class="verdict" id="cash-verdict" aria-live="polite"></span>
      </div>
      <pre id="cash-log" aria-label="E-Cash transaction log"></pre>
    </div>
  `
  );

  setHtml(
    'voting',
    `
    <div class="card">
      <h2>Exhibit 4 &mdash; Anonymous Voting</h2>
      <p>The authority issues one blind-signed ballot token. The ballot box verifies the authority's signature
        (eligibility) and that the token is unused (one-person-one-vote) — without ever linking the token to a voter.</p>
      <div class="form-row">
        <label for="vote-choice">Ballot choice</label>
        <select id="vote-choice" aria-describedby="vote-hint">
          <option value="Option A">Option A</option>
          <option value="Option B">Option B</option>
        </select>
        <span id="vote-hint" class="sr-only">Select which option to vote for</span>
      </div>
      <div class="button-row" role="group" aria-label="Voting actions">
        <button class="btn primary" id="vote-issue" aria-label="Request a blind-signed ballot token from the authority">Issue Ballot Token</button>
        <button class="btn" id="vote-submit" aria-label="Submit anonymous vote with the token" disabled>Submit Anonymous Vote</button>
        <button class="btn danger" id="vote-forge" aria-label="Submit a vote with a forged token" disabled>Submit Forged Token</button>
      </div>
      <div class="result-row">
        <span class="status-line" id="vote-status" role="status" aria-live="polite"></span>
        <span class="verdict" id="vote-verdict" aria-live="polite"></span>
      </div>
      <pre id="vote-log" aria-label="Voting transcript"></pre>
    </div>
  `
  );

  setHtml(
    'credentials',
    `
    <div class="card">
      <h2>Exhibit 5 &mdash; Anonymous Credentials</h2>
      <p>The issuer blind-signs an attribute claim like &ldquo;over 18.&rdquo; The verifier checks the issuer's signature
        on the exact claim — so a holder cannot swap in a stronger claim such as <code>over21=true</code> — yet learns
        nothing that identifies the holder.</p>
      <div class="button-row" role="group" aria-label="Credential actions">
        <button class="btn primary" id="cred-issue" aria-label="Issue a blind-signed over-18 credential">Issue over-18 Credential</button>
        <button class="btn" id="cred-present" aria-label="Present credential to verifier" disabled>Present Credential</button>
        <button class="btn danger" id="cred-forge" aria-label="Present a forged credential claiming a different attribute" disabled>Present Forged Claim</button>
      </div>
      <div class="result-row">
        <span class="status-line" id="cred-status" role="status" aria-live="polite"></span>
        <span class="verdict" id="cred-verdict" aria-live="polite"></span>
      </div>
      <pre id="cred-log" aria-label="Credential transcript"></pre>
      <p class="compare-note">Compared with BBS+ and W3C Verifiable Credential stacks, blind signatures prioritize issuer unlinkability at issuance time.</p>
    </div>
  `
  );

  setHtml(
    'schnorr',
    `
    <div class="card">
      <h2>Exhibit 6 &mdash; Schnorr Blind Signature (Ed25519)</h2>
      <p>The elliptic-curve cousin of RSA blinding. The requester blinds the signer's commitment with random scalars
        &alpha;, &beta; so the signer never sees the final challenge or signature. The pair (R&prime;, s) still verifies
        as <code>s·G = R&prime; + H(R&prime;,P,m)·P</code>. Run it, then tamper to see verification fail.</p>
      <div class="button-row" role="group" aria-label="Schnorr blind actions">
        <button class="btn primary" id="schnorr-run" aria-label="Run the blind Schnorr signature flow">Run Blind Schnorr</button>
        <button class="btn danger" id="schnorr-tamper" aria-label="Tamper with the signature scalar and re-verify" disabled>Tamper &amp; re-verify</button>
      </div>
      <div class="result-row">
        <span class="status-line" id="schnorr-status" role="status" aria-live="polite"></span>
        <span class="verdict" id="schnorr-verdict" aria-live="polite"></span>
      </div>
      <pre id="schnorr-log" aria-label="Schnorr blind signature transcript">Click Run Blind Schnorr to start.</pre>
    </div>
  `
  );

  setHtml(
    'compare',
    `
    <div class="card">
      <h2>Exhibit 7 &mdash; RSA vs EC Blind</h2>
      <p>Run both engines end to end and compare measured timings, key sizes, and security assumptions.</p>
      <div class="button-row">
        <button class="btn primary" id="compare-run" aria-label="Run RSA and EC blind signature timing comparison">Run Timing Comparison</button>
      </div>
      <div class="table-wrap">
        <table class="compare-table" aria-label="Comparison of RSA and EC blind signature characteristics">
          <thead>
            <tr><th scope="col">Metric</th><th scope="col">RSA Blind</th><th scope="col">Schnorr Blind (Ed25519)</th></tr>
          </thead>
          <tbody>
            <tr><td>Total demo runtime</td><td id="cmp-rsa-time">&mdash;</td><td id="cmp-ec-time">&mdash;</td></tr>
            <tr><td>Public key size</td><td>~256 bytes modulus</td><td>32 bytes</td></tr>
            <tr><td>Security margin model</td><td>Integer factorization hardness</td><td>Discrete log on Edwards curve</td></tr>
            <tr><td>Verification result</td><td id="cmp-rsa-ok">&mdash;</td><td id="cmp-ec-ok">&mdash;</td></tr>
          </tbody>
        </table>
      </div>
      <pre id="compare-log" aria-label="Comparison output log"></pre>
    </div>
  `
  );
}

// ── Exhibit 1: real step-by-step protocol ─────────────────────
function wireProtocolExhibit(): void {
  const requesterLog = byId('requester-log');
  const signerLog = byId('signer-log');
  const status = byId('protocol-status');
  const flow = byId('flow-pill');

  // Per-run protocol state. Reset on every Blind.
  let run: {
    issuer: RsaIssuer;
    request: BlindRequest;
    blindedSignature?: bigint;
    signature?: bigint;
  } | null = null;

  const blindBtn = byId('protocol-blind') as HTMLButtonElement;
  blindBtn.addEventListener(
    'click',
    withBusy(blindBtn, async () => {
      status.textContent = 'Generating RSA keypair and blinding message…';
      announce('Generating RSA keypair and blinding message');
      setVerdict('protocol-verdict', null, '');

      const issuer = await createRsaIssuer();
      const request = await createBlindRequest('Chaum blind signature request', issuer.publicKey);
      run = { issuer, request };

      requesterLog.textContent = [
        `m  = H(message) mod n = ${shortHex(request.messageRepresentative)}`,
        `r  = random, gcd(r,n)=1 = ${shortHex(request.blindingFactor)}`,
        `m' = m · r^e mod n     = ${shortHex(request.blindedMessage)}`
      ].join('\n');

      signerLog.textContent = [
        `Signer receives only: m' = ${shortHex(request.blindedMessage)}`,
        'Signer has not seen m or r.'
      ].join('\n');

      flow.textContent = 'message wrapped by blinding factor r';
      flow.classList.remove('animate');
      void flow.offsetWidth;
      flow.classList.add('animate');
      status.textContent = 'Blind complete. Hand m′ to the signer.';
      announce('Blind step complete. Message is now blinded.');

      enable('protocol-sign', true);
      enable('protocol-unblind', false);
      enable('protocol-verify', false);
      enable('protocol-tamper', false);
    })
  );

  byId('protocol-sign').addEventListener('click', () => {
    if (!run) return;
    const { n } = run.issuer.publicKey;
    run.blindedSignature = run.issuer.signBlinded(run.request.blindedMessage);
    signerLog.textContent = [
      `Signer input:  m' = ${shortHex(run.request.blindedMessage)}`,
      `Signer output: s' = (m')^d mod n = ${shortHex(run.blindedSignature)}`,
      `(modulus n = ${shortHex(n)})`
    ].join('\n');
    status.textContent = 'Sign complete. Blinded signature s′ returned.';
    announce('Sign step complete. Blinded signature produced.');
    enable('protocol-unblind', true);
  });

  byId('protocol-unblind').addEventListener('click', () => {
    if (!run || run.blindedSignature === undefined) return;
    const { n } = run.issuer.publicKey;
    run.signature = unblindSignature(run.blindedSignature, run.request.blindingFactor, n);
    requesterLog.textContent = [
      requesterLog.textContent,
      '',
      `s = s' · r^-1 mod n = ${shortHex(run.signature)}`,
      'Requester removed r. The signer never saw this value.'
    ].join('\n');
    flow.textContent = 'blinding removed, valid signature recovered';
    status.textContent = 'Unblind complete. Now verify it.';
    announce('Unblind step complete. Valid signature recovered.');
    enable('protocol-verify', true);
  });

  byId('protocol-verify').addEventListener('click', () => {
    if (!run || run.signature === undefined) return;
    const { n, e } = run.issuer.publicKey;
    const ok = verifySignature(run.signature, run.request.messageRepresentative, e, n);
    requesterLog.textContent = [
      requesterLog.textContent,
      '',
      `verify: s^e mod n == m  →  ${ok}`,
      'Unlinkability: the signer only ever held (m′, s′). Without r they',
      'cannot map the public (m, s) back to this issuance.'
    ].join('\n');
    setVerdict('protocol-verdict', ok, ok ? 'VALID' : 'INVALID');
    status.textContent = `Verify complete — signature is ${ok ? 'valid' : 'invalid'}.`;
    announce(`Verification ${ok ? 'passed' : 'failed'}. Signer cannot link signature to original message.`);
    enable('protocol-tamper', true);
  });

  byId('protocol-tamper').addEventListener('click', () => {
    if (!run || run.signature === undefined) return;
    const { n, e } = run.issuer.publicKey;
    const forged = (run.signature + 1n) % n; // flip the signature by one
    const ok = verifySignature(forged, run.request.messageRepresentative, e, n);
    requesterLog.textContent = [
      requesterLog.textContent,
      '',
      `Tampered signature s+1 = ${shortHex(forged)}`,
      `verify: (s+1)^e mod n == m  →  ${ok}`,
      'A single altered bit breaks the equation: forgery is rejected.'
    ].join('\n');
    setVerdict('protocol-verdict', ok, ok ? 'VALID' : 'REJECTED');
    status.textContent = 'Tampered signature rejected — this is unforgeability.';
    announce('Tampered signature rejected. Verification failed as expected.');
  });
}

// ── Exhibit 2: RFC 9474 production blind RSA ───────────────────
function selectedRfcVariant(): Rfc9474Variant {
  const checked = document.querySelector<HTMLInputElement>('input[name="rfc-variant"]:checked');
  return (checked?.value as Rfc9474Variant) ?? 'RSABSSA-SHA384-PSS-Randomized';
}

function wireRfc9474Exhibit(): void {
  const requesterLog = byId('rfc-requester-log');
  const signerLog = byId('rfc-signer-log');
  const status = byId('rfc-status');

  let run: {
    variant: Rfc9474Variant;
    issuer: Rfc9474Issuer;
    inputMsg: Uint8Array;
    prefix: Uint8Array;
    blinded: BlindResult;
    blindSig?: Uint8Array;
    signature?: Uint8Array;
  } | null = null;

  const resetSteps = (): void => {
    enable('rfc-sign', false);
    enable('rfc-finalize', false);
    enable('rfc-tamper', false);
  };

  // Changing the variant invalidates the current run.
  for (const radio of document.querySelectorAll<HTMLInputElement>('input[name="rfc-variant"]')) {
    radio.addEventListener('change', () => {
      run = null;
      resetSteps();
      setVerdict('rfc-verdict', null, '');
      requesterLog.textContent = 'Variant changed. Click 1 · Prepare & Blind to start.';
      signerLog.textContent = 'Signer has not received a blinded request yet.';
      status.textContent = '';
    });
  }

  const blindBtn = byId('rfc-blind') as HTMLButtonElement;
  blindBtn.addEventListener(
    'click',
    withBusy(blindBtn, async () => {
      const variant = selectedRfcVariant();
      status.textContent = 'Generating RSA-PSS keypair, EMSA-PSS encoding, and blinding…';
      announce('Preparing and blinding the message');
      setVerdict('rfc-verdict', null, '');

      const issuer = await createRfc9474Issuer();
      const msg = new TextEncoder().encode('Privacy Pass token: redeem-once');
      const prepared = rfcPrepare(msg, variant);
      const blinded = await rfcBlind(issuer.publicKey, prepared.inputMsg, variant);
      run = { variant, issuer, inputMsg: prepared.inputMsg, prefix: prepared.prefix, blinded };

      const saltLen = VARIANTS[variant].saltLen;
      requesterLog.textContent = [
        `variant = ${variant}`,
        VARIANTS[variant].randomize
          ? `prefix (32-byte random) = ${shortStr(bytesToHex(prepared.prefix))}`
          : 'prefix                  = (none — deterministic)',
        `salt (${saltLen}-byte)             = ${saltLen === 0 ? '(empty)' : shortStr(bytesToHex(blinded.salt))}`,
        `encoded_msg (EMSA-PSS)  = ${shortStr(bytesToHex(blinded.encodedMsg))}`,
        `blinded_msg = m·r^e     = ${shortStr(bytesToHex(blinded.blindedMsg))}`
      ].join('\n');

      signerLog.textContent = [
        `Signer receives only blinded_msg = ${shortStr(bytesToHex(blinded.blindedMsg))}`,
        'Signer sees neither the message nor the PSS salt.'
      ].join('\n');

      status.textContent = 'Blinded. Hand blinded_msg to the issuer.';
      announce('Message prepared and blinded.');
      enable('rfc-sign', true);
      enable('rfc-finalize', false);
      enable('rfc-tamper', false);
    })
  );

  byId('rfc-sign').addEventListener('click', () => {
    if (!run) return;
    run.blindSig = run.issuer.blindSign(run.blinded.blindedMsg);
    signerLog.textContent = [
      `Signer input:  blinded_msg = ${shortStr(bytesToHex(run.blinded.blindedMsg))}`,
      `Signer output: blind_sig   = ${shortStr(bytesToHex(run.blindSig))}`,
      'Signed with the RFC fault check (s^e mod n == blinded_msg).'
    ].join('\n');
    status.textContent = 'Blind-signed. Now finalize and verify.';
    announce('Issuer returned the blind signature.');
    enable('rfc-finalize', true);
  });

  const finalizeBtn = byId('rfc-finalize') as HTMLButtonElement;
  finalizeBtn.addEventListener(
    'click',
    withBusy(finalizeBtn, async () => {
      if (!run || !run.blindSig) return;
      const { n, modulusLen } = run.issuer.publicKey;
      run.signature = rfcFinalize(run.blindSig, run.blinded.inv, n, modulusLen);
      const ok = await rfcVerify(run.issuer.publicKey, run.inputMsg, run.signature, run.variant);
      requesterLog.textContent = [
        requesterLog.textContent,
        '',
        `signature = blind_sig·r^-1 = ${shortStr(bytesToHex(run.signature))}`,
        `native crypto.subtle.verify (RSA-PSS) → ${ok}`,
        'This is a standard RSASSA-PSS signature — the browser itself accepts it.'
      ].join('\n');
      setVerdict('rfc-verdict', ok, ok ? 'VALID' : 'INVALID');
      status.textContent = `Finalized — natively verified ${ok ? 'valid' : 'invalid'}.`;
      announce(`Signature natively verified ${ok ? 'valid' : 'invalid'}.`);
      enable('rfc-tamper', true);
    })
  );

  const tamperBtn = byId('rfc-tamper') as HTMLButtonElement;
  tamperBtn.addEventListener(
    'click',
    withBusy(tamperBtn, async () => {
      if (!run || !run.signature) return;
      const tampered = run.signature.slice();
      tampered[tampered.length - 1] ^= 0x01; // flip one bit
      const ok = await rfcVerify(run.issuer.publicKey, run.inputMsg, tampered, run.variant);
      requesterLog.textContent = [
        requesterLog.textContent,
        '',
        `tampered signature (1 bit flipped) = ${shortStr(bytesToHex(tampered))}`,
        `native crypto.subtle.verify → ${ok}`,
        'The browser rejects the altered signature: unforgeability.'
      ].join('\n');
      setVerdict('rfc-verdict', ok, ok ? 'VALID' : 'REJECTED');
      status.textContent = 'Tampered signature rejected by the native verifier.';
      announce('Tampered signature rejected.');
    })
  );
}

// ── Exhibit 3: e-cash with real signature verification ────────
function wireCashExhibit(): void {
  const status = byId('cash-status');
  const log = byId('cash-log');

  async function bank(): Promise<RsaIssuer> {
    if (!state.ecash.bank) state.ecash.bank = await createRsaIssuer();
    return state.ecash.bank;
  }

  const issueBtn = byId('cash-issue') as HTMLButtonElement;
  issueBtn.addEventListener(
    'click',
    withBusy(issueBtn, async () => {
      status.textContent = 'Issuing blind-signed coin…';
      announce('Issuing blind-signed coin');
      setVerdict('cash-verdict', null, '');

      const issuer = await bank();
      const serial = randomToken('COIN');
      const request = await createBlindRequest(serial, issuer.publicKey);
      const blindedSig = issuer.signBlinded(request.blindedMessage);
      const signature = unblindSignature(blindedSig, request.blindingFactor, issuer.publicKey.n);
      state.ecash.coin = { serial, signature };

      status.textContent = 'Bank issued a blind-signed coin.';
      announce('Coin issued. Bank signed a blinded serial and cannot link it to you.');
      log.textContent = [
        `Coin serial:  ${serial}`,
        `Signature:    ${shortHex(signature)}`,
        'The bank signed a blinded serial; it never saw this serial in the clear.'
      ].join('\n');

      enable('cash-spend', true);
      enable('cash-respend', true);
      enable('cash-forge', true);
    })
  );

  const spendBtn = byId('cash-spend') as HTMLButtonElement;
  spendBtn.addEventListener(
    'click',
    withBusy(spendBtn, async () => {
      const coin = state.ecash.coin;
      if (!coin) return;
      const issuer = await bank();
      const sigOk = await verifyMessageSignature(issuer.publicKey, coin.serial, coin.signature);
      const fresh = !state.ecash.spent.has(coin.serial);

      if (sigOk && fresh) {
        state.ecash.spent.add(coin.serial);
        setVerdict('cash-verdict', true, 'ACCEPTED');
        status.textContent = 'Merchant accepted the coin.';
        announce('Coin accepted. Signature valid and serial unseen.');
        log.textContent = appendLines(log.textContent, [
          `Spend ${coin.serial}`,
          `  signature valid?  ${sigOk}  (bank's key authorizes it)`,
          `  serial unseen?    ${fresh}  (no double spend)`,
          '  → accepted, payer anonymity preserved.'
        ]);
      } else {
        setVerdict('cash-verdict', false, 'REJECTED');
        status.textContent = 'Merchant rejected the coin.';
        announce('Coin rejected.');
        log.textContent = appendLines(log.textContent, [
          `Spend ${coin.serial} → rejected`,
          `  signature valid?  ${sigOk}`,
          `  serial unseen?    ${fresh}`
        ]);
      }
    })
  );

  const respendBtn = byId('cash-respend') as HTMLButtonElement;
  respendBtn.addEventListener(
    'click',
    withBusy(respendBtn, async () => {
      const coin = state.ecash.coin;
      if (!coin) return;
      const issuer = await bank();
      const sigOk = await verifyMessageSignature(issuer.publicKey, coin.serial, coin.signature);
      const fresh = !state.ecash.spent.has(coin.serial);

      if (!fresh) {
        setVerdict('cash-verdict', false, 'DOUBLE SPEND');
        status.textContent = 'Double-spend detected — serial already redeemed.';
        announce('Double spend detected. Serial already redeemed.');
        log.textContent = appendLines(log.textContent, [
          `Re-spend ${coin.serial}`,
          `  signature valid?  ${sigOk}  (still a genuine coin!)`,
          `  serial unseen?    ${fresh}  (already in the spent registry)`,
          '  → blocked. A valid signature is not enough; freshness is enforced too.'
        ]);
      } else {
        status.textContent = 'Spend the coin once before attempting a double spend.';
        announce('Spend the coin first before attempting a double spend.');
      }
    })
  );

  const forgeBtn = byId('cash-forge') as HTMLButtonElement;
  forgeBtn.addEventListener(
    'click',
    withBusy(forgeBtn, async () => {
      const issuer = await bank();
      // A counterfeiter mints a fresh serial but has no access to the bank's key d,
      // so they can only attach a bogus signature.
      const serial = randomToken('FAKE');
      const signature = randomBigIntBelow(issuer.publicKey.n);
      const sigOk = await verifyMessageSignature(issuer.publicKey, serial, signature);
      setVerdict('cash-verdict', sigOk, sigOk ? 'ACCEPTED' : 'REJECTED');
      status.textContent = 'Forged coin rejected — signature does not verify.';
      announce('Forged coin rejected. Signature invalid.');
      log.textContent = appendLines(log.textContent, [
        `Spend forged ${serial}`,
        `  signature valid?  ${sigOk}  (no bank key → cannot forge)`,
        '  → rejected before the serial is even checked.'
      ]);
    })
  );
}

// ── Exhibit 3: anonymous voting ───────────────────────────────
function wireVotingExhibit(): void {
  const status = byId('vote-status');
  const log = byId('vote-log');
  const select = byId('vote-choice') as HTMLSelectElement;

  async function authority(): Promise<RsaIssuer> {
    if (!state.voting.authority) state.voting.authority = await createRsaIssuer();
    return state.voting.authority;
  }

  const issueBtn = byId('vote-issue') as HTMLButtonElement;
  issueBtn.addEventListener(
    'click',
    withBusy(issueBtn, async () => {
      status.textContent = 'Issuing ballot token…';
      announce('Issuing anonymous ballot token');
      setVerdict('vote-verdict', null, '');

      const issuer = await authority();
      const id = randomToken('BALLOT');
      const request = await createBlindRequest(id, issuer.publicKey);
      const blindedSig = issuer.signBlinded(request.blindedMessage);
      const signature = unblindSignature(blindedSig, request.blindingFactor, issuer.publicKey.n);
      state.voting.token = { id, signature };

      status.textContent = 'Authority issued one blind-signed ballot token.';
      announce('Ballot token issued. Authority cannot link the token to a voter.');
      log.textContent = [
        `Token: ${id}`,
        'Authority signed a blinded token; it cannot link this token to a voter or choice.'
      ].join('\n');

      enable('vote-submit', true);
      enable('vote-forge', true);
    })
  );

  const submitBtn = byId('vote-submit') as HTMLButtonElement;
  submitBtn.addEventListener(
    'click',
    withBusy(submitBtn, async () => {
      const token = state.voting.token;
      if (!token) return;
      const issuer = await authority();
      const sigOk = await verifyMessageSignature(issuer.publicKey, token.id, token.signature);
      const fresh = !state.voting.consumed.has(token.id);
      const choice = select.value;

      if (sigOk && fresh) {
        state.voting.consumed.add(token.id);
        setVerdict('vote-verdict', true, 'COUNTED');
        status.textContent = `Anonymous vote for ${choice} accepted.`;
        announce(`Vote for ${choice} accepted anonymously.`);
        log.textContent = appendLines(log.textContent, [
          `Submit vote "${choice}" with ${token.id}`,
          `  token signature valid?  ${sigOk}  (eligible voter)`,
          `  token unused?           ${fresh}  (one person, one vote)`,
          '  → counted; the ballot box cannot tell who cast it.'
        ]);
      } else {
        setVerdict('vote-verdict', false, fresh ? 'REJECTED' : 'ALREADY VOTED');
        status.textContent = fresh ? 'Vote rejected: invalid token.' : 'Vote rejected: token already used.';
        announce(fresh ? 'Vote rejected. Token invalid.' : 'Vote rejected. Token already used.');
        log.textContent = appendLines(log.textContent, [
          `Submit vote "${choice}" with ${token.id}`,
          `  token signature valid?  ${sigOk}`,
          `  token unused?           ${fresh}`,
          '  → rejected.'
        ]);
      }
    })
  );

  const forgeBtn = byId('vote-forge') as HTMLButtonElement;
  forgeBtn.addEventListener(
    'click',
    withBusy(forgeBtn, async () => {
      const issuer = await authority();
      const id = randomToken('FAKE');
      const signature = randomBigIntBelow(issuer.publicKey.n);
      const sigOk = await verifyMessageSignature(issuer.publicKey, id, signature);
      setVerdict('vote-verdict', sigOk, sigOk ? 'COUNTED' : 'REJECTED');
      status.textContent = 'Forged token rejected — not signed by the authority.';
      announce('Forged ballot token rejected.');
      log.textContent = appendLines(log.textContent, [
        `Submit vote with forged ${id}`,
        `  token signature valid?  ${sigOk}  (no authority key → cannot forge)`,
        '  → rejected; ballot stuffing prevented.'
      ]);
    })
  );
}

// ── Exhibit 4: anonymous credentials ──────────────────────────
function wireCredentialExhibit(): void {
  const status = byId('cred-status');
  const log = byId('cred-log');
  const VALID_CLAIM = 'attribute:over18=true';

  async function issuer(): Promise<RsaIssuer> {
    if (!state.credential.issuer) state.credential.issuer = await createRsaIssuer();
    return state.credential.issuer;
  }

  const issueBtn = byId('cred-issue') as HTMLButtonElement;
  issueBtn.addEventListener(
    'click',
    withBusy(issueBtn, async () => {
      status.textContent = 'Issuing blind-signed credential…';
      announce('Issuing blind-signed age credential');
      setVerdict('cred-verdict', null, '');

      const iss = await issuer();
      const request = await createBlindRequest(VALID_CLAIM, iss.publicKey);
      const blindedSig = iss.signBlinded(request.blindedMessage);
      const signature = unblindSignature(blindedSig, request.blindingFactor, iss.publicKey.n);
      state.credential.credential = { claim: VALID_CLAIM, signature };

      status.textContent = 'Issuer produced a blind-signed age credential.';
      announce('Age credential issued. Issuer cannot identify the holder.');
      log.textContent = [
        'Claim issued: over18=true',
        'Issuer signed only the blinded attribute request; it cannot identify the holder.'
      ].join('\n');

      enable('cred-present', true);
      enable('cred-forge', true);
    })
  );

  const presentBtn = byId('cred-present') as HTMLButtonElement;
  presentBtn.addEventListener(
    'click',
    withBusy(presentBtn, async () => {
      const cred = state.credential.credential;
      if (!cred) return;
      const iss = await issuer();
      const ok = await verifyMessageSignature(iss.publicKey, cred.claim, cred.signature);
      setVerdict('cred-verdict', ok, ok ? 'VALID' : 'INVALID');
      status.textContent = ok ? 'Verifier accepted the claim.' : 'Verifier rejected the claim.';
      announce(ok ? 'Credential verified. Verifier cannot identify the subject.' : 'Credential rejected.');
      log.textContent = appendLines(log.textContent, [
        `Present "${cred.claim}"`,
        `  issuer signature valid?  ${ok}`,
        '  → claim accepted; the verifier still cannot identify the subject.'
      ]);
    })
  );

  const forgeBtn = byId('cred-forge') as HTMLButtonElement;
  forgeBtn.addEventListener(
    'click',
    withBusy(forgeBtn, async () => {
      const cred = state.credential.credential;
      const iss = await issuer();
      // The holder edits the claim they actually want, but the issuer only ever
      // signed over18=true — the signature no longer matches the altered claim.
      const forgedClaim = 'attribute:over21=true';
      const signature = cred ? cred.signature : randomBigIntBelow(iss.publicKey.n);
      const ok = await verifyMessageSignature(iss.publicKey, forgedClaim, signature);
      setVerdict('cred-verdict', ok, ok ? 'VALID' : 'REJECTED');
      status.textContent = 'Altered claim rejected — signature is bound to the exact attribute.';
      announce('Forged credential claim rejected.');
      log.textContent = appendLines(log.textContent, [
        `Present altered "${forgedClaim}" reusing the over18 signature`,
        `  issuer signature valid?  ${ok}  (signature is bound to the signed claim)`,
        '  → rejected; attributes cannot be upgraded.'
      ]);
    })
  );
}

// ── Exhibit 5: blind Schnorr over Ed25519 ─────────────────────
function wireSchnorrExhibit(): void {
  const status = byId('schnorr-status');
  const log = byId('schnorr-log');

  const runBtn = byId('schnorr-run') as HTMLButtonElement;
  runBtn.addEventListener(
    'click',
    withBusy(runBtn, async () => {
      status.textContent = 'Running blind Schnorr over Ed25519…';
      announce('Running blind Schnorr signature');
      setVerdict('schnorr-verdict', null, '');

      const t = await runEcBlindSignatureDemo('Schnorr blind signature request');
      state.ec = t;

      log.textContent = [
        'Signer secret x is private; public P is shared.',
        `P  (public key)      = ${shortStr(t.publicKeyHex)}`,
        `R0 (signer commit)   = ${shortStr(t.signerNonceCommitmentHex)}`,
        '— requester blinds with random scalars —',
        `α                    = ${shortStr(t.alphaHex)}`,
        `β                    = ${shortStr(t.betaHex)}`,
        `R' = R0 + αG + βP    = ${shortStr(t.blindedCommitmentHex)}`,
        `c  = H(R',P,m)       = ${shortStr(t.challengeHex)}`,
        `c' = c + β  (to signer) = ${shortStr(t.blindedChallengeHex)}`,
        `s0 = k + c'·x (signer) = ${shortStr(t.partialSignatureHex)}`,
        `s  = s0 + α  (unblind) = ${shortStr(t.signatureSHex)}`,
        '',
        `verify: s·G == R' + c·P  →  ${t.verified}`,
        'The signer only saw (R0, c′, s0) — never m, R′, or s.'
      ].join('\n');

      setVerdict('schnorr-verdict', t.verified, t.verified ? 'VALID' : 'INVALID');
      status.textContent = `Blind Schnorr complete — signature is ${t.verified ? 'valid' : 'invalid'}.`;
      announce(`Blind Schnorr verification ${t.verified ? 'passed' : 'failed'}.`);
      enable('schnorr-tamper', true);
    })
  );

  byId('schnorr-tamper').addEventListener('click', () => {
    const t = state.ec;
    if (!t) return;
    // Flip the signature scalar s by one and re-verify.
    const tampered = (BigInt(`0x${t.signatureSHex}`) + 1n).toString(16).padStart(64, '0');
    const ok = verifyEcBlindSignature(t.signatureRHex, t.publicKeyHex, t.messageText, tampered);
    log.textContent = appendLines(log.textContent, [
      `Tampered s+1 = ${shortStr(tampered)}`,
      `verify: (s+1)·G == R' + c·P  →  ${ok}`,
      'Altering the scalar breaks the curve equation: rejected.'
    ]);
    setVerdict('schnorr-verdict', ok, ok ? 'VALID' : 'REJECTED');
    status.textContent = 'Tampered Schnorr signature rejected.';
    announce('Tampered Schnorr signature rejected.');
  });
}

// ── Exhibit 6: timing comparison ──────────────────────────────
function wireCompareExhibit(): void {
  const log = byId('compare-log');

  const compareBtn = byId('compare-run') as HTMLButtonElement;
  compareBtn.addEventListener(
    'click',
    withBusy(compareBtn, async () => {
      log.textContent = 'Running RSA blind and EC blind demos for timing…';
      announce('Running timing comparison between RSA and EC blind signatures');

      const rsaStart = performance.now();
      const issuer = await createRsaIssuer();
      const request = await createBlindRequest('timing sample', issuer.publicKey);
      const blindedSig = issuer.signBlinded(request.blindedMessage);
      const sig = unblindSignature(blindedSig, request.blindingFactor, issuer.publicKey.n);
      const rsaOk = verifySignature(sig, request.messageRepresentative, issuer.publicKey.e, issuer.publicKey.n);
      const rsaMs = performance.now() - rsaStart;

      const ecStart = performance.now();
      const ec = await runEcBlindSignatureDemo('timing sample');
      const ecMs = performance.now() - ecStart;

      byId('cmp-rsa-time').textContent = `${rsaMs.toFixed(2)} ms`;
      byId('cmp-ec-time').textContent = `${ecMs.toFixed(2)} ms`;
      byId('cmp-rsa-ok').textContent = rsaOk ? 'valid' : 'invalid';
      byId('cmp-ec-ok').textContent = ec.verified ? 'valid' : 'invalid';

      log.textContent = [
        `RSA verify: ${rsaOk}`,
        `EC verify:  ${ec.verified}`,
        '',
        'RSA blind signatures need a large 2048-bit modulus and modular exponentiation.',
        'Ed25519 blind Schnorr uses 32-byte keys and fast curve-scalar multiplication.',
        'Most RSA time is keypair generation; both verify in well under a millisecond.'
      ].join('\n');

      announce(`Comparison complete. RSA: ${rsaMs.toFixed(0)}ms, EC: ${ecMs.toFixed(0)}ms. Both verified.`);
    })
  );
}

// ── DOM / formatting utilities ────────────────────────────────
function setHtml(id: string, html: string): void {
  const target = document.getElementById(id);
  if (target) target.innerHTML = html;
}

function byId(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element: ${id}`);
  return el;
}

function appendLines(existing: string, lines: string[]): string {
  return [existing, '', ...lines].join('\n');
}

function shortHex(value: bigint): string {
  return `0x${shortStr(value.toString(16))}`;
}

function shortStr(hex: string): string {
  if (hex.length <= 28) return hex;
  return `${hex.slice(0, 12)}…${hex.slice(-12)}`;
}

function randomToken(prefix: string): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${prefix}-${hex}`;
}

function randomBigIntBelow(modulus: bigint): bigint {
  const bytes = new Uint8Array(256);
  crypto.getRandomValues(bytes);
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return (value % (modulus - 1n)) + 1n;
}
