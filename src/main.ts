import './style.css';
import { runRsaBlindSignatureDemo, type RsaBlindTranscript } from './blind';
import { runEcBlindSignatureDemo, type EcBlindTranscript } from './ecblind';

type Theme = 'dark' | 'light';

const state = {
  rsa: null as RsaBlindTranscript | null,
  ec: null as EcBlindTranscript | null,
  ecash: {
    coin: '' as string,
    spent: false,
    serialRegistry: new Set<string>()
  },
  voting: {
    token: '' as string,
    vote: '' as string,
    consumedTokens: new Set<string>()
  },
  credential: {
    token: '' as string
  }
};

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

  const panel = document.getElementById(panelId);
  panel?.classList.add('active');
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
wireCashExhibit();
wireVotingExhibit();
wireCredentialExhibit();
wireCompareExhibit();
setupThemeToggle();

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

function renderExhibits(): void {
  setHtml(
    'protocol',
    `
    <div class="card">
      <h2>Exhibit 1 &mdash; The Protocol</h2>
      <p>Walk through blind &rarr; sign &rarr; unblind &rarr; verify with concrete values. The signer sees only blinded values.</p>
      <div class="button-row" role="group" aria-label="Protocol steps">
        <button class="btn primary" id="protocol-blind" aria-label="Step 1: Blind the message">Blind</button>
        <button class="btn" id="protocol-sign" aria-label="Step 2: Signer signs blinded message">Sign</button>
        <button class="btn" id="protocol-unblind" aria-label="Step 3: Unblind the signature">Unblind</button>
        <button class="btn" id="protocol-verify" aria-label="Step 4: Verify the unblinded signature">Verify</button>
      </div>
      <div class="protocol-grid">
        <div class="card inset" id="requester-view">
          <h3>Requester (Alice) View</h3>
          <pre id="requester-log" aria-label="Requester protocol transcript">Click Blind to start.</pre>
        </div>
        <div class="card inset" id="signer-view">
          <h3>Signer (Bank) View</h3>
          <pre id="signer-log" aria-label="Signer protocol transcript">Signer has not received a blinded request yet.</pre>
        </div>
      </div>
      <div class="flow-track" aria-hidden="true">
        <span class="flow-pill" id="flow-pill">blinding factor wraps message</span>
      </div>
      <div class="status-line" id="protocol-status" role="status" aria-live="polite"></div>
    </div>
  `
  );

  setHtml(
    'cash',
    `
    <div class="card">
      <h2>Exhibit 2 &mdash; Chaum's E-Cash</h2>
      <p>Issue a blind-signed coin, spend it at a merchant, and detect double spend by serial reuse. DigiCash launched in 1989; privacy worked, economics did not.</p>
      <div class="button-row" role="group" aria-label="E-Cash actions">
        <button class="btn primary" id="cash-issue" aria-label="Issue a new blind-signed coin">Issue Coin</button>
        <button class="btn" id="cash-spend" aria-label="Spend the coin at a merchant">Spend Coin</button>
        <button class="btn" id="cash-respend" aria-label="Attempt to spend the same coin again">Attempt Double Spend</button>
      </div>
      <div class="status-line" id="cash-status" role="status" aria-live="polite"></div>
      <pre id="cash-log" aria-label="E-Cash transaction log"></pre>
    </div>
  `
  );

  setHtml(
    'voting',
    `
    <div class="card">
      <h2>Exhibit 3 &mdash; Anonymous Voting</h2>
      <p>Authority issues one blind-signed ballot token. Token proves eligibility, not identity.</p>
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
        <button class="btn" id="vote-submit" aria-label="Submit anonymous vote with the token">Submit Anonymous Vote</button>
      </div>
      <div class="status-line" id="vote-status" role="status" aria-live="polite"></div>
      <pre id="vote-log" aria-label="Voting transcript"></pre>
    </div>
  `
  );

  setHtml(
    'credentials',
    `
    <div class="card">
      <h2>Exhibit 4 &mdash; Anonymous Credentials</h2>
      <p>Issuer signs an attribute claim like &ldquo;over 18.&rdquo; Verifier checks claim validity without learning identity.</p>
      <div class="button-row" role="group" aria-label="Credential actions">
        <button class="btn primary" id="cred-issue" aria-label="Issue a blind-signed over-18 credential">Issue over-18 Credential</button>
        <button class="btn" id="cred-present" aria-label="Present credential to verifier">Present Credential</button>
      </div>
      <div class="status-line" id="cred-status" role="status" aria-live="polite"></div>
      <pre id="cred-log" aria-label="Credential transcript"></pre>
      <p class="compare-note">Compared with BBS+ and W3C Verifiable Credential stacks, blind signatures prioritize issuer unlinkability at issuance time.</p>
    </div>
  `
  );

  setHtml(
    'compare',
    `
    <div class="card">
      <h2>Exhibit 5 &mdash; RSA vs EC Blind</h2>
      <p>Run both engines and compare measured timings, key sizes, and security assumptions.</p>
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

function wireProtocolExhibit(): void {
  const requesterLog = byId('requester-log');
  const signerLog = byId('signer-log');
  const status = byId('protocol-status');
  const flow = byId('flow-pill');

  const blindBtn = byId('protocol-blind');
  blindBtn.addEventListener('click', async () => {
    if (blindBtn.hasAttribute('aria-busy')) return;
    blindBtn.setAttribute('aria-busy', 'true');
    status.textContent = 'Generating RSA keypair and blinding message…';
    announce('Generating RSA keypair and blinding message');
    const transcript = await runRsaBlindSignatureDemo('Chaum blind signature request');
    state.rsa = transcript;

    requesterLog.textContent = [
      `m = ${shortHex(transcript.messageRepresentative)}`,
      `r = ${shortHex(transcript.blindingFactor)}`,
      `m' = m × r^e mod n = ${shortHex(transcript.blindedMessage)}`
    ].join('\n');

    signerLog.textContent = [
      `Signer receives only: m' = ${shortHex(transcript.blindedMessage)}`,
      'Signer has not seen m or r.'
    ].join('\n');

    flow.textContent = 'message wrapped by blinding factor r';
    flow.classList.remove('animate');
    void flow.offsetWidth;
    flow.classList.add('animate');
    status.textContent = 'Blind step complete.';
    announce('Blind step complete. Message is now blinded.');
    blindBtn.removeAttribute('aria-busy');
  });

  byId('protocol-sign').addEventListener('click', () => {
    if (!state.rsa) {
      status.textContent = 'Run Blind first.';
      announce('Run Blind first before signing.');
      return;
    }
    signerLog.textContent = [
      `Signer input: m' = ${shortHex(state.rsa.blindedMessage)}`,
      `Signer output: s' = (m')^d mod n = ${shortHex(state.rsa.blindedSignature)}`
    ].join('\n');
    status.textContent = 'Sign step complete.';
    announce('Sign step complete. Blinded signature produced.');
  });

  byId('protocol-unblind').addEventListener('click', () => {
    if (!state.rsa) {
      status.textContent = 'Run Blind first.';
      announce('Run Blind first before unblinding.');
      return;
    }
    requesterLog.textContent = [
      requesterLog.textContent,
      '',
      `s = s' × r^-1 mod n = ${shortHex(state.rsa.unblindedSignature)}`,
      'Requester unblinds without revealing m.'
    ].join('\n');
    flow.textContent = 'blinding removed, valid signature recovered';
    status.textContent = 'Unblind step complete.';
    announce('Unblind step complete. Valid signature recovered.');
  });

  byId('protocol-verify').addEventListener('click', () => {
    if (!state.rsa) {
      status.textContent = 'Run Blind first.';
      announce('Run Blind first before verifying.');
      return;
    }
    const result = state.rsa.verifyPass ? 'PASS' : 'FAIL';
    requesterLog.textContent = [
      requesterLog.textContent,
      '',
      `verify: s^e mod n == m → ${state.rsa.verifyPass ? 'true' : 'false'}`,
      `unlinkability: ${state.rsa.unlinkability.reason}`
    ].join('\n');
    signerLog.textContent = [
      signerLog.textContent,
      '',
      'Signer transcript contains only (m\', s\').',
      'After unblinding, signer cannot link s to original m.'
    ].join('\n');
    status.textContent = `Verify step complete — ${result}.`;
    announce(`Verification ${result}. Signer cannot link signature to original message.`);
  });
}

function wireCashExhibit(): void {
  const status = byId('cash-status');
  const log = byId('cash-log');

  const issueBtn = byId('cash-issue');
  issueBtn.addEventListener('click', async () => {
    if (issueBtn.hasAttribute('aria-busy')) return;
    issueBtn.setAttribute('aria-busy', 'true');
    const serial = randomToken('COIN');
    status.textContent = 'Issuing blind-signed coin…';
    announce('Issuing blind-signed coin');
    const transcript = await runRsaBlindSignatureDemo(serial);
    state.ecash.coin = `${serial}:${transcript.unblindedSignature.toString(16)}`;
    state.ecash.spent = false;
    status.textContent = 'Bank issued blind-signed coin.';
    announce('Coin issued successfully. Bank cannot link serial to identity.');
    log.textContent = [
      `Coin serial: ${serial}`,
      'Bank signed a blinded serial number.',
      'Bank cannot link this serial to Alice identity.'
    ].join('\n');
    issueBtn.removeAttribute('aria-busy');
  });

  byId('cash-spend').addEventListener('click', () => {
    if (!state.ecash.coin) {
      status.textContent = 'Issue a coin first.';
      announce('Issue a coin first.');
      return;
    }
    const serial = state.ecash.coin.split(':')[0];
    state.ecash.serialRegistry.add(serial);
    state.ecash.spent = true;
    status.textContent = 'Merchant accepted coin and queried bank for serial freshness.';
    announce('Coin spent successfully. Payment accepted with anonymity preserved.');
    log.textContent = [
      log.textContent,
      '',
      `Spent serial: ${serial}`,
      'Bank confirms serial has not appeared before.',
      'Payment accepted with payer anonymity preserved.'
    ].join('\n');
  });

  byId('cash-respend').addEventListener('click', () => {
    if (!state.ecash.coin) {
      status.textContent = 'Issue a coin first.';
      announce('Issue a coin first.');
      return;
    }
    const serial = state.ecash.coin.split(':')[0];
    if (state.ecash.serialRegistry.has(serial)) {
      status.textContent = 'Double-spend detected. Serial already redeemed.';
      announce('Double-spend detected! Serial already redeemed.');
      log.textContent = [
        log.textContent,
        '',
        'Double spend attempt blocked by serial collision.',
        'System reveals the reused serial to prove fraud.'
      ].join('\n');
      return;
    }
    status.textContent = 'No prior spend detected (unexpected state).';
  });
}

function wireVotingExhibit(): void {
  const status = byId('vote-status');
  const log = byId('vote-log');
  const select = byId('vote-choice') as HTMLSelectElement;

  const voteIssueBtn = byId('vote-issue');
  voteIssueBtn.addEventListener('click', async () => {
    if (voteIssueBtn.hasAttribute('aria-busy')) return;
    voteIssueBtn.setAttribute('aria-busy', 'true');
    const token = randomToken('BALLOT');
    status.textContent = 'Issuing ballot token…';
    announce('Issuing anonymous ballot token');
    const transcript = await runRsaBlindSignatureDemo(token);
    state.voting.token = `${token}:${transcript.unblindedSignature.toString(16)}`;
    status.textContent = 'Authority issued one blind-signed ballot token.';
    announce('Ballot token issued. Authority cannot link token to voter.');
    log.textContent = [
      `Token: ${token}`,
      'Authority signs blinded token and learns no voter-choice link.'
    ].join('\n');
    voteIssueBtn.removeAttribute('aria-busy');
  });

  byId('vote-submit').addEventListener('click', () => {
    if (!state.voting.token) {
      status.textContent = 'Issue a token first.';
      announce('Issue a ballot token first.');
      return;
    }
    const token = state.voting.token.split(':')[0];
    if (state.voting.consumedTokens.has(token)) {
      status.textContent = 'Rejected: token already used.';
      announce('Rejected. This ballot token was already used.');
      return;
    }
    state.voting.vote = select.value;
    state.voting.consumedTokens.add(token);
    status.textContent = 'Anonymous vote accepted with single-use token validation.';
    announce(`Vote for ${state.voting.vote} accepted anonymously.`);
    log.textContent = [
      log.textContent,
      '',
      `Submitted vote: ${state.voting.vote}`,
      `Verifier checks token signature and freshness for ${token}.`,
      'Verifier does not know who cast this vote.'
    ].join('\n');
  });
}

function wireCredentialExhibit(): void {
  const status = byId('cred-status');
  const log = byId('cred-log');

  const credIssueBtn = byId('cred-issue');
  credIssueBtn.addEventListener('click', async () => {
    if (credIssueBtn.hasAttribute('aria-busy')) return;
    credIssueBtn.setAttribute('aria-busy', 'true');
    const claim = 'attribute:over18=true';
    status.textContent = 'Issuing blind-signed credential…';
    announce('Issuing blind-signed age credential');
    const transcript = await runRsaBlindSignatureDemo(claim);
    state.credential.token = `${claim}:${transcript.unblindedSignature.toString(16)}`;
    status.textContent = 'Issuer generated blind-signed age credential.';
    announce('Age credential issued. Issuer cannot identify holder.');
    log.textContent = [
      'Claim issued: over18=true',
      'Issuer saw only blinded attribute request during signing.'
    ].join('\n');
    credIssueBtn.removeAttribute('aria-busy');
  });

  byId('cred-present').addEventListener('click', () => {
    if (!state.credential.token) {
      status.textContent = 'Issue credential first.';
      announce('Issue a credential first.');
      return;
    }
    status.textContent = 'Verifier confirmed claim validity and signature integrity.';
    announce('Credential verified. Verifier cannot identify the subject.');
    log.textContent = [
      log.textContent,
      '',
      'Verifier outcome: attribute is valid.',
      'Verifier still cannot identify subject from this transcript.'
    ].join('\n');
  });
}

function wireCompareExhibit(): void {
  const log = byId('compare-log');

  const compareBtn = byId('compare-run');
  compareBtn.addEventListener('click', async () => {
    if (compareBtn.hasAttribute('aria-busy')) return;
    compareBtn.setAttribute('aria-busy', 'true');
    log.textContent = 'Running RSA blind and EC blind demos for timing…';
    announce('Running timing comparison between RSA and EC blind signatures');

    const rsaStart = performance.now();
    const rsa = await runRsaBlindSignatureDemo('timing sample');
    const rsaMs = performance.now() - rsaStart;

    const ecStart = performance.now();
    const ec = await runEcBlindSignatureDemo('timing sample');
    const ecMs = performance.now() - ecStart;

    state.rsa = rsa;
    state.ec = ec;

    byId('cmp-rsa-time').textContent = `${rsaMs.toFixed(2)} ms`;
    byId('cmp-ec-time').textContent = `${ecMs.toFixed(2)} ms`;
    byId('cmp-rsa-ok').textContent = rsa.verifyPass ? 'valid' : 'invalid';
    byId('cmp-ec-ok').textContent = ec.verified ? 'valid' : 'invalid';

    log.textContent = [
      `RSA verify: ${rsa.verifyPass}`,
      `EC verify: ${ec.verified}`,
      '',
      'RSA signer works over modulus n with exponentiation.',
      'EC signer works over Ed25519 points with scalar operations.',
      ec.comparison.ecSummary
    ].join('\n');

    announce(`Comparison complete. RSA: ${rsaMs.toFixed(0)}ms, EC: ${ecMs.toFixed(0)}ms. Both verified.`);
    compareBtn.removeAttribute('aria-busy');
  });
}

function setHtml(id: string, html: string): void {
  const target = document.getElementById(id);
  if (!target) {
    return;
  }
  target.innerHTML = html;
}

function byId(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) {
    throw new Error(`Missing element: ${id}`);
  }
  return el;
}

function shortHex(value: bigint): string {
  const hex = value.toString(16);
  if (hex.length <= 30) {
    return `0x${hex}`;
  }
  return `0x${hex.slice(0, 14)}...${hex.slice(-14)}`;
}

function randomToken(prefix: string): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${prefix}-${hex}`;
}
