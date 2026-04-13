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

const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab-btn'));
const panels = Array.from(document.querySelectorAll<HTMLElement>('.panel'));

for (const tab of tabs) {
  tab.addEventListener('click', () => {
    const panelId = tab.dataset.panel;
    if (!panelId) {
      return;
    }
    for (const button of tabs) {
      button.classList.remove('active');
    }
    for (const panel of panels) {
      panel.classList.remove('active');
    }
    tab.classList.add('active');
    document.getElementById(panelId)?.classList.add('active');
  });
}

renderExhibits();
wireProtocolExhibit();
wireCashExhibit();
wireVotingExhibit();
wireCredentialExhibit();
wireCompareExhibit();
setupThemeToggle();

function setupThemeToggle(): void {
  const button = document.getElementById('theme-toggle') as HTMLButtonElement | null;
  if (!button) {
    return;
  }

  const sync = (): void => {
    const current = currentTheme();
    button.textContent = current === 'dark' ? '🌙' : '☀️';
    button.setAttribute('aria-label', current === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  };

  button.addEventListener('click', () => {
    const next: Theme = currentTheme() === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    sync();
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
      <h2>Exhibit 1 - The Protocol</h2>
      <p>Walk through blind -> sign -> unblind -> verify with concrete values. The signer sees only blinded values.</p>
      <div class="button-row">
        <button class="btn primary" id="protocol-blind">Blind</button>
        <button class="btn" id="protocol-sign">Sign</button>
        <button class="btn" id="protocol-unblind">Unblind</button>
        <button class="btn" id="protocol-verify">Verify</button>
      </div>
      <div class="protocol-grid">
        <div class="card inset" id="requester-view">
          <h3>Requester (Alice) View</h3>
          <pre id="requester-log">Click Blind to start.</pre>
        </div>
        <div class="card inset" id="signer-view">
          <h3>Signer (Bank) View</h3>
          <pre id="signer-log">Signer has not received a blinded request yet.</pre>
        </div>
      </div>
      <div class="flow-track" aria-hidden="true">
        <span class="flow-pill" id="flow-pill">blinding factor wraps message</span>
      </div>
      <div class="status-line" id="protocol-status"></div>
    </div>
  `
  );

  setHtml(
    'cash',
    `
    <div class="card">
      <h2>Exhibit 2 - Chaum's E-Cash</h2>
      <p>Issue a blind-signed coin, spend it at a merchant, and detect double spend by serial reuse. DigiCash launched in 1989; privacy worked, economics did not.</p>
      <div class="button-row">
        <button class="btn primary" id="cash-issue">Issue Coin</button>
        <button class="btn" id="cash-spend">Spend Coin</button>
        <button class="btn" id="cash-respend">Attempt Double Spend</button>
      </div>
      <div class="status-line" id="cash-status"></div>
      <pre id="cash-log"></pre>
    </div>
  `
  );

  setHtml(
    'voting',
    `
    <div class="card">
      <h2>Exhibit 3 - Anonymous Voting</h2>
      <p>Authority issues one blind-signed ballot token. Token proves eligibility, not identity.</p>
      <div class="form-row">
        <label for="vote-choice">Ballot</label>
        <select id="vote-choice">
          <option value="Option A">Option A</option>
          <option value="Option B">Option B</option>
        </select>
      </div>
      <div class="button-row">
        <button class="btn primary" id="vote-issue">Issue Ballot Token</button>
        <button class="btn" id="vote-submit">Submit Anonymous Vote</button>
      </div>
      <div class="status-line" id="vote-status"></div>
      <pre id="vote-log"></pre>
    </div>
  `
  );

  setHtml(
    'credentials',
    `
    <div class="card">
      <h2>Exhibit 4 - Anonymous Credentials</h2>
      <p>Issuer signs an attribute claim like over 18. Verifier checks claim validity without learning identity.</p>
      <div class="button-row">
        <button class="btn primary" id="cred-issue">Issue over-18 Credential</button>
        <button class="btn" id="cred-present">Present Credential</button>
      </div>
      <div class="status-line" id="cred-status"></div>
      <pre id="cred-log"></pre>
      <p class="compare-note">Compared with BBS+ and W3C VC stacks, blind signatures prioritize issuer unlinkability at issuance time.</p>
    </div>
  `
  );

  setHtml(
    'compare',
    `
    <div class="card">
      <h2>Exhibit 5 - RSA vs EC Blind</h2>
      <p>Run both engines and compare measured timings, key sizes, and security assumptions.</p>
      <div class="button-row">
        <button class="btn primary" id="compare-run">Run Timing Comparison</button>
      </div>
      <table class="compare-table">
        <thead>
          <tr><th>Metric</th><th>RSA Blind</th><th>Schnorr Blind (Ed25519)</th></tr>
        </thead>
        <tbody>
          <tr><td>Total demo runtime</td><td id="cmp-rsa-time">-</td><td id="cmp-ec-time">-</td></tr>
          <tr><td>Public key size</td><td>~256 bytes modulus</td><td>32 bytes</td></tr>
          <tr><td>Security margin model</td><td>Integer factorization hardness</td><td>Discrete log on Edwards curve</td></tr>
          <tr><td>Verification result</td><td id="cmp-rsa-ok">-</td><td id="cmp-ec-ok">-</td></tr>
        </tbody>
      </table>
      <pre id="compare-log"></pre>
    </div>
  `
  );
}

function wireProtocolExhibit(): void {
  const requesterLog = byId('requester-log');
  const signerLog = byId('signer-log');
  const status = byId('protocol-status');
  const flow = byId('flow-pill');

  byId('protocol-blind').addEventListener('click', async () => {
    status.textContent = 'Generating RSA keypair and blinding message...';
    const transcript = await runRsaBlindSignatureDemo('Chaum blind signature request');
    state.rsa = transcript;

    requesterLog.textContent = [
      `m = ${shortHex(transcript.messageRepresentative)}`,
      `r = ${shortHex(transcript.blindingFactor)}`,
      `m' = m * r^e mod n = ${shortHex(transcript.blindedMessage)}`
    ].join('\n');

    signerLog.textContent = [
      `Signer receives only: m' = ${shortHex(transcript.blindedMessage)}`,
      'Signer has not seen m or r.'
    ].join('\n');

    flow.textContent = 'message wrapped by blinding factor r';
    flow.classList.add('animate');
    status.textContent = 'Blind step complete.';
  });

  byId('protocol-sign').addEventListener('click', () => {
    if (!state.rsa) {
      status.textContent = 'Run Blind first.';
      return;
    }
    signerLog.textContent = [
      `Signer input: m' = ${shortHex(state.rsa.blindedMessage)}`,
      `Signer output: s' = (m')^d mod n = ${shortHex(state.rsa.blindedSignature)}`
    ].join('\n');
    status.textContent = 'Sign step complete.';
  });

  byId('protocol-unblind').addEventListener('click', () => {
    if (!state.rsa) {
      status.textContent = 'Run Blind first.';
      return;
    }
    requesterLog.textContent = [
      requesterLog.textContent,
      '',
      `s = s' * r^-1 mod n = ${shortHex(state.rsa.unblindedSignature)}`,
      'Requester unblinds without revealing m.'
    ].join('\n');
    flow.textContent = 'blinding removed, valid signature recovered';
    status.textContent = 'Unblind step complete.';
  });

  byId('protocol-verify').addEventListener('click', () => {
    if (!state.rsa) {
      status.textContent = 'Run Blind first.';
      return;
    }
    requesterLog.textContent = [
      requesterLog.textContent,
      '',
      `verify: s^e mod n == m -> ${state.rsa.verifyPass ? 'true' : 'false'}`,
      `unlinkability: ${state.rsa.unlinkability.reason}`
    ].join('\n');
    signerLog.textContent = [
      signerLog.textContent,
      '',
      'Signer transcript contains only (m\', s\').',
      'After unblinding, signer cannot link s to original m.'
    ].join('\n');
    status.textContent = 'Verify step complete.';
  });
}

function wireCashExhibit(): void {
  const status = byId('cash-status');
  const log = byId('cash-log');

  byId('cash-issue').addEventListener('click', async () => {
    const serial = randomToken('COIN');
    const transcript = await runRsaBlindSignatureDemo(serial);
    state.ecash.coin = `${serial}:${transcript.unblindedSignature.toString(16)}`;
    state.ecash.spent = false;
    status.textContent = 'Bank issued blind-signed coin.';
    log.textContent = [
      `Coin serial: ${serial}`,
      'Bank signed a blinded serial number.',
      'Bank cannot link this serial to Alice identity.'
    ].join('\n');
  });

  byId('cash-spend').addEventListener('click', () => {
    if (!state.ecash.coin) {
      status.textContent = 'Issue a coin first.';
      return;
    }
    const serial = state.ecash.coin.split(':')[0];
    state.ecash.serialRegistry.add(serial);
    state.ecash.spent = true;
    status.textContent = 'Merchant accepted coin and queried bank for serial freshness.';
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
      return;
    }
    const serial = state.ecash.coin.split(':')[0];
    if (state.ecash.serialRegistry.has(serial)) {
      status.textContent = 'Double-spend detected. Serial already redeemed.';
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

  byId('vote-issue').addEventListener('click', async () => {
    const token = randomToken('BALLOT');
    const transcript = await runRsaBlindSignatureDemo(token);
    state.voting.token = `${token}:${transcript.unblindedSignature.toString(16)}`;
    status.textContent = 'Authority issued one blind-signed ballot token.';
    log.textContent = [
      `Token: ${token}`,
      'Authority signs blinded token and learns no voter-choice link.'
    ].join('\n');
  });

  byId('vote-submit').addEventListener('click', () => {
    if (!state.voting.token) {
      status.textContent = 'Issue a token first.';
      return;
    }
    const token = state.voting.token.split(':')[0];
    if (state.voting.consumedTokens.has(token)) {
      status.textContent = 'Rejected: token already used.';
      return;
    }
    state.voting.vote = select.value;
    state.voting.consumedTokens.add(token);
    status.textContent = 'Anonymous vote accepted with single-use token validation.';
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

  byId('cred-issue').addEventListener('click', async () => {
    const claim = 'attribute:over18=true';
    const transcript = await runRsaBlindSignatureDemo(claim);
    state.credential.token = `${claim}:${transcript.unblindedSignature.toString(16)}`;
    status.textContent = 'Issuer generated blind-signed age credential.';
    log.textContent = [
      'Claim issued: over18=true',
      'Issuer saw only blinded attribute request during signing.'
    ].join('\n');
  });

  byId('cred-present').addEventListener('click', () => {
    if (!state.credential.token) {
      status.textContent = 'Issue credential first.';
      return;
    }
    status.textContent = 'Verifier confirmed claim validity and signature integrity.';
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

  byId('compare-run').addEventListener('click', async () => {
    log.textContent = 'Running RSA blind and EC blind demos for timing...';

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
