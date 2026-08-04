import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

/**
 * WCAG regression gate. Deploys are already gated on the RFC 9474 KATs;
 * this gates them on accessibility the same way.
 *
 * Three things this gate has to do that a naive "goto then scan" cannot:
 *
 *  1. Scan the page in the states a user actually reaches. Every exhibit here
 *     paints its transcript, its status line and its verdict only after a
 *     button is clicked, so a scan of the untouched page checks seven empty
 *     result areas. Driving each exhibit to a result — including the rejected
 *     ones — is what surfaced five `scrollable-region-focusable` failures: the
 *     transcript `<pre>` blocks are capped at `max-height:20rem; overflow-y:auto`
 *     and become keyboard traps the moment their content overflows.
 *
 *  2. Settle motion before sampling. The theme flip animates background and
 *     border colours for 150ms, and a scan fired straight after the toggle
 *     samples mid-transition: it read `#protocol-blind` at 2.19:1 (light-theme
 *     foreground already applied over a still-dark background) on some runs and
 *     clean on others. That is a flaky gate, not a page defect. Rather than
 *     inject `transition: none` — which would also blind the gate to any real
 *     transition or theme-swap defect — emulate `prefers-reduced-motion`, which
 *     this lab's stylesheet honours, and then wait for `document.getAnimations()`
 *     to stay quiet for several consecutive frames.
 *
 *  3. Look past `results.violations`. axe files two defect classes under
 *     `incomplete`, where a `violations`-only assertion never sees them:
 *     contrast over a gradient (it declines to compute a ratio), and
 *     `aria-label` on an element with no role (ARIA discards the name). The
 *     gradient case is closed arithmetically by `auditContrast`; the role-less
 *     case is closed by asserting nothing but `color-contrast` may appear in
 *     `incomplete` at all.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * The only rule allowed to land in axe's `incomplete` bucket. axe refuses to
 * compute a ratio when the backdrop is a gradient, and this page's hero, cards
 * and buttons are gradient-painted throughout, so `color-contrast` incompletes
 * are structural. They are not waved through: `auditContrast` composites the
 * real painted stack, gradient stops included, and measures every one of them.
 * Any other rule appearing here — `aria-prohibited-attr` above all — is a
 * finding the gate must fail on.
 */
const INCOMPLETE_ALLOWED = new Set(['color-contrast']);

/** Playwright 1.61's `test.use({ reducedMotion })` silently does nothing, so
 *  the emulation is applied per test and then verified from inside the page. */
async function useReducedMotion(page: Page): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
}

/**
 * Wait until nothing is animating and it stays that way. A theme flip does not
 * drain in a single batch — one wave of transitions can start others — so
 * requiring five consecutive quiet frames avoids exiting through a gap between
 * waves. 10s because a cold, loaded machine can take a while to reach the
 * first quiet frame; on an idle machine this returns in well under 100ms.
 */
async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running').length;
      w.__quietFrames = running === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return (w.__quietFrames ?? 0) >= 5;
    },
    undefined,
    { timeout: 10_000, polling: 'raf' }
  );
}

async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    // Open any native disclosure widgets.
    for (const details of document.querySelectorAll('details')) {
      details.open = true;
    }
    // Tab panels are hidden with `.panel { display:none }` and revealed only
    // when they carry `.active`. Reveal every panel so hidden exhibit content
    // (which the visible-only scan would otherwise skip) is scanned too.
    for (const panel of document.querySelectorAll('.panel')) {
      panel.classList.add('active');
    }
  });
}

async function scan(page: Page, label: string): Promise<void> {
  await settle(page);

  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations at: ${label}`).toEqual([]);

  const unexpectedIncomplete = results.incomplete
    .filter((v) => !INCOMPLETE_ALLOWED.has(v.id))
    .map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexpectedIncomplete, `axe incomplete (non-contrast) at: ${label}`).toEqual([]);

  const contrast = formatContrastFailures(await auditContrast(page));
  expect(contrast, `measured contrast failures at: ${label}`).toEqual([]);
}

/**
 * Drive all seven exhibits to a settled result, taking every failure path as
 * well as every success one: a tampered signature, a double spend, a forged
 * coin, a forged ballot token and a forged credential claim all paint a
 * `verdict fail` that a first-paint-only scan never sees.
 */
async function driveEveryExhibit(page: Page): Promise<void> {
  await page.locator('#protocol-blind').click();
  await page.locator('#protocol-sign').click();
  await page.locator('#protocol-unblind').click();
  await page.locator('#protocol-verify').click();
  await expect(page.locator('#protocol-verdict')).toHaveClass(/pass/);
  await page.locator('#protocol-tamper').click();
  await expect(page.locator('#protocol-verdict')).toHaveClass(/fail/);

  await page.locator('#tab-rfc9474').click();
  await page.locator('#rfc-blind').click();
  await page.locator('#rfc-sign').click();
  await page.locator('#rfc-finalize').click();
  await expect(page.locator('#rfc-verdict')).toHaveClass(/pass/);
  await page.locator('#rfc-tamper').click();
  await expect(page.locator('#rfc-verdict')).toHaveClass(/fail/);

  await page.locator('#tab-cash').click();
  await page.locator('#cash-issue').click();
  await page.locator('#cash-spend').click();
  await expect(page.locator('#cash-verdict')).toHaveClass(/pass/);
  await page.locator('#cash-respend').click();
  await expect(page.locator('#cash-verdict')).toHaveClass(/fail/);
  await page.locator('#cash-forge').click();
  await expect(page.locator('#cash-verdict')).toHaveClass(/fail/);

  await page.locator('#tab-voting').click();
  await page.locator('#vote-issue').click();
  await page.locator('#vote-submit').click();
  await expect(page.locator('#vote-verdict')).toHaveClass(/pass/);
  await page.locator('#vote-forge').click();
  await expect(page.locator('#vote-verdict')).toHaveClass(/fail/);

  await page.locator('#tab-credentials').click();
  await page.locator('#cred-issue').click();
  await page.locator('#cred-present').click();
  await expect(page.locator('#cred-verdict')).toHaveClass(/pass/);
  await page.locator('#cred-forge').click();
  await expect(page.locator('#cred-verdict')).toHaveClass(/fail/);

  await page.locator('#tab-schnorr').click();
  await page.locator('#schnorr-run').click();
  await expect(page.locator('#schnorr-verdict')).toHaveClass(/pass/);
  await page.locator('#schnorr-tamper').click();
  await expect(page.locator('#schnorr-verdict')).toHaveClass(/fail/);

  await page.locator('#tab-compare').click();
  await page.locator('#compare-run').click();
  await expect(page.locator('#cmp-rsa-time')).not.toHaveText('—');
  await expect(page.locator('#cmp-ec-time')).not.toHaveText('—');
}

async function toLight(page: Page): Promise<void> {
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
}

test('the reduced-motion emulation this gate depends on actually reaches the page', async ({
  page,
}) => {
  // `test.use({ reducedMotion })` is a no-op on Playwright 1.61.1. If this ever
  // regresses to a no-op, every scan below silently goes back to racing the
  // 150ms theme transition, so assert the media query from inside the page.
  await useReducedMotion(page);
  await page.goto('.');
  const reduced = await page.evaluate(
    () => matchMedia('(prefers-reduced-motion: reduce)').matches
  );
  expect(reduced).toBe(true);
});

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await useReducedMotion(page);
  await page.goto('.');
  await revealAll(page);
  await scan(page, 'dark / first paint');
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await useReducedMotion(page);
  await page.goto('.');
  await toLight(page);
  await revealAll(page);
  await scan(page, 'light / first paint');
});

test('no WCAG A/AA violations once every exhibit has painted a result, dark theme', async ({
  page,
}) => {
  await useReducedMotion(page);
  await page.goto('.');
  await driveEveryExhibit(page);
  await revealAll(page);
  await scan(page, 'dark / every exhibit driven');
});

test('no WCAG A/AA violations once every exhibit has painted a result, light theme', async ({
  page,
}) => {
  await useReducedMotion(page);
  await page.goto('.');
  await driveEveryExhibit(page);
  await toLight(page);
  await revealAll(page);
  await scan(page, 'light / every exhibit driven');
});

// The transcript blocks are `max-height:20rem; overflow-y:auto`, so they only
// overflow — and only become 2.1.1 keyboard traps — once they hold real content,
// and three of the five only overflow at a narrow width. A scan at 1280px on an
// untouched page cannot fail this rule no matter how broken the page is.
for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations at 380px with every exhibit driven, ${theme} theme`, async ({
    page,
  }) => {
    await useReducedMotion(page);
    await page.setViewportSize({ width: 380, height: 720 });
    await page.goto('.');
    await driveEveryExhibit(page);
    if (theme === 'light') await toLight(page);
    await revealAll(page);
    await scan(page, `${theme} / every exhibit driven / 380px`);
  });
}
