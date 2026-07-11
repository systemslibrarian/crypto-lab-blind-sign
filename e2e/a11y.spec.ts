import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the RFC 9474 KATs;
 * this gates them on accessibility the same way. Scans the full page with
 * every collapsible expanded and every tab panel revealed, in both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

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

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealAll(page);
  await scan(page);
});
