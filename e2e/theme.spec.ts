import { expect, test } from "@playwright/test";

/**
 * One theme, pinned, with no way to change it.
 *
 * This lab is dark. That is a fleet invariant rather than a local preference:
 * the shared header used to carry a theme toggle that persisted its choice, so
 * a single past click pinned a returning visitor to light forever, and the
 * light palettes read badly anyway. Both were removed fleet-wide.
 *
 * The catalog's `node tools/theme-sync.js check` holds all 175 labs to this by
 * reading their markup. This test is the half that runs in CI, where it blocks
 * the deploy — the source check only runs when somebody remembers to run it.
 *
 * The two halves catch different things and neither is redundant. This one sees
 * the RESOLVED theme, so it catches a boot script switched to light and a
 * toggle that renders. It cannot see `<html data-theme="light">` left behind by
 * a boot script that still pins dark, because the script wins before this
 * assertion runs — that mismatch costs a flash of the wrong theme on first
 * paint, and only the source check catches it.
 *
 * CSS hiding is not removal: this lab used to ship a #theme-toggle button that
 * the shared bar's CSS merely hid, and that markup and its theme JS are now
 * gone. So this asserts no toggle EXISTS, not merely that none is visible — a
 * hidden one would otherwise slip back in unnoticed.
 */
test("the page pins the dark theme and offers no way to leave it", async ({
  page,
}) => {
  await page.goto(".");

  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.locator("#cl-theme-toggle")).toHaveCount(0);
  await expect(
    page.locator(
      "#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn," +
        " [data-theme-toggle], [title='Toggle color theme']",
    ),
  ).toHaveCount(0);
});
