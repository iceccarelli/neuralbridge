import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

// The "Coverage" panel of /assurance against the REAL local Assurance API
// (scripts/e2e-assurance-panels.sh): real accounts, real per-account ledgers, nothing mocked.
// The manifest is synthetic. A fresh machine has a sealed manifest and nothing else, so what
// the panel must show is evidence it can count, verification that is not covered, an intel match
// and an anchor that are not claimed, and UNKNOWN kept apart from zero.

const seedPath = process.env.PANELS_SEED;
const apiBase = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || 'http://127.0.0.1:8001';

type Seed = { key_coverage: string; key_coverage_empty: string; key_free: string; manifest: Record<string, unknown> };

test.describe.configure({ mode: 'serial' });

test.describe('Assurance workspace: Coverage panel', () => {
  let seed: Seed;
  test.beforeAll(() => {
    test.skip(!seedPath, 'Set PANELS_SEED (run scripts/e2e-assurance-panels.sh): not faking an API.');
    seed = JSON.parse(readFileSync(seedPath!, 'utf8'));
  });
  test.beforeEach(({}, info) => {
    test.skip(info.project.name !== 'desktop-chromium', 'One viewport: the spec shares one ledger.');
  });

  async function enter(page: Page, key: string) {
    await page.goto('/assurance');
    await page.getByLabel('API key').fill(key);
    await page.getByRole('button', { name: 'Refresh' }).click();
  }
  const panel = (page: Page) => page.locator('section#aw-coverage');

  test('an empty fleet is not clear: no share, no table, the words say so', async ({ page }) => {
    await enter(page, seed.key_coverage_empty);
    await expect(panel(page).getByTestId('coverage-empty')).toBeVisible();
    await expect(panel(page).getByTestId('coverage-empty')).toContainText('not clear and not covered');
    await expect(panel(page).getByTestId('coverage-machines')).toHaveCount(0);
    expect(await panel(page).innerText()).not.toMatch(/100%|\b0%/);
  });

  test('a plan without access shows a refusal and no numbers', async ({ page }) => {
    await enter(page, seed.key_free);
    await expect(panel(page).locator('[role="alert"]').first()).toBeVisible();
    await expect(panel(page).getByTestId('coverage-machines')).toHaveCount(0);
    await expect(panel(page).getByTestId('coverage-empty')).toHaveCount(0);
  });

  test('an enrolled machine: denominators are shown, unknown is counted apart from zero', async ({ page, request }) => {
    const res = await request.post(`${apiBase}/v1/machinery/enrol`, {
      headers: { 'X-API-Key': seed.key_coverage },
      data: { manifest: seed.manifest, actor: 'Ada Integrator' },
    });
    expect(res.status()).toBe(200);
    await enter(page, seed.key_coverage);
    const p = panel(page);
    await expect(p.getByTestId('coverage-machines')).toBeVisible();

    for (const dim of ['evidence', 'verification', 'intel', 'anchor']) {
      await expect(p.getByTestId('coverage-machines').locator(`tr[data-dimension="${dim}"] [data-testid="tally-denominator"]`)).toHaveText('1');
    }
    // never verified: not covered; intel is unknown (no advisory case); no operator anchor.
    const row = p.getByTestId('coverage-row');
    await expect(row).toHaveCount(1);
    await expect(row.locator('td[data-dimension="verification"]')).not.toHaveAttribute('data-state', 'covered');
    await expect(row.locator('td[data-dimension="intel"]')).toHaveAttribute('data-state', 'unknown');
    await expect(row.locator('td[data-dimension="intel"]')).toContainText('not a finding of no match');
    await expect(row.locator('td[data-dimension="anchor"]')).not.toHaveAttribute('data-state', 'covered');
    await expect(p.getByTestId('coverage-machines').locator('tr[data-dimension="intel"] [data-testid="tally-unknown"]')).toHaveText('1');
    await expect(p.getByTestId('coverage-machines').locator('tr[data-dimension="intel"] [data-testid="tally-covered"]')).toContainText('0 of 1');

    // every source is listed with its state
    await expect(p.getByTestId('coverage-sources').locator('li')).toHaveCount(4);
    // the panel's own disclaimer names the words it refuses to claim; it is removed before checking
    const text = (await p.innerText()).replace(/not a statement that any machine is safe or compliant/i, '');
    expect(text).not.toMatch(/\b(compliant|certified|approved|is safe|are safe)\b/i);
  });

  test('a source that refuses leaves its cells unknown, not covered', async ({ page }) => {
    // The attestation log is gated by the same entitlement; make that one request fail at the
    // network edge, so only its cells may change.
    await page.route('**/v1/ledger/attest/log', (route) => route.abort());
    await enter(page, seed.key_coverage);
    const row = panel(page).getByTestId('coverage-row');
    await expect(row.locator('td[data-dimension="anchor"]')).toHaveAttribute('data-state', 'unknown');
    await expect(panel(page).locator('li[data-source="/v1/ledger/attest/log"]')).toHaveAttribute('data-status', 'unavailable');
    await expect(row.locator('td[data-dimension="evidence"]')).not.toHaveAttribute('data-state', 'unknown');
  });

  test('the panel does not widen the page at phone width', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 800 });
    await enter(page, seed.key_coverage);
    await expect(panel(page).getByTestId('coverage-rows')).toBeVisible();
    const m = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, inner: window.innerWidth }));
    expect(m.sw).toBeLessThanOrEqual(390);
    expect(m.inner).toBeLessThanOrEqual(390);
  });
});
