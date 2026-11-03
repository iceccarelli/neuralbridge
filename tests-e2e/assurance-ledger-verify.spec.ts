import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

// The "Ledger verify" panel of /assurance against the REAL local Assurance API
// (scripts/e2e-ledger-verify.sh): real accounts, real per-account ledgers, a throwaway service
// signing key and the real counter-signing code. The truncated ledger is cut with SQL after it
// was counter-signed. Nothing in the assurance API is mocked. The panel is read-only, so both
// viewport projects share one seed.

const seedPath = process.env.LEDGER_VERIFY_SEED;

type Seed = {
  key_empty: string;
  key_unanchored: string;
  key_complete: string;
  key_incomplete: string;
  key_free: string;
};

// Words the panel must never use for any of these states.
const PASS_WORDS = /\b(passed|passes|compliant|certified|approved|all clear)\b/i;

test.describe('Assurance workspace — Ledger verify panel', () => {
  let seed: Seed;
  test.beforeAll(() => {
    test.skip(!seedPath, 'Set LEDGER_VERIFY_SEED (run scripts/e2e-ledger-verify.sh): not faking an API.');
    seed = JSON.parse(readFileSync(seedPath!, 'utf8'));
  });

  async function enter(page: Page, key: string) {
    await page.goto('/assurance');
    await page.getByLabel('API key').fill(key);
    await page.getByRole('button', { name: 'Refresh' }).click();
  }
  const panel = (page: Page) => page.locator('section#aw-ledger-verify');

  async function noSideways(page: Page) {
    const w = await page.evaluate(() => ({ doc: document.documentElement.scrollWidth, view: document.documentElement.clientWidth }));
    expect(w.doc).toBeLessThanOrEqual(w.view);
  }

  test('a counter-signed, untouched ledger is complete only up to the anchor', async ({ page }) => {
    await enter(page, seed.key_complete);
    const p = panel(page);
    await expect(p.getByTestId('lv-result')).toBeVisible({ timeout: 15_000 });
    await expect(p.getByTestId('lv-result')).toHaveAttribute('data-chain', 'intact');
    await expect(p.getByTestId('lv-result')).toHaveAttribute('data-completeness', 'complete');
    await expect(p.getByTestId('lv-completeness')).toContainText('complete up to the signed anchor');
    await expect(p.getByTestId('lv-uncovered')).toContainText('1 record(s) follow the anchor and are not covered by it');
    await expect(p.getByTestId('lv-entries')).toHaveText('4');
    await expect(p.getByTestId('lv-head-hash')).toHaveText(/^[0-9a-f]{64}$/);
    await expect(p.getByTestId('lv-ledger-id')).not.toHaveText('not stated');
    await expect(p.getByTestId('lv-anchor-fingerprint')).not.toContainText('none');
    await expect(p.getByTestId('lv-tier')).toHaveText('cell', { timeout: 15_000 });
    await expect(p.getByTestId('lv-anchor-meaning')).toContainText('A signature proves who signed the head');
    await expect(p.getByTestId('lv-alert')).toHaveCount(0);
    expect(await p.innerText()).not.toMatch(PASS_WORDS);
    await noSideways(page);
  });

  test('truncation past the anchor is loud and never complete', async ({ page }) => {
    await enter(page, seed.key_incomplete);
    const p = panel(page);
    await expect(p.getByTestId('lv-result')).toBeVisible({ timeout: 15_000 });
    await expect(p.getByTestId('lv-result')).toHaveAttribute('data-completeness', 'incomplete');
    const alert = p.getByTestId('lv-alert');
    await expect(alert).toBeVisible();
    await expect(alert).toHaveAttribute('role', 'alert');
    await expect(alert).toContainText('LEDGER INCOMPLETE');
    await expect(p.getByTestId('lv-completeness')).toContainText('INCOMPLETE');
    await expect(p.getByTestId('lv-problems')).toBeVisible();
    await expect(p.getByTestId('lv-uncovered')).toHaveCount(0);
    await expect(p.getByTestId('lv-entries')).toHaveText('1');
    expect(await p.innerText()).not.toMatch(/complete up to/i);
    expect(await p.innerText()).not.toMatch(PASS_WORDS);
    await noSideways(page);
  });

  test('a chain nobody counter-signed is unanchored, not a pass', async ({ page }) => {
    await enter(page, seed.key_unanchored);
    const p = panel(page);
    await expect(p.getByTestId('lv-result')).toBeVisible({ timeout: 15_000 });
    await expect(p.getByTestId('lv-result')).toHaveAttribute('data-chain', 'intact');
    await expect(p.getByTestId('lv-result')).toHaveAttribute('data-completeness', 'unanchored');
    await expect(p.getByTestId('lv-completeness')).toContainText('unanchored');
    await expect(p.getByTestId('lv-completeness-text')).toContainText('This is not a pass');
    await expect(p.getByTestId('lv-anchor-fingerprint')).toContainText('none');
    await expect(p.getByTestId('lv-not-checked')).toContainText('holds no attestations');
    await expect(p.getByTestId('lv-entries')).toHaveText('3');
    expect(await p.innerText()).not.toMatch(/complete up to/i);
    await noSideways(page);
  });

  test('an empty ledger says so, with no anchor and no completeness claim', async ({ page }) => {
    await enter(page, seed.key_empty);
    const p = panel(page);
    await expect(p.getByTestId('lv-result')).toBeVisible({ timeout: 15_000 });
    await expect(p.getByTestId('lv-entries')).toContainText('0 (empty ledger)');
    await expect(p.getByTestId('lv-result')).toHaveAttribute('data-completeness', 'unanchored');
    await noSideways(page);
  });

  test('an unentitled key gets a 402 refusal and no result', async ({ page }) => {
    await enter(page, seed.key_free);
    const p = panel(page);
    await expect(p.locator('[role="alert"][data-outcome="upgrade"]')).toBeVisible({ timeout: 15_000 });
    await expect(p.getByTestId('lv-result')).toHaveCount(0);
  });

  test('a key the server does not know gets a 401 refusal and no result', async ({ page }) => {
    await enter(page, 'not-a-key-' + 'x'.repeat(20));
    const p = panel(page);
    await expect(p.locator('[role="alert"][data-outcome="unauthorized"]')).toBeVisible({ timeout: 15_000 });
    await expect(p.getByTestId('lv-result')).toHaveCount(0);
  });
});
