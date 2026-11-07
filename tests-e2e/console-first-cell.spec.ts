import { test, expect } from './support/fixtures';
import type { Page } from '@playwright/test';
import { aiSeed } from './support/ai';

// Console's guided "First Cell verification" flow (app/components/FirstCell.tsx) against the REAL assurance
// API. POST /v1/machine/verify is gated by the Machine dependency directly: no key gets a real 401, a
// Register-tier key a real 402 ("Cell required"), and only a Cell key a real 200 with a real verdict. Run
// through scripts/e2e-local.sh; there is no skip path. Screenshots go to the test's output dir, never into
// the committed reports/.

const VERIFY = /\/v1\/machine\/verify/;
const verifyButton = (page: Page) => page.locator('#cell-verify').getByRole('button', { name: 'Verify the sample run' });

test.describe('Console: First Cell verification', () => {
  test('no API key gets the real 401, never a fake pass', async ({ page, allowHealth }, testInfo) => {
    allowHealth({ status: 401, url: VERIFY, why: 'the spec verifies with no key' });
    await page.goto('/console');
    await expect(page.locator('#cell-verify')).toBeVisible();
    await verifyButton(page).click();
    await expect(page.getByText(/HTTP 401/)).toBeVisible();
    await expect(page.getByText(/HTTP 200/)).toHaveCount(0);
    await page.screenshot({ path: testInfo.outputPath('cell-verify-refused.png'), fullPage: true });
  });

  test('a Register key is real but under-entitled: the real 402, never a verdict', async ({ page, allowHealth }) => {
    allowHealth({ status: 402, url: VERIFY, why: 'the spec verifies with a Register-plan key' });
    await page.goto('/console');
    await page.getByLabel('API key (optional for free routes)').fill(aiSeed().register_a);
    await verifyButton(page).click();
    await expect(page.getByText('Cell required')).toBeVisible();
    await expect(page.getByText(/HTTP 200/)).toHaveCount(0);
  });

  test('a Cell key gets a real verdict sealed to the ledger, never an echo', async ({ page }, testInfo) => {
    await page.goto('/console');
    await page.getByLabel('API key (optional for free routes)').fill(aiSeed().cell);
    await verifyButton(page).click();
    await expect(page.getByText(/HTTP 200 — verdict:/)).toBeVisible();
    await expect(page.getByText(/content_hash/)).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath('cell-verify-success.png'), fullPage: true });
  });
});
