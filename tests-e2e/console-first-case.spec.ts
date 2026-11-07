import { test, expect } from './support/fixtures';
import { aiSeed } from './support/ai';

// Console's guided "First Register case" flow (app/components/FirstCase.tsx) against the REAL assurance API
// and its real account store: an absent key gets the API's real 401, a key whose plan has no register gets the
// real 402, and a Register key opens a real case and shows the content_hash / ledger_seq the ledger returned.
// Run through scripts/e2e-local.sh; there is no skip path.

const SIGNAL = /\/v1\/cases\/[^/]+\/signal$/;

test.describe('Console: First Register case', () => {
  test('no API key gets the real 401, never a fake success', async ({ page, allowHealth }) => {
    allowHealth({ status: 401, url: SIGNAL, why: 'the spec files a case with no key' });
    await page.goto('/console');
    await expect(page.locator('#first-case')).toBeVisible();
    await page.getByLabel('What was reported').fill('Playwright: unauthenticated first-case attempt');
    await page.getByRole('button', { name: 'Open this case' }).click();
    await expect(page.getByText(/HTTP 401/)).toBeVisible();
    await expect(page.getByText(/HTTP 201/)).toHaveCount(0);
  });

  test('a real key on a plan without the register gets the real 402 upgrade card', async ({ page, allowHealth }) => {
    allowHealth({ status: 402, url: SIGNAL, why: 'the spec files a case with a Validator-plan key' });
    await page.goto('/console');
    await page.getByLabel('API key (optional for free routes)').fill(aiSeed().free_account);
    await page.locator('#first-case').getByLabel('What was reported').fill('Playwright: free-plan first-case attempt');
    await page.getByRole('button', { name: 'Open this case' }).click();
    await expect(page.getByText('Register or Cell required')).toBeVisible();
    await expect(page.getByText(/HTTP 201/)).toHaveCount(0);
  });

  test('a Register key opens a real case with a real ledger receipt, and the same key carries to /ai', async ({ page }) => {
    const key = aiSeed().register_a;
    await page.goto('/console');
    await page.getByLabel('API key (optional for free routes)').fill(key);
    await page.locator('#first-case').getByLabel('What was reported').fill('Playwright: paid-key first-case flow');
    await page.getByRole('button', { name: 'Open this case' }).click();

    await expect(page.getByText(/HTTP 201 — recorded on the register/)).toBeVisible();
    await expect(page.getByText(/content_hash/)).toBeVisible();
    await expect(page.getByText(/ledger_seq/)).toBeVisible();

    // The key travels to /ai through the tab's shared storage, and the platform API honours it.
    await page.goto('/ai');
    await expect(page.getByLabel(/^API key/)).toHaveValue(key);
    await expect(page.getByText(/control plane: full/i)).toBeVisible();
  });
});
