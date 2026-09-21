import { test, expect } from '@playwright/test';

// Console's guided "First Register case" flow (app/components/FirstCase.tsx),
// against the REAL local assurance API — no mocking of the assurance API
// itself, same rule as tests-e2e/ai.spec.ts. Unlike /ai's backend
// (Postgres-backed), assurance.api.service is SQLite-only, so this spec can
// run against a real local instance without a database server — see
// docs/ai-local-setup.md and docs/buyer-journey.md for the same distinction.
//
// A free/no-key submission must get the API's real 401 (or, once a key
// proves insufficient, a real 402) — never a fabricated success. A
// Register/Cell key must open a real case and show the real
// content_hash/ledger_seq the ledger returned.

async function assuranceApiIsUp(): Promise<boolean> {
  try {
    const apiBase = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || 'http://127.0.0.1:8001';
    const res = await fetch(`${apiBase}/v1/plans`);
    return res.ok;
  } catch {
    return false;
  }
}

test.describe('Console — First Register case', () => {
  test.beforeEach(async () => {
    const up = await assuranceApiIsUp();
    test.skip(
      !up,
      'Assurance API not reachable at NEXT_PUBLIC_ASSURANCE_API_URL — start it with ' +
        '`uvicorn assurance.api.service:app --port 8001` (see docs/buyer-journey.md) and re-run, ' +
        'rather than faking this result.'
    );
  });

  test('no API key gets the real refusal, never a fake success', async ({ page }) => {
    await page.goto('/console');
    await expect(page.locator('#first-case')).toBeVisible({ timeout: 10_000 });

    await page.getByLabel('What was reported').fill('Playwright: unauthenticated first-case attempt');
    await page.getByRole('button', { name: 'Open this case' }).click();

    // What the exact refusal looks like depends on how this deployment's
    // auth_mode is configured (see src/assurance/api/deps.py::require_register):
    // a 401 (no account resolvable from an absent key), a 402 upgrade card
    // (an under-entitled key), or, with no ASSURANCE_API_KEYS/
    // ASSURANCE_ALLOW_UNAUTHENTICATED set at all, a 503 explaining that this
    // service refuses unauthenticated register writes by default. All three
    // are honest refusals; a 201 success here would mean this deployment is
    // handing out register writes for free, which is exactly what this test
    // exists to catch.
    const refused = page.getByText(/HTTP 401|Register or Cell required|refuses unauthenticated writes/i);
    await expect(refused).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/HTTP 201/)).not.toBeVisible();
  });

  test('a Register/Cell key opens a real case with a real ledger receipt', async ({ page }) => {
    const paidKey = process.env.ASSURANCE_E2E_PAID_KEY;
    test.skip(!paidKey, 'Set ASSURANCE_E2E_PAID_KEY to a real Cell-tier key minted via AccountStore to run this — see docs/buyer-journey.md step 1.');

    await page.goto('/console');
    await page.getByLabel('API key (optional for free routes)').fill(paidKey!);
    await page.locator('#first-case').getByLabel('What was reported').fill('Playwright: paid-key first-case flow');
    await page.getByRole('button', { name: 'Open this case' }).click();

    await expect(page.getByText(/HTTP 201 — recorded on the register/)).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/content_hash/)).toBeVisible();
    await expect(page.getByText(/ledger_seq/)).toBeVisible();

    // The same key travels to /ai via shared sessionStorage — no retyping.
    // Checked at the storage layer (app/lib/apiKey.ts's shared key), not by
    // asserting on /ai's own rendered field, so this half of the test does
    // not also require the separate NeuralBridge (/ai) API to be running.
    const stored = await page.evaluate(() => window.sessionStorage.getItem('nb-api-key'));
    expect(stored).toBe(paidKey);
  });
});
