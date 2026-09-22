import { test, expect } from '@playwright/test';
import fs from 'fs';
import path from 'path';

// Console's guided "First Cell verification" flow (app/components/FirstCell.tsx),
// against the REAL local assurance API — no mocking of the assurance API
// itself, same rule as console-first-case.spec.ts / ai.spec.ts.
//
// Unlike the register write (Anyone-reachable door, Register/Cell decide
// whether it writes), POST /v1/machine/verify is gated by the `Machine`
// dependency directly: no key gets a real 401, a Register-tier (or free)
// key gets a real 402 ("plan_does_not_include_machine_verification"), and
// only a Cell key gets a real 200 with a real verdict. This spec checks the
// real refusal and the real success, never a fabricated one, and captures
// desktop + mobile screenshots of both states into reports/demo/phase5/.

const OUT_DIR = path.join(__dirname, '..', 'reports', 'demo', 'phase5');
fs.mkdirSync(OUT_DIR, { recursive: true });

async function assuranceApiIsUp(): Promise<boolean> {
  try {
    const apiBase = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || 'http://127.0.0.1:8001';
    const res = await fetch(`${apiBase}/v1/plans`);
    return res.ok;
  } catch {
    return false;
  }
}

test.describe('Console — First Cell verification', () => {
  test.beforeEach(async () => {
    const up = await assuranceApiIsUp();
    test.skip(
      !up,
      'Assurance API not reachable at NEXT_PUBLIC_ASSURANCE_API_URL — start it with ' +
        '`uvicorn assurance.api.service:app --port 8001` (see docs/buyer-journey.md) and re-run, ' +
        'rather than faking this result.'
    );
  });

  test('no API key gets the real 401/402 refusal, never a fake pass', async ({ page }, testInfo) => {
    await page.goto('/console');
    await expect(page.locator('#cell-verify')).toBeVisible({ timeout: 10_000 });

    await page.locator('#cell-verify').getByRole('button', { name: 'Verify the sample run' }).click();

    // With no ASSURANCE_API_KEYS/ASSURANCE_ALLOW_UNAUTHENTICATED set, an
    // absent key resolves to a keyless Principal with account=None, which
    // require_machine refuses with a 401 ("This endpoint needs an API
    // key."). A real but under-tier key would instead show the 402 upgrade
    // card ("Cell required"). Either is an honest refusal; a verdict here
    // would mean this deployment hands out machine verification for free.
    const refused = page.getByText(/HTTP 401|Cell required/i);
    await expect(refused).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/HTTP 200/)).not.toBeVisible();

    await page.screenshot({
      path: path.join(OUT_DIR, `cell-verify-refused-${testInfo.project.name}.png`),
      fullPage: true,
    });
  });

  test('a Cell key gets a real verdict, never an echo', async ({ page }, testInfo) => {
    const paidKey = process.env.ASSURANCE_E2E_CELL_KEY || process.env.ASSURANCE_E2E_PAID_KEY;
    test.skip(
      !paidKey,
      'Set ASSURANCE_E2E_CELL_KEY to a real Cell-tier key minted via AccountStore to run this — ' +
        'see docs/buyer-journey.md step 1 (mint with tier="cell").'
    );

    await page.goto('/console');
    await page.getByLabel('API key (optional for free routes)').fill(paidKey!);
    await page.locator('#cell-verify').getByRole('button', { name: 'Verify the sample run' }).click();

    await expect(page.getByText(/HTTP 200 — verdict:/)).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/content_hash/)).toBeVisible();

    await page.screenshot({
      path: path.join(OUT_DIR, `cell-verify-success-${testInfo.project.name}.png`),
      fullPage: true,
    });
  });
});
