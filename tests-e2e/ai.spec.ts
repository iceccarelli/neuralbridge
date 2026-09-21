import { test, expect } from '@playwright/test';

// Golden path against a real backend: discover a real connection, run a
// real read, plan a write, approve it, see a receipt. Skips itself with a
// clear reason if the API isn't reachable (see docs/ai-local-setup.md) —
// no faked pass.
//
// Phase 2: writes are a paid (Register/Cell) capability, so these tests
// authenticate as paid by seeding sessionStorage with an API key before
// the page's first fetch — see docs/ai-local-setup.md for
// ASSURANCE_API_KEYS. TestGolden defined in tests-e2e/ai-entitlement.spec.ts
// covers the free (no key) path.

const PAID_API_KEY = process.env.NEURALBRIDGE_E2E_PAID_KEY || 'demo-cell-key-12345';

async function apiIsUp(baseURL: string): Promise<boolean> {
  try {
    const apiBase = process.env.NEXT_PUBLIC_NEURALBRIDGE_API_URL || 'http://127.0.0.1:8000/api/v1';
    const res = await fetch(`${apiBase}/ai/connections`);
    return res.ok;
  } catch {
    return false;
  }
}

test.beforeEach(async ({ baseURL, page }) => {
  const up = await apiIsUp(baseURL!);
  test.skip(!up, 'NeuralBridge API not reachable — see docs/ai-local-setup.md');
  await page.addInitScript((key) => {
    window.sessionStorage.setItem('nb-ai-api-key', key);
  }, PAID_API_KEY);
});

test('discover -> real read -> plan write -> approve -> receipt', async ({ page }) => {
  await page.goto('/ai');
  await expect(page.getByRole('heading', { name: /discover, read, plan, approve/i })).toBeVisible();

  // Discover: a real connection is selected in Context.
  await expect(page.getByLabel('Connection')).toBeVisible({ timeout: 10_000 });
  await expect(page.getByLabel('Connection').locator('option')).toHaveCount(1);

  // Real read.
  await page.getByLabel('Message').fill('list tables');
  await page.getByLabel('Message').press('Enter');
  await expect(page.getByText('Read OK')).toBeVisible({ timeout: 10_000 });

  // Plan a write — must NOT execute immediately.
  await page.getByLabel('Message').fill("UPDATE demo_customers SET plan='register' WHERE id=1");
  await page.getByLabel('Message').press('Enter');
  await expect(page.getByText(/approval required/i)).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText('Execution receipt')).not.toBeVisible();

  // Approve -> receipt.
  await page.getByRole('button', { name: /approve & execute/i }).click();
  await expect(page.getByText('Execution receipt')).toBeVisible({ timeout: 10_000 });

  await page.screenshot({ path: 'test-results/ai-golden-path.png', fullPage: true });
});

test('deny path leaves nothing executed', async ({ page }) => {
  await page.goto('/ai');
  await page.getByLabel('Message').fill('DELETE FROM demo_customers');
  await page.getByLabel('Message').press('Enter');
  await expect(page.getByText(/approval required/i)).toBeVisible({ timeout: 10_000 });

  await page.getByRole('button', { name: /^deny$/i }).click();
  await expect(page.getByText(/denied — nothing executed/i)).toBeVisible({ timeout: 10_000 });
});

test('no API configured renders an honest disabled state, not a fake success', async ({ page, context }) => {
  // Simulate no backend by intercepting the connections call to fail —
  // the component's own no-API-BASE path isn't reachable at runtime once
  // the env var is baked into the build, so we instead assert the error
  // banner appears when the API is unreachable.
  await context.route('**/ai/connections', (route) => route.abort());
  await page.goto('/ai');
  await expect(page.getByText(/could not reach the neuralbridge api/i)).toBeVisible({ timeout: 10_000 });
});
