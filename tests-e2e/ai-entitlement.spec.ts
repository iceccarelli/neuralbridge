import { test, expect } from '@playwright/test';

// Phase 2: the free (Validator, no API key) path — reads work, a write
// attempt shows a real upgrade card (402 payload), never a fake success
// and never a bare error. See tests-e2e/ai.spec.ts for the paid path.

async function apiIsUp(baseURL: string): Promise<boolean> {
  try {
    const apiBase = process.env.NEXT_PUBLIC_NEURALBRIDGE_API_URL || 'http://127.0.0.1:8000/api/v1';
    const res = await fetch(`${apiBase}/ai/connections`);
    return res.ok;
  } catch {
    return false;
  }
}

test.beforeEach(async ({ baseURL }) => {
  const up = await apiIsUp(baseURL!);
  test.skip(!up, 'NeuralBridge API not reachable — see docs/ai-local-setup.md');
});

test('free tier: read works, write shows a real upgrade card', async ({ page }) => {
  await page.goto('/ai');
  await expect(page.getByLabel('Connection')).toBeVisible({ timeout: 10_000 });

  // Free tier is the default — no API key seeded for this test.
  await expect(page.locator('.ai-plan-pill.free')).toBeVisible({ timeout: 10_000 });

  // Read still works.
  await page.getByLabel('Message').fill('list tables');
  await page.getByLabel('Message').press('Enter');
  await expect(page.getByText('Read OK')).toBeVisible({ timeout: 10_000 });

  // Write is refused with a real upgrade card, not silently allowed and
  // not a bare error.
  await page.getByLabel('Message').fill("UPDATE demo_customers SET plan='register' WHERE id=1");
  await page.getByLabel('Message').press('Enter');
  await expect(page.getByText('Register or Cell required')).toBeVisible({ timeout: 10_000 });
  await expect(page.getByRole('link', { name: /see pricing/i })).toHaveAttribute('href', '/#pricing');
  await expect(page.getByText('Execution receipt')).not.toBeVisible();
  await expect(page.getByText(/approval required/i)).not.toBeVisible();

  await page.screenshot({ path: 'test-results/ai-free-upgrade-card.png', fullPage: true });
});

test('pasting a paid API key unlocks the write path in the same session', async ({ page }) => {
  const paidKey = process.env.NEURALBRIDGE_E2E_PAID_KEY || 'demo-cell-key-12345';

  await page.goto('/ai');
  await expect(page.getByLabel('Connection')).toBeVisible({ timeout: 10_000 });
  await expect(page.locator('.ai-plan-pill.free')).toBeVisible({ timeout: 10_000 });

  await page.getByLabel('API key').fill(paidKey);
  await expect(page.locator('.ai-plan-pill.cell')).toBeVisible({ timeout: 10_000 });

  await page.getByLabel('Message').fill("UPDATE demo_customers SET plan='cell' WHERE id=1");
  await page.getByLabel('Message').press('Enter');
  await expect(page.getByText(/approval required/i)).toBeVisible({ timeout: 10_000 });
});
