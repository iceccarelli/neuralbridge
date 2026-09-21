import { test, expect } from '@playwright/test';

// Phase 3 ("first euro" pass): browser-visible behavior added this phase.
//
// 1. The checkout-success "next step" panel (app/checkout/success/SuccessClient.tsx)
//    — proven with a mocked GET /v1/checkout/complete (no live Stripe involved
//    anywhere in this repo; a real session_id only ever comes from a real
//    Stripe redirect, so this is the same "mock what Stripe would deliver"
//    pattern the component's own comments describe, not a fabricated success
//    for a code path this repo actually executes unmocked).
// 2. `/ai`'s 402-then-paste-key-then-retry loop (app/components/AiWorkspace.tsx)
//    against the REAL local backend — no mocking of the /ai API itself, same
//    as tests-e2e/ai.spec.ts and tests-e2e/ai-entitlement.spec.ts.

async function apiIsUp(baseURL: string): Promise<boolean> {
  try {
    const apiBase = process.env.NEXT_PUBLIC_NEURALBRIDGE_API_URL || 'http://127.0.0.1:8000/api/v1';
    const res = await fetch(`${apiBase}/ai/connections`);
    return res.ok;
  } catch {
    return false;
  }
}

test.describe('checkout-success next-step panel', () => {
  test('a completed checkout shows the two concrete next actions', async ({ page }) => {
    await page.route('**/v1/checkout/complete*', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          api_key: 'nb-test-key-do-not-ship',
          tier: 'cell',
          account_id: 'acct_test_123',
          keep_this: "This is shown once — copy it now.",
          use_it: { header: 'X-API-Key', start_here: 'GET /v1/cases' },
        }),
      })
    );

    await page.goto('/checkout/success?session_id=cs_test_123');

    await expect(page.getByRole('heading', { name: /your cell key/i })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('nb-test-key-do-not-ship')).toBeVisible();

    // The two concrete next-step cards this phase added.
    await expect(page.getByText(/open your first register case/i)).toBeVisible();
    await expect(page.getByText(/open \/ai and paste this key/i)).toBeVisible();
    await expect(page.getByRole('link', { name: '/ai' })).toHaveAttribute('href', '/ai');
  });

  test('an incomplete session polls, never fakes a key', async ({ page }) => {
    await page.route('**/v1/checkout/complete*', (route) => route.fulfill({ status: 202, body: '{}' }));
    await page.goto('/checkout/success?session_id=cs_test_pending');
    await expect(page.getByText(/confirming your payment/i)).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('nb-test-key-do-not-ship')).not.toBeVisible();
  });
});

test.describe('/ai key-paste auto-retry', () => {
  test.beforeEach(async ({ baseURL }) => {
    const up = await apiIsUp(baseURL!);
    test.skip(!up, 'NeuralBridge API not reachable — see docs/ai-local-setup.md');
  });

  test('a 402d write is retried automatically after pasting a key, no retyping', async ({ page }) => {
    const paidKey = process.env.NEURALBRIDGE_E2E_PAID_KEY || 'demo-cell-key-12345';
    const sql = "UPDATE demo_customers SET plan='cell' WHERE id=1";

    await page.goto('/ai');
    await expect(page.getByLabel('Connection')).toBeVisible({ timeout: 10_000 });

    // Free caller: propose a write, get the real 402 upgrade card with a
    // disabled "Retry now" button (no key pasted yet).
    await page.getByLabel('Message').fill(sql);
    await page.getByLabel('Message').press('Enter');
    await expect(page.getByText('Register or Cell required')).toBeVisible({ timeout: 10_000 });
    const retryButton = page.getByRole('button', { name: /retry now with your key/i });
    await expect(retryButton).toBeVisible();
    await expect(retryButton).toBeDisabled();

    // Message field is not pre-filled with the failed write — the retry
    // button is the only path back, proving the request is carried on the
    // card itself, not re-typed.
    await expect(page.getByLabel('Message')).toHaveValue('');

    // Paste the key — no reload, no retyping the write.
    await page.getByLabel('API key').fill(paidKey);
    await expect(retryButton).toBeEnabled({ timeout: 10_000 });

    await retryButton.click();
    await expect(page.getByText(/approval required/i)).toBeVisible({ timeout: 10_000 });

    await page.getByRole('button', { name: /approve & execute/i }).click();
    await expect(page.getByText('Execution receipt')).toBeVisible({ timeout: 10_000 });
  });
});
