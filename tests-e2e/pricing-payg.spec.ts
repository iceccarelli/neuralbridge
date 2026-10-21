import { expect, test } from '@playwright/test';

// The pricing page against a REAL assurance API (GET /v1/plans), in whichever
// mode that API was started in. Set E2E_PAYG=on when the API has
// ASSURANCE_PRICE_PAYG and ASSURANCE_PAYG_METER_EVENT set (and a test-mode or
// no Stripe key); leave it unset for an API without them. Requires the Next
// server to have been started with NEXT_PUBLIC_ASSURANCE_API_URL pointing at
// that API. Pay-as-you-go is verified against a fake Stripe only, so this spec
// never completes a checkout: with no Stripe key on the API the honest outcome
// of pressing the button is an error message, which is what it asserts.

const payg = process.env.E2E_PAYG === 'on';

test.describe(`pricing page, pay-as-you-go ${payg ? 'configured' : 'not configured'}`, () => {
  test('the page renders the catalogue the API serves, and pay-as-you-go only if listed', async ({
    page,
  }) => {
    await page.goto('/#pricing');
    // Proof the live catalogue was used, not the static fallback.
    await expect(page.locator('.pricing-live-note')).toBeVisible();
    await expect(page.locator('.price-card').first()).toBeVisible();

    const prices = await page.locator('.price-amount').allTextContents();
    expect(prices[0]).toContain('Free');
    expect(prices.join(' ')).toContain('390');
    expect(prices.join(' ')).toContain('1,290');

    if (!payg) {
      await expect(page.locator('#payg')).toHaveCount(0);
      await expect(page.getByText('Pay as you go')).toHaveCount(0);
      return;
    }

    const card = page.locator('#payg');
    await expect(card).toBeVisible();
    await expect(card.locator('.price-name')).toHaveText('Pay as you go');
    await expect(card.locator('.price-amount')).toHaveText('Pay per use');
    // No amount is shown for it: the unit price lives in Stripe, not here.
    await expect(card).not.toContainText(/€\s*\d/);

    await card.getByRole('button', { name: /pay as you go/i }).click();
    await card.getByPlaceholder('you@company.com').fill('buyer@example.de');
    await card.getByRole('button', { name: /continue to stripe checkout/i }).click();
    // No Stripe key on this API: it must say so, not pretend.
    await expect(card.locator('.playground-error')).toBeVisible();
    expect(page.url()).not.toContain('checkout.stripe.com');
  });
});
