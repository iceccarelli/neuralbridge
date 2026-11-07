import { test, expect } from './support/fixtures';

// The conversion path is one connected journey with no dead end: /start lists nine labelled steps,
// every in-site link on it resolves, the "account" CTA lands on the contact form with the account
// intent selected, and the form says plainly that nothing is created by sending it. The services
// page lists eight services, each answering the same questions.

const STEP_IDS = ['understand', 'free', 'account', 'enrol', 'evidence', 'verify', 'deliverable', 'paid', 'ongoing'];

test.describe('conversion path', () => {
  test('/start has nine labelled steps and every in-site link resolves', async ({ page, request }) => {
    await page.goto('/start');
    await expect(page.getByTestId('start-glance')).toContainText('Not available');
    for (const id of STEP_IDS) {
      const step = page.locator(`ol.journey li#${id}`);
      await expect(step, id).toHaveCount(1);
      await expect(step.locator('.tag').first(), `${id} carries a state label`).toBeVisible();
    }
    const hrefs = await page.locator('ol.journey a[href^="/"]').evaluateAll((els) =>
      [...new Set(els.map((e) => (e as HTMLAnchorElement).getAttribute('href') || ''))],
    );
    expect(hrefs.length).toBeGreaterThan(10);
    for (const href of hrefs) {
      const res = await request.get(href.split('#')[0] || '/');
      expect(res.status(), href).toBe(200);
    }
  });

  test('the account CTA opens the contact form on the account intent and does not pretend to send', async ({ page }) => {
    await page.goto('/start');
    await page.getByRole('link', { name: 'Ask for an account or key' }).click();
    await expect(page).toHaveURL(/\/contact\?intent=account/);
    await expect(page.getByLabel('What is this about?')).toHaveValue('account');
    await expect(page.getByText(/nothing is sent until you do/i)).toBeVisible();
  });

  test('/services lists eight services that each answer the same questions', async ({ page }) => {
    await page.goto('/services');
    const services = page.locator('article.service');
    await expect(services).toHaveCount(8);
    for (const label of [
      'Customer inputs',
      'Deliverables',
      'Evidence produced',
      'Automated by the software',
      'Needs engineering or named-person review',
      'Exclusions',
      'Technical prerequisites',
      'Customer responsibilities',
      'Ongoing-support dependency',
    ]) {
      await expect(services.first().getByRole('heading', { name: label })).toHaveCount(1);
    }
    await expect(services.getByText(/€|\bEUR\b/)).toHaveCount(0);
  });
});
