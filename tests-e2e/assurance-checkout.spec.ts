import { test, expect, type Page } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Website -> checkout success -> workspace, against the REAL local API.
//
// Stripe itself is not reachable from a test. What is real here is everything after the
// webhook: the pending key is staged through the real AccountStore.apply_checkout (the
// call the webhook makes), `GET /v1/checkout/complete` hands it over once and deletes it,
// `GET /v1/me` reports the plan, and the workspace opens with that key.

const seedPath = process.env.ASSURANCE_E2E_SEED;
const apiBase = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || 'http://127.0.0.1:8001';
const KEY_STORAGE = 'nb-api-key';

test.describe.configure({ mode: 'serial' });

test.describe('Checkout success hands the buyer into the workspace', () => {
  test.beforeAll(() => {
    test.skip(!seedPath, 'Set ASSURANCE_E2E_SEED (run scripts/e2e-assurance.sh) — not faking a payment.');
  });

  // What the Stripe webhook does after a payment, through the real store.
  function stage(sessionId: string, tier: 'cell' | 'register') {
    const res = spawnSync(
      process.env.ASSURANCE_E2E_PYTHON || 'python',
      [join(process.cwd(), 'scripts', 'e2e_seed_assurance.py'), seedPath!, 'unused', '--stage-checkout', sessionId, tier],
      { env: { ...process.env, PYTHONPATH: join(process.cwd(), 'src') } },
    );
    expect(res.status, res.stderr.toString()).toBe(0);
  }

  const stored = (page: Page) => page.evaluate((k) => window.sessionStorage.getItem(k), KEY_STORAGE);

  test('Cell: confirm, show the key once, read the plan from /v1/me, open the workspace with that key', async ({
    page,
    request,
  }) => {
    const sid = `cs_e2e_cell_${Date.now()}`;
    stage(sid, 'cell');
    await page.goto(`/checkout/success?session_id=${sid}`);

    const keyBox = page.getByTestId('issued-key');
    await expect(keyBox).toBeVisible({ timeout: 20_000 });
    const key = (await keyBox.textContent())!.trim();
    expect(key).toMatch(/^asr_/);

    // The plan section is the API's answer for THIS key, not text this page made up.
    const me = await (await request.get(`${apiBase}/v1/me`, { headers: { 'X-API-Key': key } })).json();
    const plan = page.getByTestId('checkout-plan');
    await expect(plan).toContainText(me.plan.name, { timeout: 10_000 });
    await expect(plan).toContainText(me.account.status);
    for (const line of me.plan.includes) await expect(plan).toContainText(line.slice(0, 40));
    await expect(plan).toContainText('GET /v1/me');

    // The key lives in this tab's sessionStorage only, never in the URL or localStorage.
    expect(await stored(page)).toBe(key);
    expect(await page.evaluate(() => JSON.stringify(window.localStorage))).not.toContain(key);
    expect(page.url()).not.toContain(key);

    await page.getByRole('link', { name: 'Open your workspace' }).click();
    await expect(page).toHaveURL(/\/assurance$/);
    await expect(page.getByLabel('API key')).toHaveValue(key);
    // A brand-new account: the workspace loads with its key and says honestly that nothing is enrolled.
    await expect(page.getByText(/No machine is enrolled in your ledger/)).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('.aw-alert')).toHaveCount(0);
    await expect(page.locator('section#aw-plan').getByTestId('plan-name')).toContainText(me.plan.name);

    // The key was handed over once: the same session cannot be collected again.
    const again = await request.get(`${apiBase}/v1/checkout/complete?session_id=${sid}`);
    expect(again.status()).toBe(202);
  });

  test('the page waits for the webhook, and picks the key up when it arrives', async ({ page }) => {
    const sid = `cs_e2e_late_${Date.now()}`;
    await page.goto(`/checkout/success?session_id=${sid}`);
    await expect(page.getByText(/Confirming your payment/)).toBeVisible();
    await expect(page.getByTestId('issued-key')).toHaveCount(0);
    // Not collecting anything is not a failure yet, and no workspace link is offered before a key exists.
    await expect(page.getByRole('link', { name: 'Open your workspace' })).toHaveCount(0);
    stage(sid, 'cell');
    await expect(page.getByTestId('issued-key')).toBeVisible({ timeout: 20_000 });
    await expect(page.getByRole('link', { name: 'Open your workspace' })).toBeVisible();
  });

  test('Register: the plan is shown as it is, and the workspace link says what it will and will not show', async ({
    page,
    request,
  }) => {
    const sid = `cs_e2e_register_${Date.now()}`;
    stage(sid, 'register');
    await page.goto(`/checkout/success?session_id=${sid}`);
    const key = (await page.getByTestId('issued-key').textContent({ timeout: 20_000 }))!.trim();
    const me = await (await request.get(`${apiBase}/v1/me`, { headers: { 'X-API-Key': key } })).json();
    await expect(page.getByTestId('checkout-plan')).toContainText(me.plan.name, { timeout: 10_000 });
    await expect(page.getByTestId('checkout-next')).toContainText(/fleet and change-assurance views need the Cell plan/i);
    await page.getByRole('link', { name: 'Open your workspace' }).click();
    // The server's refusal, with its remedy: not a blank page and not a made-up fleet.
    await expect(page.locator('section#aw-fleet').getByRole('alert')).toContainText('(402)', { timeout: 20_000 });
    await expect(page.locator('section#aw-plan').getByTestId('plan-tier')).toContainText('register');
  });

  test('a session whose key was already collected says so, instead of waiting on a webhook that has come', async ({
    page,
    request,
  }) => {
    test.setTimeout(90_000);
    const sid = `cs_e2e_gone_${Date.now()}`;
    stage(sid, 'cell');
    expect((await request.get(`${apiBase}/v1/checkout/complete?session_id=${sid}`)).status()).toBe(200);
    await page.goto(`/checkout/success?session_id=${sid}`);
    const msg = page.getByTestId('checkout-nokey');
    await expect(msg).toBeVisible({ timeout: 60_000 });
    await expect(msg).toContainText(/already collected/i);
    await expect(msg).toContainText(/shown once/i);
    await expect(msg).toContainText(/webhook/i);
    await expect(msg).toContainText(sid);
    await expect(page.getByTestId('issued-key')).toHaveCount(0);
  });

  test('a key already saved in this tab is offered, with its plan read from the API', async ({ page, request }) => {
    test.setTimeout(90_000);
    const seed = JSON.parse(readFileSync(seedPath!, 'utf8'));
    await page.goto('/assurance');
    await page.evaluate(([k, v]) => window.sessionStorage.setItem(k, v), [KEY_STORAGE, seed.key_g]);
    const me = await (await request.get(`${apiBase}/v1/me`, { headers: { 'X-API-Key': seed.key_g } })).json();
    await page.goto(`/checkout/success?session_id=cs_e2e_never_staged_${Date.now()}`);
    const saved = page.getByTestId('checkout-saved-key');
    await expect(saved).toBeVisible({ timeout: 60_000 });
    await expect(saved).toContainText(me.plan.name);
    await expect(saved.getByRole('link', { name: 'Open your workspace' })).toBeVisible();
    await expect(page.locator('body')).not.toContainText(seed.key_g);
  });

  test('no session id and no API are said plainly', async ({ page }) => {
    await page.goto('/checkout/success');
    await expect(page.getByText('No checkout session found')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Open your workspace' })).toHaveCount(0);
  });
});
