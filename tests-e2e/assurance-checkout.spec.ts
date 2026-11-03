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

  // The claim token is NOT in the success URL (Stripe stores that URL). The tab that started checkout holds the
  // token POST /v1/checkout returned in its sessionStorage under `nb-checkout-claim:<session_id>` (written by
  // PricingPlans before it redirects). The seed registers `claim-<session>` the way /v1/checkout does.
  const CLAIM_STORAGE_PREFIX = 'nb-checkout-claim:';
  const claimToken = (sid: string) => `claim-${sid}`;
  const successUrl = (sid: string) => `/checkout/success?session_id=${sid}`;
  // The tab that started the checkout: its sessionStorage entry exists before the success page loads.
  const arriveAsBuyer = async (page: Page, sid: string) => {
    await page.goto('/');
    await page.evaluate(([k, v]) => window.sessionStorage.setItem(k, v), [`${CLAIM_STORAGE_PREFIX}${sid}`, claimToken(sid)]);
    await page.goto(successUrl(sid));
  };
  const claim = (request: import('@playwright/test').APIRequestContext, sid: string, token = claimToken(sid)) =>
    request.post(`${apiBase}/v1/checkout/complete`, { data: { session_id: sid, claim_token: token } });

  const stored = (page: Page) => page.evaluate((k) => window.sessionStorage.getItem(k), KEY_STORAGE);

  test('Cell: confirm, show the key once, read the plan from /v1/me, open the workspace with that key', async ({
    page,
    request,
  }) => {
    const sid = `cs_e2e_cell_${Date.now()}`;
    stage(sid, 'cell');
    await arriveAsBuyer(page, sid);

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
    // (scoped to the fleet section: the coverage view repeats the sentence, which made an unscoped locator ambiguous)
    await expect(page.locator('section#aw-fleet').getByText(/No machine is enrolled in your ledger/)).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('.aw-alert')).toHaveCount(0);
    await expect(page.locator('section#aw-plan').getByTestId('plan-name')).toContainText(me.plan.name);

    // The key was handed over once: the same session cannot be collected again (410: a definite answer,
    // not "pending forever"), and the retired GET never returns a key whatever it is given.
    expect((await claim(request, sid)).status()).toBe(410);
    expect((await request.get(`${apiBase}/v1/checkout/complete?session_id=${sid}`)).status()).toBe(410);
  });

  test('the page waits for the webhook, and picks the key up when it arrives', async ({ page }) => {
    const sid = `cs_e2e_late_${Date.now()}`;
    await arriveAsBuyer(page, sid);
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
    await arriveAsBuyer(page, sid);
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
    expect((await claim(request, sid)).status()).toBe(200);
    await arriveAsBuyer(page, sid);
    const msg = page.getByTestId('checkout-gone');
    await expect(msg).toBeVisible({ timeout: 60_000 });
    await expect(msg).toContainText(/already been collected/i);
    await expect(msg).toContainText(/shown once/i);
    await expect(msg).toContainText(/treat it as exposed/i);   // a key someone else collected is exposed
    await expect(msg).toContainText(sid);
    await expect(page.getByTestId('issued-key')).toHaveCount(0);
  });

  test('a key already saved in this tab is offered, with its plan read from the API', async ({ page, request }) => {
    test.setTimeout(90_000);
    const seed = JSON.parse(readFileSync(seedPath!, 'utf8'));
    await page.goto('/assurance');
    await page.evaluate(([k, v]) => window.sessionStorage.setItem(k, v), [KEY_STORAGE, seed.key_g]);
    const me = await (await request.get(`${apiBase}/v1/me`, { headers: { 'X-API-Key': seed.key_g } })).json();
    await arriveAsBuyer(page, `cs_e2e_never_staged_${Date.now()}`);
    const saved = page.getByTestId('checkout-saved-key');
    await expect(saved).toBeVisible({ timeout: 60_000 });
    await expect(saved).toContainText(me.plan.name);
    await expect(saved.getByRole('link', { name: 'Open your workspace' })).toBeVisible();
    await expect(page.locator('body')).not.toContainText(seed.key_g);
  });

  test('another tab or device has no claim token: it is told the key is held, and nothing is collected', async ({
    page,
    request,
  }) => {
    test.setTimeout(90_000);
    const sid = `cs_e2e_othertab_${Date.now()}`;
    stage(sid, 'cell');
    await page.goto(successUrl(sid));      // no sessionStorage entry: not the tab that started the checkout
    const msg = page.getByTestId('checkout-claim');
    await expect(msg).toBeVisible({ timeout: 60_000 });
    await expect(msg).toContainText(/this tab does not hold the claim token/i);
    await expect(msg).toContainText(sid);
    await expect(page.getByTestId('issued-key')).toHaveCount(0);
    expect(page.url()).not.toContain(sid);   // the session id is stripped from the address bar
    // Nothing was consumed: the buyer's own tab (the token holder) can still collect it.
    expect((await claim(request, sid)).status()).toBe(200);
  });

  test('no session id and no API are said plainly', async ({ page }) => {
    await page.goto('/checkout/success');
    await expect(page.getByText('No checkout session found')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Open your workspace' })).toHaveCount(0);
  });
});
