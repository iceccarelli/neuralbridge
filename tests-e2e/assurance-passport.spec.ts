import { test, expect, type APIRequestContext, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

// The "Machine passport" panel of /assurance against the REAL local Assurance API (seeded by
// scripts/e2e_seed_panels.py; run with PANELS_SEED set, see deploy/assurance/E2E.md). Passports
// are produced by the real POST /v1/machinery/passport with seal:false (nothing is written to the
// ledger) and re-checked by the real POST /v1/machinery/passport/check. The manifest is synthetic.
// The one request that is interrupted (the "unreachable" test) is aborted in the browser; no
// assurance logic is replaced.

const seedPath = process.env.PANELS_SEED;
const apiBase = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || 'http://127.0.0.1:8001';

type Seed = { key_cell: string; key_free: string; manifest: Record<string, unknown> };

const CLAIMS = /\b(compliant|compliance|certified|approved|passed|is safe|are safe)\b/i;

test.describe.configure({ mode: 'serial' });

test.describe('Assurance workspace — machine passport panel', () => {
  let seed: Seed;
  let passport: Record<string, unknown>;

  async function assemble(request: APIRequestContext): Promise<Record<string, unknown>> {
    const r = await request.post(`${apiBase}/v1/machinery/passport`, {
      headers: { 'X-API-Key': seed.key_cell },
      data: { manifest: seed.manifest, actor: 'Ada Integrator', seal: false },
    });
    expect(r.status()).toBe(200);
    const body = await r.json();
    delete body.sealed;
    delete body.verdict;
    return body;
  }

  test.beforeAll(async ({ request }) => {
    test.skip(!seedPath, 'Set PANELS_SEED (run scripts/e2e-assurance-panels.sh): not faking an API.');
    seed = JSON.parse(readFileSync(seedPath!, 'utf8'));
    passport = await assemble(request);
  });

  const panel = (page: Page) => page.locator('section#aw-passport');

  async function open(page: Page, key = '') {
    await page.goto('/assurance');
    if (key) {
      await page.getByLabel('API key').fill(key);
      await page.getByRole('button', { name: 'Refresh' }).click();
    }
  }

  async function paste(page: Page, doc: unknown) {
    await panel(page).getByLabel(/^Passport file \(JSON\), pasted/).fill(typeof doc === 'string' ? doc : JSON.stringify(doc));
    await panel(page).getByRole('button', { name: 'Check passport' }).click();
  }

  async function assertFits(page: Page) {
    const w = page.viewportSize()!.width;
    const wide = await page.evaluate((vw) => {
      return Array.from(document.body.querySelectorAll('*'))
        .filter((el) => !el.closest('.aw-scroll') && el.getBoundingClientRect().right > vw + 1)
        .slice(0, 5)
        .map((el) => `${el.tagName}.${(el as HTMLElement).className}`);
    }, w);
    expect(wide).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(w);
  }

  test('a real passport is shown with what it asserts, and the check names what it did not look at', async ({ page }) => {
    await open(page); // no API key at all: the check is free
    await paste(page, passport);
    const view = page.getByTestId('passport-view');
    await expect(view).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('passport-result')).toBeFocused();

    await expect(page.getByTestId('passport-check')).toHaveAttribute('data-state', 'no-problem-found');
    await expect(page.getByTestId('passport-check-outcome')).toContainText('no problem found');
    await expect(page.getByTestId('passport-chk-seal')).toHaveText('checked');
    await expect(page.getByTestId('passport-chk-ledger')).toContainText('NOT checked');

    await expect(page.getByTestId('passport-verdict')).toContainText('gaps');
    await expect(page.getByTestId('passport-machine')).toContainText('Grimaldi AR-7');
    await expect(page.getByTestId('passport-machine')).toContainText('E2E-0001');
    await expect(page.getByTestId('passport-config-hash')).toContainText(/[0-9a-f]{64}/);
    const rows = page.getByTestId('passport-functions').locator('tbody tr');
    await expect(rows).toHaveCount(2);
    for (const r of await rows.all()) {
      await expect(r).toHaveAttribute('data-coverage', 'never_verified');
      await expect(r).toContainText('none recorded');
    }

    // evidence: nothing named, no tier: stated as such, not as a good result
    await expect(page.getByTestId('passport-verifications')).toContainText('none: no verification is named');
    await expect(page.getByTestId('passport-tier-floor')).toContainText('not stated');

    // signer: a declared name, no signature
    await expect(page.getByTestId('passport-actor')).toContainText('Ada Integrator');
    await expect(page.getByTestId('passport-signature')).toContainText('A passport carries no signature field');
    await expect(page.getByTestId('passport-actor-basis')).toContainText('not authenticated');

    // the unchecked list: the check's own limit, the producer's skips, and each function
    const gaps = page.getByTestId('passport-gaps');
    await expect(gaps).toContainText('records this passport names');
    await expect(gaps.locator('li[data-source="passport"]').first()).toBeVisible();
    await expect(gaps).toContainText('SF-01: coverage is never_verified');
    await expect(gaps).toContainText('SF-02: coverage is never_verified');
    await expect(gaps).toContainText('No verification is named');

    expect(await view.innerText()).not.toMatch(CLAIMS);
    await assertFits(page);
  });

  test('a passport edited after sealing is reported as problems, and what it says is labelled as claims', async ({ page }) => {
    const tampered = JSON.parse(JSON.stringify(passport));
    tampered.evidence.body.functions[0].coverage = 'current';
    await open(page);
    await paste(page, tampered);
    await expect(page.getByTestId('passport-check')).toHaveAttribute('data-state', 'problems', { timeout: 15_000 });
    await expect(page.getByTestId('passport-check-outcome')).toContainText('problems found');
    await expect(page.getByTestId('passport-problems')).toContainText(/edited after sealing|does not hash/);
    await expect(page.getByTestId('passport-untrusted')).toContainText('claims in a file');
    await expect(page.getByTestId('passport-view')).toHaveAttribute('data-check', 'not-established');
    await expect(page.getByTestId('passport-check-outcome')).not.toContainText('no problem found');
    await assertFits(page);
  });

  test('a file that is not a passport is refused with a reason and nothing is drawn', async ({ page }) => {
    await open(page);
    await paste(page, { schema: 'something/else' });
    await expect(page.getByTestId('passport-result').getByRole('alert')).toContainText('not a machine passport');
    await expect(page.getByTestId('passport-view')).toHaveCount(0);
    await paste(page, '{ not json');
    await expect(page.getByTestId('passport-result').getByRole('alert')).toContainText('could not be read as JSON');
    await expect(page.getByTestId('passport-view')).toHaveCount(0);
  });

  test('a passport file can be loaded from disk', async ({ page }) => {
    await open(page);
    await panel(page).getByLabel(/^Or load a passport file/).setInputFiles({
      name: 'passport.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(passport)),
    });
    await expect(panel(page)).toContainText('loaded: passport.json');
    await panel(page).getByRole('button', { name: 'Check passport' }).click();
    await expect(page.getByTestId('passport-source')).toContainText('passport.json', { timeout: 15_000 });
    await expect(page.getByTestId('passport-check')).toHaveAttribute('data-state', 'no-problem-found');
  });

  test('if the check cannot be reached the file is shown as unchecked, never as sound', async ({ page }) => {
    await page.route('**/v1/machinery/passport/check', (route) => route.abort());
    await open(page);
    await paste(page, passport);
    await expect(page.getByTestId('passport-check')).toHaveAttribute('data-state', 'unchecked', { timeout: 15_000 });
    await expect(page.getByTestId('passport-check')).toContainText('not a clean result');
    await expect(page.getByTestId('passport-view')).toHaveAttribute('data-check', 'not-established');
    await expect(page.getByTestId('passport-gaps')).toContainText('nothing in this file has been checked');
    await expect(page.getByTestId('passport-check')).not.toContainText('no problem found');
  });

  test('assembling needs a key; with an entitled key it shows an unsealed passport and writes nothing', async ({ page, request }) => {
    await open(page);
    await panel(page).getByText('Assemble the current passport from a manifest').click();
    await panel(page).getByLabel(/^Safety manifest/).fill(JSON.stringify(seed.manifest));
    await panel(page).getByLabel(/^Your name/).fill('Ada Integrator');
    await panel(page).getByRole('button', { name: 'Assemble, do not seal' }).click();
    await expect(page.getByTestId('passport-result').getByRole('alert')).toContainText('Paste an API key first');

    await page.getByLabel('API key').fill(seed.key_cell);
    await panel(page).getByRole('button', { name: 'Assemble, do not seal' }).click();
    await expect(page.getByTestId('passport-source')).toContainText('not sealed, nothing written', { timeout: 15_000 });
    await expect(page.getByTestId('passport-check')).toHaveAttribute('data-state', 'no-problem-found');

    // the ledger did not grow: a second assembly reads the same ledger head
    const again = await assemble(request);
    const head = (p: Record<string, any>) => p.evidence.body.ledger_head.length;
    expect(head(again)).toBe(head(passport));
  });

  test('an unentitled key is refused with the server\'s 402 and no passport is drawn', async ({ page }) => {
    await open(page, seed.key_free);
    await panel(page).getByText('Assemble the current passport from a manifest').click();
    await panel(page).getByLabel(/^Safety manifest/).fill(JSON.stringify(seed.manifest));
    await panel(page).getByLabel(/^Your name/).fill('Ada Integrator');
    await panel(page).getByRole('button', { name: 'Assemble, do not seal' }).click();
    const alert = page.getByTestId('passport-result').getByRole('alert');
    await expect(alert).toContainText('402', { timeout: 15_000 });
    await expect(page.getByTestId('passport-view')).toHaveCount(0);
  });

  test('a wrong key is a 401 and no passport is drawn', async ({ page }) => {
    await open(page, 'not-a-key-' + 'x'.repeat(20));
    await panel(page).getByText('Assemble the current passport from a manifest').click();
    await panel(page).getByLabel(/^Safety manifest/).fill(JSON.stringify(seed.manifest));
    await panel(page).getByLabel(/^Your name/).fill('Ada Integrator');
    await panel(page).getByRole('button', { name: 'Assemble, do not seal' }).click();
    await expect(page.getByTestId('passport-result').getByRole('alert')).toContainText('401', { timeout: 15_000 });
    await expect(page.getByTestId('passport-view')).toHaveCount(0);
  });

  test('an automation-looking name is refused before anything is sent', async ({ page }) => {
    let sent = 0;
    await page.route('**/v1/machinery/passport', (route) => {
      sent++;
      return route.continue();
    });
    await open(page, seed.key_cell);
    await panel(page).getByText('Assemble the current passport from a manifest').click();
    await panel(page).getByLabel(/^Safety manifest/).fill(JSON.stringify(seed.manifest));
    await panel(page).getByLabel(/^Your name/).fill('automation');
    await panel(page).getByRole('button', { name: 'Assemble, do not seal' }).click();
    await expect(page.getByTestId('passport-result').getByRole('alert')).toBeVisible();
    expect(sent).toBe(0);
  });
});
