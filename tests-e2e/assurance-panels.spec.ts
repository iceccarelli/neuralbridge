import { test, expect } from './support/fixtures';
import { type Page } from '@playwright/test';
import { mkdirSync, readFileSync } from 'node:fs';

// The "Enrol a machine" and "Public intelligence lookup" panels of /assurance against the REAL
// local Assurance API (scripts/e2e-assurance-panels.sh): real accounts, a real per-account
// ledger, a real intel observation store built from tests/fixtures/intel. Nothing in the
// assurance API is mocked. The fixtures are contract fixtures (minimized or synthetic), not
// live feeds, and the manifests are synthetic.
//
// Tests tagged @nostore / @badstore run in their own phase against an API started without the
// store, or with a file that is not a store.

const seedPath = process.env.PANELS_SEED;
const shots = process.env.PANELS_SHOTS || '/var/tmp/ws-shots';
const apiBase = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || 'http://127.0.0.1:8001';

type Seed = {
  key_cell: string;
  key_free: string;
  manifest: Record<string, unknown>;
  manifest_changed: Record<string, unknown>;
  manifest_uncomparable: Record<string, unknown>;
  cve_listed: string;
  cve_nvd_only: string;
  cve_nowhere: string;
};

// Sentences the SERVER writes about its own limits ("not verified safe") are quoted back by the
// panel; they are removed before checking that the panel adds no claim of its own.
const SERVER_LIMITS = [/not verified safe[^\n]*/gi, /no verification has been run yet[^\n]*/gi, /never_verified/gi];
const CLAIMS = /\b(compliant|compliance|certified|approved|passed|is safe|are safe)\b/i;
function withoutServerLimits(text: string): string {
  return SERVER_LIMITS.reduce((t, re) => t.replace(re, ''), text);
}

test.describe.configure({ mode: 'serial' });

test.describe('Assurance workspace — enrol and public intelligence panels', () => {
  let seed: Seed;
  test.beforeAll(() => {
    test.skip(!seedPath, 'Set PANELS_SEED (run scripts/e2e-assurance-panels.sh): not faking an API.');
    seed = JSON.parse(readFileSync(seedPath!, 'utf8'));
    mkdirSync(shots, { recursive: true });
  });
  test.beforeEach(({}, info) => {
    test.skip(info.project.name !== 'desktop-chromium', 'One viewport: the spec shares one ledger.');
  });

  async function enter(page: Page, key: string) {
    await page.goto('/assurance');
    await page.getByLabel('API key').fill(key);
    await page.getByRole('button', { name: 'Refresh' }).click();
  }
  const enrol = (page: Page) => page.locator('section#aw-enrol');
  const intel = (page: Page) => page.locator('section#aw-intel');

  async function submitEnrol(page: Page, manifest: unknown, opts: { actor?: string; owner?: string; site?: string } = {}) {
    const p = enrol(page);
    await p.getByLabel(/^Safety manifest/).fill(typeof manifest === 'string' ? manifest : JSON.stringify(manifest));
    await p.getByLabel(/^Your name/).fill(opts.actor ?? 'Ada Integrator');
    await p.getByLabel(/^Owner/).fill(opts.owner ?? 'Example GmbH');
    await p.getByLabel(/^Site/).fill(opts.site ?? '');
    await p.getByRole('button', { name: 'Enrol machine' }).click();
  }

  // ------------------------------------------------------------------ Enrol a machine
  test('enrolling a synthetic manifest shows the receipt faithfully, every function never_verified', async ({ page }) => {
    await enter(page, seed.key_cell);
    await submitEnrol(page, seed.manifest);
    const receipt = page.getByTestId('enrol-receipt');
    await expect(receipt).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('enrol-result')).toBeFocused(); // focus moved to the answer

    await expect(page.getByTestId('enrol-outcome')).toContainText('enrolled');
    await expect(receipt).toHaveAttribute('data-status', 'enrolled');
    await expect(page.getByTestId('enrol-machine')).toHaveText('Grimaldi/AR-7#E2E-0001');
    await expect(page.getByTestId('enrol-config-hash')).toContainText(/[0-9a-f]{64}/);
    await expect(page.getByTestId('enrol-written')).toContainText(/yes — manifest entry 1, enrolment entry 2/);
    await expect(page.getByTestId('enrol-ceiling')).toContainText('a ceiling, not a result');

    // every declared function reads never_verified, as the server returned it
    const rows = page.getByTestId('enrol-coverage').locator('tbody tr');
    await expect(rows).toHaveCount(2);
    for (const r of await rows.all()) await expect(r).toHaveAttribute('data-coverage', 'never_verified');

    // the limits the server lists, and the next steps
    const limits = page.getByTestId('enrol-not-established').locator('li');
    expect(await limits.count()).toBeGreaterThanOrEqual(4);
    await expect(page.getByTestId('enrol-not-established')).toContainText('no verification has been run yet');
    await expect(page.getByTestId('enrol-not-established')).toContainText('not authenticated to a physical unit');
    await expect(page.getByTestId('enrol-next-steps')).toContainText('machinery coverage');

    expect(withoutServerLimits(await receipt.innerText())).not.toMatch(CLAIMS);
    await enrol(page).screenshot({ path: `${shots}/enrol-enrolled.png` });
  });

  test('enrolling the same manifest again is already_enrolled and writes nothing', async ({ page }) => {
    await enter(page, seed.key_cell);
    await submitEnrol(page, seed.manifest);
    await expect(page.getByTestId('enrol-outcome')).toContainText('already_enrolled', { timeout: 15_000 });
    await expect(page.getByTestId('enrol-written')).toContainText('none (written: false)');
    await expect(page.getByTestId('enrol-conflict')).toHaveCount(0);
    for (const r of await page.getByTestId('enrol-coverage').locator('tbody tr').all()) {
      await expect(r).toHaveAttribute('data-coverage', 'never_verified');
    }
    await enrol(page).screenshot({ path: `${shots}/enrol-already.png` });
  });

  test('one item version changed is configuration_differs (409) with the pointer, nothing written', async ({ page }) => {
    await enter(page, seed.key_cell);
    await submitEnrol(page, seed.manifest_changed);
    const conflict = page.getByTestId('enrol-conflict');
    await expect(conflict).toBeVisible({ timeout: 15_000 });
    await expect(conflict).toContainText('409');
    await expect(conflict).toContainText('drift, not an enrolment');
    await expect(page.getByTestId('enrol-receipt')).toHaveAttribute('data-status', 'configuration_differs');
    await expect(page.getByTestId('enrol-receipt')).toHaveAttribute('data-state', 'refused');
    await expect(page.getByTestId('enrol-pointer')).toContainText('machinery diff');
    await expect(page.getByTestId('enrol-enrolled-hash')).toContainText(/[0-9a-f]{64}/);
    await expect(page.getByTestId('enrol-written')).toContainText('none (written: false)');
    await expect(page.getByTestId('enrol-next-steps')).toHaveCount(0); // a refusal has no "next steps"
    await enrol(page).screenshot({ path: `${shots}/enrol-configuration-differs.png` });
  });

  test('the same configuration under a different owner is identity_conflict (409)', async ({ page }) => {
    await enter(page, seed.key_cell);
    await submitEnrol(page, seed.manifest, { owner: 'Other Owner AG' });
    await expect(page.getByTestId('enrol-conflict')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('enrol-receipt')).toHaveAttribute('data-status', 'identity_conflict');
    await expect(page.getByTestId('enrol-conflicts')).toContainText('owner');
    await expect(page.getByTestId('enrol-conflicts')).toContainText('Example GmbH');
    await expect(page.getByTestId('enrol-conflicts')).toContainText('Other Owner AG');
    await expect(page.getByTestId('enrol-pointer')).toContainText('a person must decide');
  });

  test('items that carry no hash are listed, with the server note', async ({ page }) => {
    await enter(page, seed.key_cell);
    await submitEnrol(page, seed.manifest_uncomparable);
    await expect(page.getByTestId('enrol-outcome')).toContainText('enrolled', { timeout: 15_000 });
    await expect(page.getByTestId('enrol-uncomparable')).toContainText('a change to them would not be detectable');
    await expect(page.getByTestId('enrol-uncomparable-items')).toContainText('ITM-PARAMS');
  });

  test('an empty or automation-looking actor is refused here and nothing is sent; the server refuses it too', async ({ page, request }) => {
    await enter(page, seed.key_cell);
    const sent: string[] = [];
    page.on('request', (r) => {
      if (r.url().includes('/v1/machinery/enrol')) sent.push(r.method());
    });
    for (const actor of ['', '   ', 'automation', 'Watch Agent']) {
      await submitEnrol(page, seed.manifest, { actor });
      await expect(page.getByTestId('enrol-result').getByRole('alert')).toBeVisible();
      await expect(page.getByTestId('enrol-receipt')).toHaveCount(0);
    }
    await expect(page.getByTestId('enrol-result')).toContainText(/automated actor|named person/i);
    expect(sent).toEqual([]); // not even an OPTIONS preflight reached the enrol route

    // The server agrees on its own, so the client check is a convenience and not the control.
    const res = await request.post(`${apiBase}/v1/machinery/enrol`, {
      headers: { 'X-API-Key': seed.key_cell },
      data: { manifest: seed.manifest, actor: 'automation' },
    });
    expect(res.status()).toBe(422);
    expect(JSON.stringify(await res.json())).toMatch(/named person/);
    await enrol(page).screenshot({ path: `${shots}/enrol-actor-refused.png` });
  });

  test('a manifest the server cannot read shows the server 422, not a receipt', async ({ page }) => {
    await enter(page, seed.key_cell);
    await submitEnrol(page, {});
    const out = page.getByTestId('enrol-result');
    await expect(out.getByRole('alert')).toContainText('422', { timeout: 15_000 });
    await expect(page.getByTestId('enrol-receipt')).toHaveCount(0);
    await submitEnrol(page, '{not json');
    await expect(out).toContainText('not valid JSON');
  });

  test('an unentitled key gets 402 and a wrong key 401, both shown as such', async ({ page }) => {
    await enter(page, seed.key_free);
    await submitEnrol(page, seed.manifest);
    await expect(page.getByTestId('enrol-result').getByRole('alert')).toContainText('402', { timeout: 15_000 });
    await expect(page.getByTestId('enrol-receipt')).toHaveCount(0);
    await enter(page, 'asr_not_a_real_key');
    await submitEnrol(page, seed.manifest);
    await expect(page.getByTestId('enrol-result').getByRole('alert')).toContainText('401', { timeout: 15_000 });
  });

  test('a manifest file can be loaded instead of pasted', async ({ page }) => {
    await enter(page, seed.key_cell);
    await enrol(page).getByLabel(/^Or load a manifest file/).setInputFiles({
      name: 'manifest.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(seed.manifest)),
    });
    await expect(enrol(page).getByLabel(/^Safety manifest/)).toHaveValue(/E2E-0001/);
    await enrol(page).getByLabel(/^Your name/).fill('Ada Integrator');
    await enrol(page).getByLabel(/^Owner/).fill('Example GmbH');
    await enrol(page).getByRole('button', { name: 'Enrol machine' }).click();
    await expect(page.getByTestId('enrol-outcome')).toContainText('already_enrolled', { timeout: 15_000 });
  });

  // ------------------------------------------------------------------ Public intelligence lookup
  async function lookup(page: Page, id: string) {
    await intel(page).getByLabel('CVE id').fill(id);
    await intel(page).getByRole('button', { name: 'Look up' }).click();
  }

  test('a CVE in the fixtures: KEV listed, EPSS available with its score date, NVD present, with provenance', async ({ page }) => {
    await enter(page, seed.key_cell);
    await lookup(page, seed.cve_listed.toLowerCase()); // typed in lower case: upper-cased before it is sent
    await expect(page.getByTestId('intel-report')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('intel-result')).toBeFocused();
    await expect(intel(page).getByLabel('CVE id')).toHaveValue(seed.cve_listed);
    await expect(page.getByTestId('intel-kev')).toHaveAttribute('data-state', 'listed');
    await expect(page.getByTestId('intel-epss')).toHaveAttribute('data-state', 'available');
    await expect(page.getByTestId('intel-epss-score')).toHaveText(/^0?\.\d+$/);
    await expect(page.getByTestId('intel-epss-date')).toHaveText(/^\d{4}-\d{2}-\d{2}/);
    await expect(page.getByTestId('intel-nvd')).toHaveAttribute('data-state', 'present');
    await expect(page.getByTestId('intel-summary')).toHaveAttribute('data-state', 'recorded');
    // every statement is cited: observation, source, retrieval time, sha256
    const cite = page.getByTestId('intel-kev').getByTestId('intel-citation');
    await expect(cite).toContainText(/observation #\d+ · cisa_kev · retrieved \d{4}-\d{2}-\d{2}/);
    await expect(cite).toContainText(/sha256 [0-9a-f]{64}/);
    expect(await page.getByTestId('intel-observation').count()).toBeGreaterThanOrEqual(3);
    await expect(page.getByTestId('intel-not-established')).toContainText('Version ranges are not matched');
    await intel(page).screenshot({ path: `${shots}/intel-listed.png` });
  });

  test('a CVE not in KEV: the "does not establish" note is shown, and a missing EPSS score is unavailable, never 0', async ({ page }) => {
    await enter(page, seed.key_cell);
    await lookup(page, seed.cve_nvd_only);
    const kev = page.getByTestId('intel-kev');
    await expect(kev).toBeVisible({ timeout: 15_000 });
    await expect(kev).toHaveAttribute('data-state', 'not_listed_in_kev');
    await expect(page.getByTestId('intel-kev-note')).toContainText('does not establish that the vulnerability is not exploited');
    const epss = page.getByTestId('intel-epss');
    await expect(epss).toHaveAttribute('data-state', 'unavailable');
    await expect(epss).toContainText('unavailable');
    await expect(page.getByTestId('intel-epss-score')).toHaveCount(0);
    await expect(page.getByTestId('intel-epss-note')).toContainText('not a score of 0.0');
    // no digit stands where a score would be: strip the server's own sentence about 0.0 and look
    expect((await epss.innerText()).replace(/not a score of 0\.0/g, '')).not.toMatch(/\b0(\.0*)?\b/);
    await expect(page.getByTestId('intel-nvd')).toHaveAttribute('data-state', 'present');
    await intel(page).screenshot({ path: `${shots}/intel-not-in-kev.png` });
  });

  test('a CVE no source mentions is unknown, drawn apart from a recorded one and not green', async ({ page }) => {
    await enter(page, seed.key_cell);
    await lookup(page, seed.cve_nowhere);
    const summary = page.getByTestId('intel-summary');
    await expect(summary).toBeVisible({ timeout: 15_000 });
    await expect(summary).toHaveAttribute('data-state', 'unknown');
    await expect(summary).toContainText('Unknown, not clear');
    await expect(page.getByTestId('intel-nvd')).toHaveAttribute('data-state', 'unknown');
    const style = await summary.evaluate((el) => {
      const s = getComputedStyle(el);
      return { color: s.borderLeftColor, style: s.borderLeftStyle };
    });
    expect(style.style).toBe('dashed');
    const [r, g, b] = style.color.match(/\d+/g)!.map(Number);
    expect(g > r + 40 && g > b + 20 && g > 100).toBe(false); // not a green
    // the page's success green is rgb(6, 125, 104): the unknown summary must not use it
    expect(style.color).not.toBe('rgb(6, 125, 104)');
    await intel(page).screenshot({ path: `${shots}/intel-unknown.png` });
  });

  test('a malformed CVE id is refused here and nothing is sent', async ({ page }) => {
    await enter(page, seed.key_cell);
    const sent: string[] = [];
    page.on('request', (r) => {
      if (r.url().includes('/v1/intel/')) sent.push(r.url());
    });
    for (const bad of ['', 'CVE-1', 'CVE-2021-123', 'not a cve', '../../v1/me', 'CVE-2021-44228/x']) {
      await lookup(page, bad);
      await expect(page.getByTestId('intel-result').getByRole('alert')).toBeVisible();
      await expect(page.getByTestId('intel-report')).toHaveCount(0);
    }
    expect(sent).toEqual([]);
  });

  test('a free key gets 402 on the lookup', async ({ page }) => {
    await enter(page, seed.key_free);
    await lookup(page, seed.cve_listed);
    await expect(page.getByTestId('intel-result').getByRole('alert')).toContainText('402', { timeout: 15_000 });
    await expect(page.getByTestId('intel-report')).toHaveCount(0);
  });

  test('the panels can be driven from the keyboard', async ({ page }) => {
    await enter(page, seed.key_cell);
    await intel(page).getByLabel('CVE id').focus();
    await page.keyboard.type(seed.cve_listed);
    await page.keyboard.press('Enter'); // submits the form
    await expect(page.getByTestId('intel-report')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('intel-result')).toBeFocused();
  });

  // ------------------------------------------------------------------ the operator's store is unavailable
  test('@nostore with no store configured, the lookup says so and what the operator must do', async ({ page }) => {
    await enter(page, seed.key_cell);
    await lookup(page, seed.cve_listed);
    const banner = page.getByTestId('intel-store-banner');
    await expect(banner).toBeVisible({ timeout: 15_000 });
    await expect(banner).toHaveAttribute('data-code', 'no_intel_store_configured');
    await expect(banner).toContainText('not configured (503)');
    await expect(banner).toContainText('Operator action');
    await expect(banner).toContainText('ASSURANCE_INTEL_STORE');
    await expect(banner).toContainText('not an empty result');
    await expect(page.getByTestId('intel-report')).toHaveCount(0);
    await expect(page.getByTestId('intel-summary')).toHaveCount(0); // no "nothing known" look-alike
    await intel(page).screenshot({ path: `${shots}/intel-503-nostore.png` });
  });

  test('@badstore with a file that is not a store, the banner is the unreadable one', async ({ page }) => {
    await enter(page, seed.key_cell);
    await lookup(page, seed.cve_listed);
    const banner = page.getByTestId('intel-store-banner');
    await expect(banner).toBeVisible({ timeout: 15_000 });
    await expect(banner).toHaveAttribute('data-code', 'intel_store_unreadable');
    await expect(banner).toContainText('unreadable (503)');
    await expect(banner).toContainText('Operator action');
    await expect(page.getByTestId('intel-report')).toHaveCount(0);
    await intel(page).screenshot({ path: `${shots}/intel-503-unreadable.png` });
  });
});
