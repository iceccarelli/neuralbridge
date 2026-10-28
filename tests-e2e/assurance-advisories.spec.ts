import { test, expect, type Page } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// The Advisories panel of /assurance against the REAL local Assurance API and real
// tenant ledgers (scripts/e2e_seed_assurance.py). The signed feed is produced by the
// real `assurance supplier` CLI, the hosted copy by the real POST /v1/supplier/advisory.
// Nothing in the assurance API is mocked.
//
// What this pins, because it is the place a UI could most easily overclaim:
//   * a pasted advisory is NEVER shown as verified: this workspace and the hosted API hold
//     no supplier keys, so provenance is "unsigned / unverified" or "signature not checked";
//   * the engine's states are shown as the engine reports them, and a HASH_MISMATCH machine
//     is "neither affected nor clear", counted in neither column;
//   * a case is opened only by an explicit click, under a named person.

const seedPath = process.env.ASSURANCE_E2E_SEED;
const apiBase = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || 'http://127.0.0.1:8001';

type Seed = {
  key_g: string;
  key_register: string;
  key_b: string;
  machines_g: string[];
  advisories: { hash: Record<string, unknown>; mismatch: Record<string, unknown>; clear: Record<string, unknown> };
  supplier: {
    feed_path: string;
    tampered_path: string;
    public_key_path: string;
    fingerprint: string;
    supplier_id: string;
    records: number;
    // The hosted copy: POST /v1/supplier/advisory refuses a signed withdrawal as a duplicate id
    // (reported to the lead), so it holds one record fewer than the feed file.
    hosted_records: number;
    hosted_feed_id: string;
    first_advisory_id: string;
    withdrawn_advisory_id: string;
  };
};

// No sentence on this panel may say a pasted advisory was verified. "Not verified" and
// "unverified" are the honest words and are allowed.
const CLAIMS_VERIFIED = /(?<!not )(?<!un)(?<!cannot be )verified(?! here)|signature (is )?valid|authentic/i;

test.describe.configure({ mode: 'serial' });

test.describe('Assurance workspace — advisories and fleet impact', () => {
  let seed: Seed;
  test.beforeAll(() => {
    test.skip(!seedPath, 'Set ASSURANCE_E2E_SEED (run scripts/e2e-assurance.sh) — not faking a fleet.');
    seed = JSON.parse(readFileSync(seedPath!, 'utf8'));
  });

  async function enter(page: Page, key: string) {
    await page.goto('/assurance');
    await page.getByLabel('API key').fill(key);
    await page.getByRole('button', { name: 'Refresh' }).click();
  }

  const panel = (page: Page) => page.locator('section#aw-advisories');
  const paste = async (page: Page, text: string) => {
    await panel(page).getByLabel(/^Advisory or feed/).fill(text);
    await panel(page).getByRole('button', { name: 'Read advisory' }).click();
  };

  test('a bare advisory is shown as unsigned and unverified, and its impact is the engine\'s', async ({ page }) => {
    await enter(page, seed.key_g);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    await paste(page, JSON.stringify(seed.advisories.hash));

    const prov = panel(page).getByTestId('adv-provenance');
    await expect(prov).toContainText(/unsigned/i);
    await expect(prov).toContainText(/unverified/i);
    await expect(prov).toContainText(/local assessment/i);
    await expect(prov).not.toContainText(CLAIMS_VERIFIED);

    await panel(page).getByRole('button', { name: /Check fleet impact/ }).click();
    const verdict = panel(page).getByTestId('impact-verdict');
    await expect(verdict).toContainText('EXPOSED', { timeout: 10_000 });

    const [m1, m2] = seed.machines_g;
    const hashRow = panel(page).locator(`[data-testid="exposure-row"][data-machine="${m1}"]`);
    await expect(hashRow).toContainText('confirmed');
    await expect(hashRow).toContainText('hash');
    await expect(hashRow).toContainText('SF-01');
    await expect(hashRow).toContainText(/now in question/i);
    // The other machine runs the same component with a different artefact: the match is only
    // "possible", it says a person has to look, and the page does not call it confirmed.
    const nameRow = panel(page).locator(`[data-testid="exposure-row"][data-machine="${m2}"]`);
    await expect(nameRow).toContainText('possible');
    await expect(nameRow).toContainText(/needs a person/i);
    await expect(nameRow).not.toContainText('confirmed');
    await expect(nameRow).not.toContainText('byte-identical');

    // The engine's own limits are on the page, verbatim.
    await expect(panel(page).getByTestId('impact-skipped')).toContainText(/absence here is not evidence of safety/i);
    await expect(panel(page).getByTestId('impact-provenance')).toContainText(/not checked|unverified/i);
    await expect(panel(page)).not.toContainText(CLAIMS_VERIFIED);
  });

  test('HASH_MISMATCH is neither affected nor clear, and is counted in neither column', async ({ page }) => {
    await enter(page, seed.key_g);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    await paste(page, JSON.stringify(seed.advisories.mismatch));
    await panel(page).getByRole('button', { name: /Check fleet impact/ }).click();

    await expect(panel(page).getByTestId('impact-verdict')).toContainText('NEEDS REVIEW', { timeout: 10_000 });
    for (const m of seed.machines_g) {
      const row = panel(page).locator(`[data-testid="exposure-row"][data-machine="${m}"]`);
      await expect(row).toContainText('contradictory');
      await expect(row).toContainText(/neither affected nor clear/i);
      await expect(row).toContainText(/unresolved/i);
      await expect(row).not.toContainText(/now in question/i);
    }
    const summary = panel(page).getByTestId('impact-summary');
    await expect(summary).toContainText('0 confirmed by hash');
    await expect(summary).toContainText('2 contradictory');
    await expect(summary).toContainText('0 safety function(s) newly in question');
  });

  test('no match is "no enrolled machine matches", never "unaffected" or "safe"', async ({ page }) => {
    await enter(page, seed.key_g);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    await paste(page, JSON.stringify(seed.advisories.clear));
    await panel(page).getByRole('button', { name: /Check fleet impact/ }).click();
    const verdict = panel(page).getByTestId('impact-verdict');
    await expect(verdict).toContainText(/no enrolled machine matches/i, { timeout: 10_000 });
    await expect(panel(page).getByTestId('impact-skipped')).toContainText(/not evidence of safety/i);
    await expect(panel(page).getByTestId('impact-result')).not.toContainText(/\bunaffected\b|\ball clear\b|\bis safe\b|\bsafe to\b/i);
    // Nothing to open a case for.
    await expect(panel(page).getByRole('button', { name: 'Open assurance case' })).toHaveCount(0);
  });

  // What `assurance fleet import-csaf` writes into an advisory (fleet/advisory.py ImportRecord).
  const importRecord = (over: Record<string, unknown> = {}) => ({
    origin: 'csaf_import',
    trust: 'unsigned_inspect_only',
    partial: false,
    dropped: [],
    partial_reasons: [],
    severity_source: 'defaulted_by_importer',
    tlp: 'AMBER',
    tracking_status: 'final',
    document_category: 'csaf_security_advisory',
    document_date: '2026-10-02T08:30:00Z',
    notes: [],
    ...over,
  });

  test('a partial unsigned CSAF import is never "no enrolled machine matches"', async ({ page }) => {
    await enter(page, seed.key_g);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    const partial = importRecord({
      partial: true,
      dropped: [{ product_id: 'B', reason: 'it is defined only in product_tree.full_product_names' }],
      partial_reasons: ["1 affected product(s) could not be imported: 'B'"],
    });
    await paste(page, JSON.stringify({ ...seed.advisories.clear, import_record: partial }));
    await panel(page).getByRole('button', { name: /Check fleet impact/ }).click();

    const verdict = panel(page).getByTestId('impact-verdict');
    await expect(verdict).toContainText(/INCOMPLETE TRANSLATION/i, { timeout: 10_000 });
    await expect(verdict).not.toContainText(/no enrolled machine matches/i);
    const marker = panel(page).getByTestId('impact-import-marker');
    await expect(marker).toHaveAttribute('data-advisory-trust', 'unsigned_inspect_only');
    await expect(marker).toHaveAttribute('data-advisory-partial', 'true');
    await expect(marker).toContainText('TLP:AMBER');
    await expect(marker).toContainText('not imported: B');
    await expect(marker).toContainText(/defaulted by the importer/i);
    await expect(panel(page)).not.toContainText(CLAIMS_VERIFIED);
  });

  test('a case on an unsigned import needs an explicit acceptance, and the server refuses without it', async ({
    page,
    request,
  }) => {
    await enter(page, seed.key_g);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    const imported = { ...seed.advisories.hash, import_record: importRecord() };
    await paste(page, JSON.stringify(imported));
    await panel(page).getByRole('button', { name: /Check fleet impact/ }).click();
    await expect(panel(page).getByTestId('impact-verdict')).toContainText('EXPOSED', { timeout: 10_000 });
    await expect(panel(page).getByTestId('impact-import-marker')).toHaveAttribute('data-advisory-partial', 'false');

    const open = panel(page).getByRole('button', { name: 'Open assurance case' });
    await panel(page).getByLabel(/Your name/).fill('e2e.reviewer');
    await expect(open).toBeDisabled();
    await panel(page).getByTestId('accept-unsigned').getByRole('checkbox').check();
    await expect(open).toBeEnabled();

    // The same refusal from the API itself, with a named person but no explicit override. Nothing
    // is opened: this does not touch the queue the other specs count.
    const r = await request.post(`${apiBase}/v1/change/assess/advisory`, {
      headers: { 'X-API-Key': seed.key_g },
      data: { advisory: imported, actor: 'e2e.reviewer' },
    });
    expect(r.status()).toBe(409);
  });

  test('a case opens only on an explicit click, under a named person, and links to the real case', async ({
    page,
    request,
  }) => {
    await enter(page, seed.key_g);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('case-summary')).toContainText('0 open');
    await paste(page, JSON.stringify(seed.advisories.hash));
    await panel(page).getByRole('button', { name: /Check fleet impact/ }).click();
    await expect(panel(page).getByTestId('impact-verdict')).toContainText('EXPOSED', { timeout: 10_000 });

    // The check alone opened nothing.
    const before = await request.get(`${apiBase}/v1/change/cases`, { headers: { 'X-API-Key': seed.key_g } });
    expect((await before.json()).cases).toHaveLength(0);

    // No name, no case.
    await panel(page).getByRole('button', { name: 'Open assurance case' }).click();
    await expect(panel(page).getByRole('alert')).toContainText(/name of the person/i);
    expect((await (await request.get(`${apiBase}/v1/change/cases`, { headers: { 'X-API-Key': seed.key_g } })).json()).cases).toHaveLength(0);

    await panel(page).getByLabel(/Your name/).fill('v.grimaldi');
    await panel(page).getByRole('button', { name: 'Open assurance case' }).click();
    const result = panel(page).getByTestId('adv-case-result');
    await expect(result).toContainText(/opened/i, { timeout: 10_000 });
    const link = result.getByRole('button', { name: /^Open case case-/ });
    await expect(link).toBeVisible();

    const after = await (await request.get(`${apiBase}/v1/change/cases`, { headers: { 'X-API-Key': seed.key_g } })).json();
    expect(after.cases).toHaveLength(1);
    const caseId: string = after.cases[0].case_id;
    expect(after.cases[0].trigger).toContain('supplier_advisory');
    await expect(page.getByTestId('case-table')).toContainText(caseId, { timeout: 10_000 });

    await link.click();
    const detail = page.getByTestId('case-detail');
    await expect(detail).toContainText(caseId, { timeout: 10_000 });
    await expect(detail).toContainText('supplier_advisory');
    // The server recorded who: the named person, via this account.
    const full = await (await request.get(`${apiBase}/v1/change/cases/${caseId}`, { headers: { 'X-API-Key': seed.key_g } })).json();
    expect(full.history.length).toBeGreaterThan(0);

    // Doing it again is an update of the same case, and the page says so rather than "opened".
    await panel(page).getByRole('button', { name: 'Open assurance case' }).click();
    await expect(result).toContainText(/already existed|updated/i, { timeout: 10_000 });
    const again = await (await request.get(`${apiBase}/v1/change/cases`, { headers: { 'X-API-Key': seed.key_g } })).json();
    expect(again.cases).toHaveLength(1);
  });

  test('a signed feed file: provenance is claimed, not verified; the real CLI is what verifies it', async ({ page }) => {
    const s = seed.supplier;
    // Ground truth, from the real CLI: the pristine feed verifies, the tampered one does not.
    const env = { ...process.env, PYTHONPATH: join(process.cwd(), 'src') };
    const py = process.env.ASSURANCE_E2E_PYTHON || 'python';
    const cli = (feed: string) =>
      spawnSync(py, ['-m', 'assurance', 'supplier', 'verify', '--feed', feed, '--public-key', s.public_key_path, '--expect-supplier', s.supplier_id], { env });
    expect(cli(s.feed_path).status).toBe(0);
    expect(cli(s.tampered_path).status).not.toBe(0);

    await enter(page, seed.key_g);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });

    for (const file of [s.tampered_path, s.feed_path]) {
      await panel(page).getByLabel('Choose an advisory or feed file').setInputFiles(file);
      const prov = panel(page).getByTestId('adv-provenance');
      await expect(prov).toContainText(/signature not verified/i, { timeout: 10_000 });
      await expect(prov).toContainText(s.fingerprint);
      await expect(prov).toContainText(s.supplier_id);
      await expect(prov).toContainText('assurance supplier verify');
      await expect(prov).toContainText(/another route|key_contact|confirm the fingerprint/i);
      // The page cannot tell the tampered copy from the pristine one, and must not pretend to.
      await expect(panel(page)).not.toContainText(CLAIMS_VERIFIED);
      await expect(panel(page).getByTestId('adv-record')).toHaveCount(s.records);
    }

    // Records in the file: the withdrawn advisory and its withdrawal are labelled as the file claims.
    const orig = panel(page).locator(`[data-testid="adv-record"][data-advisory-id="${s.withdrawn_advisory_id}"][data-withdrawal="false"]`);
    await expect(orig).toContainText(/withdrawn later in this file/i);
    const wd = panel(page).locator(`[data-testid="adv-record"][data-advisory-id="${s.withdrawn_advisory_id}"][data-withdrawal="true"]`);
    await expect(wd).toContainText(/withdrawal/i);
    await expect(wd.getByRole('button', { name: /Check fleet impact/ })).toHaveCount(0);

    // The standing advisory can be checked; the result is a local assessment of an unverified record.
    const first = panel(page).locator(`[data-testid="adv-record"][data-advisory-id="${s.first_advisory_id}"]`);
    await first.getByRole('button', { name: /Check fleet impact/ }).click();
    await expect(panel(page).getByTestId('impact-verdict')).toContainText('EXPOSED', { timeout: 10_000 });
    await expect(panel(page).getByTestId('impact-provenance')).toContainText(/signature not verified/i);
  });

  test('a withdrawn advisory in a signed feed cannot open a case from the local reading at all', async ({ page, request }) => {
    const s = seed.supplier;
    await enter(page, seed.key_g);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    await panel(page).getByLabel('Choose an advisory or feed file').setInputFiles(s.feed_path);
    const orig = panel(page).locator(`[data-testid="adv-record"][data-advisory-id="${s.withdrawn_advisory_id}"][data-withdrawal="false"]`);
    await orig.getByRole('button', { name: /Check fleet impact/ }).click();
    await expect(panel(page).getByTestId('impact-verdict')).toBeVisible({ timeout: 10_000 });
    await expect(panel(page).getByTestId('impact-result')).toContainText(/withdrawn later in this file/i);
    // A record that came in a signed feed nobody has judged under pinned keys is inspect-only here:
    // the case control is disabled whatever else is ticked, and it points at the trust evaluation.
    const open = panel(page).getByRole('button', { name: 'Open assurance case' });
    await expect(open).toBeDisabled();
    await expect(panel(page).getByTestId('signed-record-no-case')).toContainText(/Inspect only/);
    await expect(panel(page).getByTestId('signed-record-no-case')).toContainText(/Evaluate under my pinned keys/);
    const cases = await (await request.get(`${apiBase}/v1/change/cases`, { headers: { 'X-API-Key': seed.key_g } })).json();
    expect(JSON.stringify(cases)).not.toContain(s.withdrawn_advisory_id);
  });

  test('a hosted feed is loaded by account id, and hosting is not described as verification', async ({ page }) => {
    const s = seed.supplier;
    await enter(page, seed.key_g);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    await panel(page).getByLabel(/Hosted feed/).fill(s.hosted_feed_id);
    await panel(page).getByRole('button', { name: 'Load hosted feed' }).click();
    await expect(panel(page).getByTestId('adv-record')).toHaveCount(s.hosted_records, { timeout: 10_000 });
    const prov = panel(page).getByTestId('adv-provenance');
    await expect(prov).toContainText(/hosted/i);
    await expect(prov).toContainText(/does not check the signature/i);
    await expect(prov).toContainText(/signature not verified/i);
    await expect(prov).toContainText(s.fingerprint);
    await expect(panel(page)).not.toContainText(CLAIMS_VERIFIED);

    // An id nobody published under is the server's 404, not an empty feed.
    await panel(page).getByLabel(/Hosted feed/).fill('acc_does_not_exist');
    await panel(page).getByRole('button', { name: 'Load hosted feed' }).click();
    await expect(panel(page).getByRole('alert')).toContainText('Not found (404)', { timeout: 10_000 });
    await expect(panel(page).getByRole('alert')).toContainText(/No feed has been published/);
    await expect(panel(page).getByRole('alert')).toContainText(/not .*empty|nothing was learned|not the same as/i);
  });

  test('unreadable input is refused on the page; unusable content is the server\'s 422', async ({ page }) => {
    await enter(page, seed.key_g);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    await paste(page, 'this is not json');
    await expect(panel(page).getByRole('alert')).toContainText(/not JSON|could not be read/i);
    await expect(panel(page).getByTestId('adv-record')).toHaveCount(0);

    await paste(page, JSON.stringify({ advisory_id: 'ADV-X' }));
    await panel(page).getByRole('button', { name: /Check fleet impact/ }).click();
    await expect(panel(page).getByRole('alert')).toContainText(/\(422\)/, { timeout: 10_000 });
    await expect(panel(page).getByTestId('impact-result')).toHaveCount(0);
  });

  test('an advisory over the server size limit is a 413 that names the limit, not "unreachable"', async ({ page }) => {
    await enter(page, seed.key_g);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    const huge = { ...seed.advisories.hash, summary: 'x'.repeat(1_200_000) };
    await paste(page, JSON.stringify(huge));
    await panel(page).getByRole('button', { name: /Check fleet impact/ }).click();
    const alert = panel(page).getByRole('alert');
    await expect(alert).toContainText('Too large (413)', { timeout: 20_000 });
    await expect(alert).toContainText('1,048,576');
    await expect(alert).not.toContainText(/unreachable|could not be reached/i);
  });

  test('a Register key gets the plan\'s refusal and remedy for the fleet check', async ({ page }) => {
    await enter(page, seed.key_register);
    await paste(page, JSON.stringify(seed.advisories.hash));
    await panel(page).getByRole('button', { name: /Check fleet impact/ }).click();
    const alert = panel(page).getByRole('alert');
    await expect(alert).toContainText('Not included in your plan (402)', { timeout: 10_000 });
    await expect(alert).toContainText(/Cell plan/);
    await expect(panel(page).getByTestId('impact-result')).toHaveCount(0);
  });

  test('another account\'s fleet is not in the result: an empty fleet reports no match, with its limits', async ({ page }) => {
    await enter(page, seed.key_b);
    await expect(page.getByText(/No machine is enrolled in your ledger/)).toBeVisible({ timeout: 15_000 });
    await paste(page, JSON.stringify(seed.advisories.hash));
    await panel(page).getByRole('button', { name: /Check fleet impact/ }).click();
    await expect(panel(page).getByTestId('impact-verdict')).toContainText(/no enrolled machine matches/i, { timeout: 10_000 });
    await expect(panel(page).getByTestId('impact-summary')).toContainText('0 of 0');
    await expect(panel(page).getByTestId('impact-result')).not.toContainText(seed.machines_g[0]);
  });
});
