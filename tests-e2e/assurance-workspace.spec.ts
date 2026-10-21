import { test, expect, type Page } from '@playwright/test';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// /assurance workspace against the REAL local Assurance API and real,
// per-account ledgers seeded by scripts/e2e_seed_assurance.py (real engines:
// Watch -> compare -> assess_drift -> ChangeAssuranceCase). Nothing in the
// assurance API is mocked. Run via scripts/e2e-assurance.sh, which starts the
// API, seeds it, starts Next with NEXT_PUBLIC_ASSURANCE_API_URL and sets
// ASSURANCE_E2E_SEED to the seed JSON.

const seedPath = process.env.ASSURANCE_E2E_SEED;
const apiBase = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || 'http://127.0.0.1:8001';

type Seed = {
  key_a: string;
  key_b: string;
  key_new: string;
  key_register: string;
  key_d: string;
  key_e: string;
  key_g: string;
  key_past_due: string;
  case_id: string;
  machines: string[];
  d_machine: string;
  // Account E: its fleet exists only because the real `assurance watch push` reported it.
  machines_e: { ok: string; blind_stale: string; blind_fresh: string };
  case_e: string;
};

test.describe.configure({ mode: 'serial' });

test.describe('Assurance workspace', () => {
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

  test('shows the account\'s own fleet and the case the watch opened', async ({ page }) => {
    await enter(page, seed.key_a);
    const fleet = page.getByTestId('fleet-table');
    await expect(fleet).toBeVisible({ timeout: 15_000 });
    for (const m of seed.machines) await expect(fleet).toContainText(m);
    await expect(page.getByTestId('fleet-summary')).toContainText('2 machine(s)');
    await expect(page.getByTestId('chain-broken')).toHaveCount(0);

    const cases = page.getByTestId('case-table');
    await expect(cases).toContainText(seed.case_id);
    await expect(cases).toContainText('SF-01');
    await expect(page.getByTestId('case-summary')).toContainText('1 open');
    // The honest limitation is on the page, not buried in docs — and says what is true now:
    // Watch still runs in the customer's kit, the columns show what the customer reports.
    await expect(page.getByText(/does not run Watch/i)).toBeVisible();
    await expect(page.getByText(/what you chose to report with/i)).toBeVisible();
    await expect(fleet).toContainText('Last successful observation');
    await expect(fleet).toContainText('Last attempt');
    await expect(fleet).toContainText('Stale?');
    await expect(fleet).toContainText('Last sealed manifest');
  });

  function row(page: Page, machine: string) {
    return page.getByTestId('fleet-row').filter({ has: page.getByText(machine, { exact: true }) });
  }

  test('a fleet reported through the real watch push shows last success, last attempt and stale per machine', async ({
    page,
  }) => {
    await enter(page, seed.key_e);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('fleet-summary')).toContainText('3 machine(s)');
    await expect(page.getByTestId('obs-none')).toHaveCount(0);

    // 7001 was observed in the latest run: a success, within its cadence.
    const ok = row(page, seed.machines_e.ok);
    await expect(ok.getByTestId('obs-last-success')).toContainText(/ago|today/);
    await expect(ok.getByTestId('obs-last-success')).not.toContainText('No Watch report');
    await expect(ok.getByTestId('obs-last-attempt')).not.toContainText('FAILED');
    await expect(ok.getByTestId('obs-stale')).toContainText('No');
    await expect(ok.getByTestId('obs-stale')).not.toContainText('Stale');

    // 7002 could not be collected and was last seen ten days ago: failed, and stale. Never current.
    const blind = row(page, seed.machines_e.blind_stale);
    await expect(blind.getByTestId('obs-last-attempt')).toContainText('FAILED');
    await expect(blind.getByTestId('obs-last-attempt')).toContainText('uncollectable');
    await expect(blind.getByTestId('obs-last-attempt')).toContainText('not shown as current');
    await expect(blind.getByTestId('obs-last-success')).toContainText('10 days ago');
    await expect(blind.getByTestId('obs-stale')).toContainText('Stale');
    await expect(blind.getByTestId('obs-stale')).toContainText('older than the declared cadence');
    await expect(blind).not.toContainText(/unchanged/i);

    // 7003 failed its latest look but was seen two days ago: shown as failed, not yet stale.
    const fresh = row(page, seed.machines_e.blind_fresh);
    await expect(fresh.getByTestId('obs-last-attempt')).toContainText('FAILED');
    await expect(fresh.getByTestId('obs-last-success')).toContainText('2 days ago');
    await expect(fresh.getByTestId('obs-stale')).toContainText('No');

    await expect(page.getByTestId('obs-summary')).toContainText('1 stale');
    await expect(page.getByTestId('obs-summary')).toContainText('2 whose latest attempt failed');
    await expect(page.getByTestId('obs-summary')).toContainText('not independently observed');

    // The drift the push carried opened exactly one case, through the same assess_drift.
    await expect(page.getByTestId('case-table')).toContainText(seed.case_e);
    await expect(page.getByTestId('case-summary')).toContainText('1 open');
    await expect(page.getByTestId('case-table')).toContainText(seed.machines_e.ok);
  });

  test('an account that never reported sees "No Watch report received", not a quiet fleet', async ({ page }) => {
    await enter(page, seed.key_d);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    const only = row(page, seed.d_machine);
    await expect(only.getByTestId('obs-last-success')).toContainText('No Watch report received');
    await expect(only.getByTestId('obs-last-success')).toContainText('assurance watch push');
    await expect(only.getByTestId('obs-last-attempt')).toContainText('—');
    await expect(only.getByTestId('obs-stale')).toContainText('Stale');
    await expect(only.getByTestId('obs-stale')).toContainText('never reported');
    await expect(page.getByTestId('obs-none')).toContainText('No Watch report received');
  });

  test('observations are tenant-scoped and gated: 401 with no key, 402 on Register, nothing for B', async ({
    request,
  }) => {
    expect((await request.get(`${apiBase}/v1/fleet/observations`)).status()).toBe(401);
    expect(
      (await request.get(`${apiBase}/v1/fleet/observations`, { headers: { 'X-API-Key': seed.key_register } })).status(),
    ).toBe(402);
    const b = await request.get(`${apiBase}/v1/fleet/observations`, { headers: { 'X-API-Key': seed.key_b } });
    expect(b.status()).toBe(200);
    expect((await b.json()).machines).toHaveLength(0);
    const e = await (
      await request.get(`${apiBase}/v1/fleet/observations`, { headers: { 'X-API-Key': seed.key_e } })
    ).json();
    expect(e.machines.map((m: { machine: string }) => m.machine).sort()).toEqual(
      [seed.machines_e.ok, seed.machines_e.blind_stale, seed.machines_e.blind_fresh].sort(),
    );
    const failed = e.machines.find((m: { machine: string }) => m.machine === seed.machines_e.blind_stale);
    expect(failed.last_attempt_status).toBe('uncollectable');
    expect(failed.last_attempt_succeeded).toBe(false);
    expect(failed.stale).toBe(true);
    // A cannot see E's machines in its own observations, and E's report is not in A's fleet.
    const a = await (
      await request.get(`${apiBase}/v1/fleet/observations`, { headers: { 'X-API-Key': seed.key_a } })
    ).json();
    expect(JSON.stringify(a)).not.toContain('#7001');
  });

  test('case detail shows source evidence, limits and history; the server refuses an early close', async ({ page }) => {
    await enter(page, seed.key_a);
    await page.getByRole('button', { name: seed.case_id }).click();
    const detail = page.getByTestId('case-detail');
    await expect(detail).toContainText('Safety functions and evidence', { timeout: 15_000 });
    await expect(detail).toContainText('What this does not establish');
    await expect(page.getByTestId('case-history').locator('li').first()).toBeVisible();

    await detail.getByLabel('Your name').fill('v.grimaldi');
    await detail.getByLabel('Decision reason').fill('Looks fine to me');
    await detail.getByRole('button', { name: 'Close', exact: true }).click();
    // The API, not the page, decides: closing before re-verification is a 409.
    await expect(detail.getByRole('alert')).toBeVisible({ timeout: 10_000 });
    await expect(detail).toContainText(/open|in_review/);
    await expect(detail).not.toContainText(/Decision: closed/);
  });

  test('claiming records the named person on the server', async ({ page }) => {
    await enter(page, seed.key_a);
    await page.getByRole('button', { name: seed.case_id }).click();
    const detail = page.getByTestId('case-detail');
    await detail.getByLabel('Your name').fill('v.grimaldi');
    await detail.getByLabel('Owner').fill('v.grimaldi');
    await detail.getByRole('button', { name: 'Claim' }).click();
    await expect(page.getByTestId('case-table')).toContainText('in_review', { timeout: 10_000 });
    await expect(page.getByTestId('case-history')).toContainText('v.grimaldi');
  });

  test('the downloaded export verifies offline, and a tampered copy does not', async ({ page }) => {
    await enter(page, seed.key_a);
    await page.getByRole('button', { name: seed.case_id }).click();
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('button', { name: /Download this case/ }).click(),
    ]);
    const dir = mkdtempSync(join(tmpdir(), 'nb-export-'));
    const good = join(dir, 'case.json');
    await download.saveAs(good);
    await expect(page.getByTestId('export-done')).toContainText('python -m assurance evidence verify');

    const py = process.env.ASSURANCE_E2E_PYTHON || 'python';
    const env = { ...process.env, PYTHONPATH: join(process.cwd(), 'src') };
    expect(execFileSync(py, ['-m', 'assurance', 'evidence', 'verify', good], { env }).toString()).toContain('VERIFIED');

    const bundle = JSON.parse(readFileSync(good, 'utf8'));
    bundle.entries[0].evidence.body = { ...bundle.entries[0].evidence.body, tampered: true };
    const bad = join(dir, 'tampered.json');
    writeFileSync(bad, JSON.stringify(bundle));
    const res = spawnSync(py, ['-m', 'assurance', 'evidence', 'verify', bad], { env });
    expect(res.status).toBe(1);
    expect(res.stdout.toString()).toContain('DOES NOT VERIFY');
  });

  test('another account sees an empty workspace and cannot read the case by id', async ({ page, request }) => {
    await enter(page, seed.key_b);
    await expect(page.getByText(/No machine is enrolled in your ledger/)).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText(/No cases\./)).toBeVisible();
    await expect(page.getByText(seed.case_id)).toHaveCount(0);

    // Direct API attempts with account B's key: read, export, mutate.
    const h = { 'X-API-Key': seed.key_b };
    expect((await request.get(`${apiBase}/v1/change/cases/${seed.case_id}`, { headers: h })).status()).toBe(404);
    const exp = await request.get(`${apiBase}/v1/cases/${seed.case_id}/export`, { headers: h });
    const expBody = await exp.json();
    expect(expBody.entries ?? []).toHaveLength(0);
    const claim = await request.post(`${apiBase}/v1/change/cases/${seed.case_id}/claim`, {
      headers: h, data: { owner: 'attacker', actor: 'attacker' },
    });
    expect([404, 409]).toContain(claim.status());
  });

  test('a brand-new account with no ledger yet loads cleanly (its first requests create the ledger)', async ({ page }) => {
    await enter(page, seed.key_new);
    await expect(page.getByText(/No machine is enrolled in your ledger/)).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText(/No cases\./)).toBeVisible();
    // No refusal or server-error banner of this page's own (Next.js injects an
    // unrelated role=alert route announcer, so match the page's banner class).
    await expect(page.locator('p.playground-error')).toHaveCount(0);
  });

  test('a Register-plan key gets the plan\'s real refusal, not a view', async ({ page }) => {
    await enter(page, seed.key_register);
    await expect(page.getByRole('alert').first()).toContainText(/does not include|plan/i, { timeout: 15_000 });
    await expect(page.getByTestId('fleet-table')).toHaveCount(0);
  });

  test('a wrong key is refused, not rendered as an empty fleet', async ({ page }) => {
    await enter(page, 'asr_not_a_real_key');
    await expect(page.getByRole('alert').first()).toContainText(/key/i, { timeout: 15_000 });
    await expect(page.getByTestId('fleet-table')).toHaveCount(0);
  });

  // ------------------------------------------------------------------------------------
  // Honest states
  // ------------------------------------------------------------------------------------

  test('every refusal names which one it is and passes the server\'s remedy through', async ({ page }) => {
    await enter(page, 'asr_not_a_real_key');
    const fleet = page.locator('section#aw-fleet');
    await expect(fleet.getByRole('alert')).toContainText('Not signed in (401)', { timeout: 15_000 });
    await expect(fleet.getByRole('alert')).toContainText(/valid key/i);
    // The plan panel is a different request: it is refused on its own terms, the page is not blanked.
    await expect(page.locator('section#aw-plan').getByRole('alert')).toContainText('Not signed in (401)');

    await page.getByLabel('API key').fill(seed.key_register);
    await page.getByRole('button', { name: 'Refresh' }).click();
    const alert = fleet.getByRole('alert');
    await expect(alert).toContainText('Not included in your plan (402)', { timeout: 15_000 });
    await expect(alert).toContainText(/register/i);
    // The server's own remedy text, not a paraphrase.
    await expect(alert).toContainText('Machine safety verification is included from the Cell plan upward');
    await expect(page.locator('section#aw-cases').getByRole('alert')).toContainText('(402)');
  });

  test('one panel failing does not blank the others, and a failed panel is never an empty one', async ({ page }) => {
    // Cut the network for ONE real request. Everything else is the real API.
    await page.route('**/v1/fleet/observations', (route) => route.abort('connectionrefused'));
    await enter(page, seed.key_a);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('case-table')).toContainText(seed.case_id);
    await expect(page.getByTestId('obs-unavailable').first()).toContainText('unavailable');
    await expect(page.locator('section#aw-fleet').getByRole('alert')).toContainText('API unreachable');
    await expect(page.locator('section#aw-fleet').getByRole('alert')).toContainText(/not an empty result|nothing was learned/i);
    // The plan panel still shows the plan.
    await expect(page.locator('section#aw-plan').getByTestId('plan-name')).toBeVisible();

    // Cases failing at the network level while the fleet loads: the fleet is still there.
    await page.unroute('**/v1/fleet/observations');
    await page.route('**/v1/change/cases', (route) => route.abort('connectionrefused'));
    await page.getByRole('button', { name: 'Refresh' }).click();
    await expect(page.locator('section#aw-cases').getByRole('alert')).toContainText('API unreachable', { timeout: 15_000 });
    await expect(page.getByTestId('fleet-table')).toBeVisible();
    await expect(page.getByTestId('case-table')).toHaveCount(0);
    await expect(page.locator('section#aw-cases')).not.toContainText('No cases.');
  });

  test('a loading panel is a skeleton, never an empty-state sentence', async ({ page }) => {
    // Real responses, held back for a moment: the empty fleet of account B must not flash
    // "No machine is enrolled" while it is still being fetched.
    await page.route('**/v1/fleet/machines', async (route) => {
      await new Promise((r) => setTimeout(r, 1500));
      await route.continue();
    });
    await enter(page, seed.key_b);
    const fleet = page.locator('section#aw-fleet');
    await expect(fleet.getByTestId('panel-skeleton')).toBeVisible();
    await expect(fleet.getByTestId('panel-skeleton')).toHaveAttribute('aria-busy', 'true');
    await expect(fleet).not.toContainText('No machine is enrolled');
    await expect(fleet).not.toContainText('0 machine(s)');
    await expect(fleet).toContainText('No machine is enrolled', { timeout: 15_000 });
    await expect(fleet.getByTestId('panel-skeleton')).toHaveCount(0);
  });

  test('data says when it was received, and says it may be out of date once it has aged', async ({ page }) => {
    await page.clock.install();
    await enter(page, seed.key_a);
    await page.clock.runFor(1000);
    const fleet = page.locator('section#aw-fleet');
    await expect(fleet.getByTestId('panel-asof')).toContainText(/as of \d{1,2}:\d{2}/i, { timeout: 15_000 });
    await expect(fleet.getByTestId('panel-asof')).toHaveAttribute('data-stale', 'false');
    await page.clock.fastForward('10:00');
    await expect(fleet.getByTestId('panel-asof')).toHaveAttribute('data-stale', 'true');
    await expect(fleet.getByTestId('panel-asof')).toContainText(/may be out of date/i);
    // Reload makes it fresh again.
    await fleet.getByRole('button', { name: 'Reload' }).click();
    await page.clock.runFor(1000);
    await expect(fleet.getByTestId('panel-asof')).toHaveAttribute('data-stale', 'false', { timeout: 15_000 });
  });

  test('a stale panel keeps its last data only after a transport failure, and labels it', async ({ page }) => {
    await enter(page, seed.key_a);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    await page.route('**/v1/fleet/machines', (route) => route.abort('connectionrefused'));
    await page.locator('section#aw-fleet').getByRole('button', { name: 'Reload' }).click();
    const fleet = page.locator('section#aw-fleet');
    await expect(fleet.getByRole('alert')).toContainText('API unreachable', { timeout: 10_000 });
    await expect(fleet.getByTestId('fleet-table')).toBeVisible();
    await expect(fleet).toContainText(/last data received/i);

    // An authorisation failure must NOT leave the previous data on screen.
    await page.unroute('**/v1/fleet/machines');
    await page.getByLabel('API key').fill('asr_not_a_real_key');
    await page.getByRole('button', { name: 'Refresh' }).click();
    await expect(fleet.getByRole('alert')).toContainText('(401)', { timeout: 10_000 });
    await expect(fleet.getByTestId('fleet-table')).toHaveCount(0);
  });

  test('a case id that is not in your ledger is a 404, and offers no export', async ({ page }) => {
    await page.goto(`/assurance?case=${encodeURIComponent(seed.case_id)}`);
    await page.getByLabel('API key').fill(seed.key_b);
    await page.getByRole('button', { name: 'Refresh' }).click();
    const detail = page.locator('section#aw-case');
    await expect(detail.getByRole('alert')).toContainText('Not found (404)', { timeout: 15_000 });
    await expect(detail.getByRole('alert')).toContainText(/another account.*does not exist|only your own ledger/i);
    await expect(page.getByRole('button', { name: /Download this case/ })).toHaveCount(0);
  });

  // ------------------------------------------------------------------------------------
  // Plan and usage
  // ------------------------------------------------------------------------------------

  test('the plan panel is what GET /v1/me says: plan, what it includes, usage today and key prefixes', async ({
    page,
    request,
  }) => {
    const me = await (await request.get(`${apiBase}/v1/me`, { headers: { 'X-API-Key': seed.key_g } })).json();
    await enter(page, seed.key_g);
    const plan = page.locator('section#aw-plan');
    await expect(plan.getByTestId('plan-name')).toContainText(me.plan.name, { timeout: 15_000 });
    await expect(plan.getByTestId('plan-tier')).toContainText(me.tier);
    await expect(plan.getByTestId('plan-status')).toContainText(me.account.status);
    for (const line of me.plan.includes) await expect(plan.getByTestId('plan-includes')).toContainText(line.slice(0, 40));
    await expect(plan.getByTestId('plan-usage')).toBeVisible();
    await expect(plan.getByTestId('plan-keys')).toContainText(me.keys[0].prefix);
    // A key is never printed back: only its prefix.
    await expect(page.locator('body')).not.toContainText(seed.key_g);
    await expect(plan.getByTestId('plan-warning')).toHaveCount(0);
  });

  test('a past-due account is told so, in the server\'s words, and keeps its views', async ({ page, request }) => {
    const me = await (await request.get(`${apiBase}/v1/me`, { headers: { 'X-API-Key': seed.key_past_due } })).json();
    expect(me.warning).toBeTruthy();
    await enter(page, seed.key_past_due);
    const plan = page.locator('section#aw-plan');
    await expect(plan.getByTestId('plan-warning')).toContainText(me.warning.slice(0, 50), { timeout: 15_000 });
    await expect(plan.getByTestId('plan-status')).toContainText('past_due');
    await expect(page.getByTestId('fleet-table').or(page.getByText(/No machine is enrolled/))).toBeVisible();
  });

  test('a Register plan shows its own plan and usage while the Cell views are refused', async ({ page }) => {
    await enter(page, seed.key_register);
    const plan = page.locator('section#aw-plan');
    await expect(plan.getByTestId('plan-tier')).toContainText('register', { timeout: 15_000 });
    await expect(page.locator('section#aw-fleet').getByRole('alert')).toContainText('(402)');
  });

  // ------------------------------------------------------------------------------------
  // Case detail: who and when
  // ------------------------------------------------------------------------------------

  test('every history item says when and who, and the requirement lists are there', async ({ page }) => {
    await enter(page, seed.key_a);
    await page.getByRole('button', { name: seed.case_id }).click();
    const detail = page.getByTestId('case-detail');
    await expect(detail.getByTestId('required-reverifications')).toBeVisible({ timeout: 15_000 });
    const rows = detail.getByTestId('history-row');
    await expect(rows.first()).toBeVisible({ timeout: 15_000 });
    const n = await rows.count();
    expect(n).toBeGreaterThan(1);
    for (let i = 0; i < n; i++) {
      await expect(rows.nth(i).getByTestId('history-when')).toContainText(/\d{4}-\d{2}-\d{2}/);
      await expect(rows.nth(i).getByTestId('history-who')).not.toBeEmpty();
      await expect(rows.nth(i).getByTestId('history-who')).not.toContainText(/unknown|—/);
    }
    // The claim an earlier test made as v.grimaldi is attributed to that person, not to the account.
    await expect(detail.getByTestId('case-history')).toContainText('v.grimaldi');
    await expect(detail.getByTestId('history-row').filter({ hasText: 'claimed by v.grimaldi' }).getByTestId('history-who')).toContainText('v.grimaldi');
  });

  test('the export can be sent to the verifier page, which is a link, not a claim', async ({ page }) => {
    await enter(page, seed.key_a);
    await page.getByRole('button', { name: seed.case_id }).click();
    const link = page.getByTestId('case-detail').getByRole('link', { name: 'Verify this export' });
    await expect(link).toBeVisible({ timeout: 15_000 });
    await expect(link).toHaveAttribute('href', '/verify');
    await expect(page.getByTestId('case-detail')).toContainText(/not .*proof|does not show .*ledger as held|internally consistent/i);
  });
});
