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

type Seed = { key_a: string; key_b: string; key_register: string; case_id: string; machines: string[] };

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
    // The honest limitation is on the page, not buried in docs.
    await expect(page.getByText(/does not run Watch/i)).toBeVisible();
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
});
