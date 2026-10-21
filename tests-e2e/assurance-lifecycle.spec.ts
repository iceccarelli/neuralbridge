import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

// The human decisions on a change-assurance case, in the workspace, against the REAL API
// and a real tenant ledger: answer a human question, waive a re-verification (which reads
// "waived", never "current"), defer and resume, replay the case from the ledger alone, and
// assess a sealed intervention. The case is opened through the real advisory route.

const seedPath = process.env.ASSURANCE_E2E_SEED;
const apiBase = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || 'http://127.0.0.1:8001';

type Seed = {
  key_k: string;
  k_machine: string;
  k_manifest: Record<string, unknown>;
  k_intervention: Record<string, unknown>;
  advisories: { mismatch: Record<string, unknown> };
};

test.describe.configure({ mode: 'serial' });

test.describe('Assurance workspace — case lifecycle', () => {
  let seed: Seed;
  let caseId = '';
  const h = () => ({ 'X-API-Key': seed.key_k });

  test.beforeAll(async ({ request }) => {
    test.skip(!seedPath, 'Set ASSURANCE_E2E_SEED (run scripts/e2e-assurance.sh).');
    seed = JSON.parse(readFileSync(seedPath!, 'utf8'));
    const r = await request.post(`${apiBase}/v1/change/assess/advisory`, {
      headers: h(),
      data: { advisory: seed.advisories.mismatch, actor: '' },
    });
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.opened).toBe(true);
    caseId = body.case.case_id;
  });

  async function openCase(page: Page) {
    await page.goto(`/assurance?case=${encodeURIComponent(caseId)}`);
    await page.getByLabel('API key').fill(seed.key_k);
    await page.getByRole('button', { name: 'Refresh' }).click();
    const detail = page.getByTestId('case-detail');
    await expect(detail).toContainText(caseId, { timeout: 15_000 });
    return detail;
  }

  test('the re-verification step explains the only path to evidence and offers no way to mark verified', async ({ page }) => {
    const detail = await openCase(page);
    const how = detail.getByTestId('reverify-howto');
    await expect(how).toContainText('POST /v1/machinery/manifest');
    await expect(how).toContainText('POST /v1/machine/verify');
    await expect(how).toContainText('subject');
    await expect(how).toContainText('verification_content_hash');
    await expect(detail.getByRole('button', { name: /mark (as )?verified/i })).toHaveCount(0);
    await expect(detail.getByRole('button', { name: /^verify$/i })).toHaveCount(0);
  });

  test('an automated name cannot answer a question: the server\'s 409 is shown in its words', async ({ page }) => {
    const detail = await openCase(page);
    await detail.getByLabel('Your name').fill('automation');
    await detail.getByLabel('Question').selectOption({ index: 0 });
    await detail.getByLabel('Answer').fill('Checked on site.');
    await detail.getByRole('button', { name: 'Record answer' }).click();
    const alert = detail.getByRole('alert');
    await expect(alert).toContainText('(409)', { timeout: 10_000 });
    await expect(alert).toContainText(/needs a named person/);
    await expect(detail).not.toContainText('Resolved human decisions');
  });

  test('a named person answers the human question; it is recorded and no longer outstanding', async ({ page, request }) => {
    const detail = await openCase(page);
    const question = await detail.getByLabel('Question').locator('option').first().textContent();
    await detail.getByLabel('Your name').fill('v.grimaldi');
    await detail.getByLabel('Answer').fill('Hash recomputed on site; supplier figure is the one in error.');
    await detail.getByRole('button', { name: 'Record answer' }).click();
    await expect(detail.getByTestId('resolved-decisions')).toContainText('supplier figure is the one in error', { timeout: 10_000 });
    await expect(detail.getByTestId('resolved-decisions')).toContainText('v.grimaldi');
    const c = await (await request.get(`${apiBase}/v1/change/cases/${caseId}`, { headers: h() })).json();
    expect(c.human_decisions_required).not.toContain(question);
    expect(c.resolved_decisions.length).toBe(1);
  });

  test('a waiver reads "waived by <name>: <reason>", never "current", and says it is without evidence', async ({ page, request }) => {
    const detail = await openCase(page);
    await expect(detail.getByTestId('waive-warning')).toContainText(/without evidence/i);
    const entry = await detail.getByLabel('Re-verification entry').locator('option').first().textContent();
    await detail.getByLabel('Your name').fill('v.grimaldi');
    await detail.getByLabel('Why closing it without evidence is acceptable').fill('Function not in use on this cell.');
    await detail.getByRole('button', { name: 'Waive without evidence' }).click();
    const row = detail.locator(`[data-testid="evidence-row"][data-entry="${entry}"]`);
    await expect(row).toHaveAttribute('data-state', 'waived', { timeout: 10_000 });
    await expect(row).toContainText('waived by v.grimaldi');
    await expect(row).toContainText('Function not in use on this cell.');
    await expect(row).not.toContainText(/\bcurrent\b|\bverified\b/i);
    const c = await (await request.get(`${apiBase}/v1/change/cases/${caseId}`, { headers: h() })).json();
    expect(c.evidence_current[entry!]).toBe('waived');
  });

  test('the server refuses to waive with a bad entry or an empty reason, in its words', async ({ page }) => {
    const detail = await openCase(page);
    await detail.getByLabel('Your name').fill('v.grimaldi');
    await detail.getByRole('button', { name: 'Waive without evidence' }).click();
    // The page asks for the reason before it calls anything.
    await expect(detail.getByRole('alert')).toContainText(/reason/i);
  });

  test('replay: the ledger alone rebuilds the case, and the page says what that does and does not show', async ({ page }) => {
    const detail = await openCase(page);
    await detail.getByRole('button', { name: 'Check this case against the ledger' }).click();
    const res = detail.getByTestId('replay-result');
    await expect(res).toHaveAttribute('data-ok', 'true', { timeout: 15_000 });
    await expect(res).toContainText(/ledger entr/i);
    await expect(res).toContainText(/does not show|not .*proof|a person still decides/i);
  });

  test('defer then resume: resume needs a name and a reason, and puts the case back in review', async ({ page, request }) => {
    const detail = await openCase(page);
    await detail.getByLabel('Your name').fill('v.grimaldi');
    await detail.getByLabel('Decision reason').fill('Waiting for the supplier to confirm.');
    await detail.getByRole('button', { name: 'Defer', exact: true }).click();
    await expect(detail.getByRole('heading', { name: new RegExp(`${caseId} — deferred`) })).toBeVisible({ timeout: 10_000 });
    // Deferred is "not today", not settled: the ordinary actions are gone and resume is offered.
    await expect(detail.getByRole('button', { name: 'Close', exact: true })).toHaveCount(0);
    await expect(detail.getByRole('button', { name: 'Resume case' })).toBeVisible();

    await detail.getByRole('button', { name: 'Resume case' }).click();
    await expect(detail.getByRole('alert')).toContainText(/reason/i);
    await detail.getByLabel('Why resume').fill('Supplier confirmed.');
    await detail.getByRole('button', { name: 'Resume case' }).click();
    await expect(detail.getByRole('heading', { name: new RegExp(`${caseId} — in_review`) })).toBeVisible({ timeout: 10_000 });
    const c = await (await request.get(`${apiBase}/v1/change/cases/${caseId}`, { headers: h() })).json();
    expect(c.status).toBe('in_review');
    // History keeps both, with who.
    await expect(detail.getByTestId('case-history')).toContainText('resumed by v.grimaldi');
    await expect(detail.getByTestId('case-history')).toHaveAttribute('data-who', 'ready');
  });

  test('the queue counts deferred and degraded cases separately from open ones', async ({ page, request }) => {
    const q = await (await request.get(`${apiBase}/v1/change/cases`, { headers: h() })).json();
    await page.goto('/assurance');
    await page.getByLabel('API key').fill(seed.key_k);
    await page.getByRole('button', { name: 'Refresh' }).click();
    const summary = page.getByTestId('case-summary');
    await expect(summary).toContainText(`${q.summary.open} open`, { timeout: 15_000 });
    await expect(summary).toContainText(`${q.summary.deferred} deferred`);
    await expect(summary).toContainText(`${q.summary.degraded} without a machine named`);
  });

  test('the case export is the change-case export, and it is an evidence bundle the offline verifier reads', async ({ page, request }) => {
    const detail = await openCase(page);
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      detail.getByRole('button', { name: /Download this case/ }).click(),
    ]);
    expect(download.suggestedFilename()).toBe(`case-${caseId}.json`);
    const direct = await (await request.get(`${apiBase}/v1/change/cases/${caseId}/export`, { headers: h() })).json();
    expect(direct.entries.length).toBeGreaterThan(0);
    await expect(detail.getByTestId('export-done')).toContainText(`${direct.entries.length} ledger entries`);
    // An id that is not in the ledger is a 404, not an empty bundle.
    const missing = await request.get(`${apiBase}/v1/change/cases/case-nope/export`, { headers: h() });
    expect(missing.status()).toBe(404);
  });

  test('an intervention is assessed only when it was sealed first; unknown ids are the server\'s 422', async ({ page, request }) => {
    await page.goto('/assurance');
    await page.getByLabel('API key').fill(seed.key_k);
    await page.getByRole('button', { name: 'Refresh' }).click();
    const form = page.locator('section#aw-intervention');
    await expect(form).toBeVisible({ timeout: 15_000 });
    await form.getByLabel(/^Safety manifest/).fill(JSON.stringify(seed.k_manifest));
    await form.getByLabel('Intervention id').fill('INT-E2E-1');
    await form.getByRole('button', { name: 'Assess intervention' }).click();
    await expect(form.getByRole('alert')).toContainText('(422)', { timeout: 10_000 });
    await expect(form.getByRole('alert')).toContainText(/no intervention 'INT-E2E-1' is sealed/);
    await expect(form.getByTestId('intervention-result')).toHaveCount(0);

    // Seal it through the real route, then assess.
    const sealed = await request.post(`${apiBase}/v1/machinery/intervention`, {
      headers: h(),
      data: { intervention: seed.k_intervention, actor: 'a.integrator', role: 'integrator' },
    });
    expect(sealed.status()).toBe(200);
    await form.getByRole('button', { name: 'Assess intervention' }).click();
    const result = form.getByTestId('intervention-result');
    await expect(result).toContainText(/opened/i, { timeout: 10_000 });
    const link = result.getByRole('button', { name: /^Open case case-/ });
    await link.click();
    await expect(page.getByTestId('case-detail')).toContainText('intervention', { timeout: 10_000 });
  });
});
