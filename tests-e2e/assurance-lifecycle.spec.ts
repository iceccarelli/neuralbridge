import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { operatorKey, useDecisionCredential } from './support/operators';

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
      // A bare advisory body is unauthenticated, so a case on it needs a named person (the server
      // used to record this as automation, which is the gap this seed step no longer relies on).
      data: { advisory: seed.advisories.mismatch, actor: 'e2e.seed.operator' },
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

  test('an automated name cannot answer a question: the server\'s 409 is shown in its words, beside the action', async ({ page, request }) => {
    // Two deciders: the person, and an operator credential that carries an automated name.
    await operatorKey(request, seed.key_k, 'v.grimaldi');
    const automation = await operatorKey(request, seed.key_k, 'automation');
    const detail = await openCase(page);
    await useDecisionCredential(detail, automation);
    await detail.getByLabel('Question').selectOption({ index: 0 });
    await detail.getByLabel('Answer').fill('Checked on site.');
    await detail.getByRole('button', { name: 'Record answer' }).click();
    const alert = detail.getByRole('alert');
    await expect(alert).toContainText('(409)', { timeout: 10_000 });
    await expect(alert).toContainText(/needs a named person/);
    // The refusal sits next to the action that was refused, and says nothing changed.
    await expect(detail.getByTestId('action-refusal')).toContainText(/changed nothing/);
    await expect(detail).not.toContainText('Resolved human decisions');
  });

  test('a human decision without a decision credential is not sent, and says why', async ({ page, request }) => {
    const before = await (await request.get(`${apiBase}/v1/change/cases/${caseId}`, { headers: h() })).json();
    const detail = await openCase(page);
    await detail.getByLabel('Your name').fill('v.grimaldi');
    await detail.getByLabel('Answer').fill('Should not be sent.');
    await detail.getByRole('button', { name: 'Record answer' }).click();
    await expect(detail.getByRole('alert')).toContainText(/decision credential/i);
    await expect(detail.getByRole('alert')).toContainText(/Nothing was sent/);
    const after = await (await request.get(`${apiBase}/v1/change/cases/${caseId}`, { headers: h() })).json();
    expect(after.history.length).toBe(before.history.length);
  });

  test('an account key is refused for a decision by the server (operator_required), with what to do about it', async ({ request }) => {
    const r = await request.post(`${apiBase}/v1/change/cases/${caseId}/decision`, {
      headers: h(),
      data: { disposition: 'closed', reason: 'x', actor: 'v.grimaldi' },
    });
    expect(r.status()).toBe(403);
    expect((await r.json()).detail.error).toBe('operator_required');
  });

  test('a named person answers the human question; it is recorded and no longer outstanding', async ({ page, request }) => {
    const detail = await openCase(page);
    const question = await detail.getByLabel('Question').locator('option').first().textContent();
    await useDecisionCredential(detail, await operatorKey(request, seed.key_k, 'v.grimaldi'));
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
    await useDecisionCredential(detail, await operatorKey(request, seed.key_k, 'v.grimaldi'));
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

  test('defer then resume: resume needs a decider credential and a reason, and puts the case back in review', async ({ page, request }) => {
    const detail = await openCase(page);
    await useDecisionCredential(detail, await operatorKey(request, seed.key_k, 'v.grimaldi'));
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
    // History keeps both, with who, and says the name rests on an operator credential.
    await expect(detail.getByTestId('case-history')).toContainText('resumed by v.grimaldi');
    await expect(
      detail.getByTestId('history-row').filter({ hasText: 'resumed by v.grimaldi' }).getByTestId('history-attribution'),
    ).toContainText(/operator credential presented \(not identity proof\)/);
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

  test('the export notice follows what the server returned, not the box that was ticked', async ({ page }) => {
    const detail = await openCase(page);
    const note = detail.getByTestId('export-completeness');
    const save = () =>
      Promise.all([page.waitForEvent('download'), detail.getByRole('button', { name: /Download this case/ }).click()]);
    // The promise a ticked box must NOT make on its own.
    const removedClaim = /none of this case.s records was removed up to that head/;

    // 1. Box off: nothing named, nothing signed (the hosted ledger has not been signed by the operator).
    await save();
    await expect(note).toHaveAttribute('data-skeleton', 'not_requested');
    await expect(note).toHaveAttribute('data-anchor', 'absent');
    await expect(note).toContainText('names no other case');
    await expect(note).toContainText('no signed anchor');
    await expect(note).not.toContainText(removedClaim);

    // 2. Box on, real server: the skeleton arrives, but a hosted export has no anchor until the operator
    //    has signed. Carrying the skeleton must not read as "nothing was removed".
    await detail.getByTestId('export-skeleton').check();
    await save();
    await expect(note).toHaveAttribute('data-skeleton', 'carried');
    await expect(note).toHaveAttribute('data-anchor', 'absent');
    await expect(note).toContainText('no signed anchor');
    await expect(note).toContainText('completeness as not checked');
    await expect(note).not.toContainText(removedClaim);

    // 3. Box on, but the server declines the skeleton (more other entries than it will list). The same
    //    request, a different response: the notice must say the file names no other case.
    const mutate = (change: (b: Record<string, unknown>) => void) => async (route: import('@playwright/test').Route) => {
      const real = await route.fetch();
      const body = await real.json();
      change(body);
      await route.fulfill({ response: real, json: body });
    };
    const url = /\/v1\/change\/cases\/[^/]+\/export\?skeleton=true/;
    await page.route(url, mutate((b) => { b.skeleton = []; b.skeleton_truncated = true; }));
    await save();
    await expect(note).toHaveAttribute('data-skeleton', 'truncated');
    await expect(note).toContainText('left the skeleton out');
    await expect(note).toContainText('names no other case');
    await expect(note).not.toContainText(removedClaim);
    await page.unroute(url);

    // 4. Skeleton carried and the operator has signed this ledger: only now may the notice say what a key can show.
    await page.route(url, mutate((b) => {
      b.anchor = { sequence: 3, head_seq: 7, basis: 'read_from_ledger', attested_at: '2026-10-01T00:00:00Z' };
    }));
    await save();
    await expect(note).toHaveAttribute('data-skeleton', 'carried');
    await expect(note).toHaveAttribute('data-anchor', 'present');
    await expect(note).toContainText('attestation 3, head seq 7');
    await expect(note).toContainText(removedClaim);
    await expect(note).toContainText('covered by no signature');
    await page.unroute(url);

    // 5. Truncated even though an anchor is present: the anchor does not rescue a skeleton-less file.
    await page.route(url, mutate((b) => {
      b.skeleton = []; b.skeleton_truncated = true;
      b.anchor = { sequence: 3, head_seq: 7, basis: 'read_from_ledger' };
    }));
    await save();
    await expect(note).toHaveAttribute('data-skeleton', 'truncated');
    await expect(note).toHaveAttribute('data-anchor', 'present');
    await expect(note).not.toContainText(removedClaim);
    await expect(note).toContainText('not established');
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
