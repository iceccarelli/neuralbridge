import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { operatorKey } from './support/operators';

// Supplier trust, impact classification, fleet record sources and the decision credential in the
// /assurance workspace, against the REAL local API and real tenant ledgers
// (scripts/e2e_seed_assurance.py). The one stubbed route is labelled where it is used.
//
// What this pins, because it is where a UI could most easily overclaim:
//   * a feed is never shown with one "verified" badge: readable, signature, key trust, chain,
//     duplicates/conflicts and withdrawals are separate answers;
//   * an untrusted feed is "inspect only", and the control that opens a case from it is disabled
//     unless the SERVER says automated consequences are permitted;
//   * a key inside a feed is not proof: pinning needs how the key was obtained, independently;
//   * an override is attributed (who, why) and is not trust in the feed;
//   * unknown and contradictory machines never look like "no match".

const seedPath = process.env.ASSURANCE_E2E_SEED;
const apiBase = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || 'http://127.0.0.1:8001';

type Seed = {
  key_g: string;
  key_a: string;
  key_e: string;
  key_d: string;
  case_id: string;
  machines_g: string[];
  machines_e: { ok: string; blind_stale: string; blind_fresh: string };
  d_machine: string;
  advisories: { hash: Record<string, unknown>; mismatch: Record<string, unknown>; clear: Record<string, unknown> };
  supplier: {
    feed_path: string;
    tampered_path: string;
    public_key_path: string;
    fingerprint: string;
    supplier_id: string;
    first_advisory_id: string;
    withdrawn_advisory_id: string;
  };
};

// Nothing on the trust views may say a feed "was verified" or is "authentic".
const CLAIMS_VERIFIED = /(?<!not )(?<!un)(?<!cannot be )verified(?! here)|signature (is )?valid\b|(?<!not )(?<!un)authentic/i;
// The statement is the server's (supplier/trust.py TRUST_STATEMENT); the page must show it verbatim.
const STATEMENT_GIST = /proves who signed these bytes\. It does not prove that the advisory is correct, complete or timely/;

test.describe.configure({ mode: 'serial' });

test.describe('Assurance workspace — supplier trust, classification, record sources, decision credential', () => {
  let seed: Seed;
  let pem = '';
  test.beforeAll(() => {
    test.skip(!seedPath, 'Set ASSURANCE_E2E_SEED (run scripts/e2e-assurance.sh) — not faking a fleet.');
    seed = JSON.parse(readFileSync(seedPath!, 'utf8'));
    pem = readFileSync(seed.supplier.public_key_path, 'utf8');
  });

  async function enter(page: Page, key: string) {
    await page.goto('/assurance');
    await page.getByLabel('API key').fill(key);
    await page.getByRole('button', { name: 'Refresh' }).click();
  }
  const adv = (page: Page) => page.locator('section#aw-advisories');
  const keys = (page: Page) => page.locator('section#aw-supplier-keys');
  const evaluate = async (page: Page, file: string, expectSupplier = '') => {
    await adv(page).getByLabel('Choose an advisory or feed file').setInputFiles(file);
    await expect(adv(page).getByTestId('adv-record').first()).toBeVisible({ timeout: 10_000 });
    await adv(page).getByLabel(/Expect this supplier id/).fill(expectSupplier);
    await adv(page).getByRole('button', { name: 'Evaluate under my pinned keys' }).click();
    await expect(adv(page).getByTestId('signed-result')).toBeVisible({ timeout: 15_000 });
  };
  const state = (page: Page, id: string) => adv(page).getByTestId(id);

  test('with no key pinned the feed is readable but not trusted: inspect only, no case control, states apart', async ({ page, request }) => {
    await enter(page, seed.key_g);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    await expect(keys(page).getByTestId('no-pins')).toContainText(/No supplier key is pinned/, { timeout: 15_000 });
    await expect(keys(page).getByTestId('key-not-proof')).toContainText(/key inside an advisory.*is not proof/i);

    await evaluate(page, seed.supplier.feed_path);
    const res = adv(page).getByTestId('signed-result');
    await expect(res).toHaveAttribute('data-inspect-only', 'true');
    await expect(res.getByTestId('inspect-only-banner')).toContainText('INSPECT ONLY');
    await expect(res.getByTestId('inspect-only-banner')).toContainText('no trusted consequences');
    // The server's trust statement, verbatim.
    await expect(res.getByTestId('trust-statement')).toContainText(STATEMENT_GIST);

    // Separate answers, none of them a single "verified".
    await expect(state(page, 'state-readable')).toHaveAttribute('data-value', 'yes');
    await expect(state(page, 'state-signature')).toHaveAttribute('data-value', 'not_checkable');
    await expect(state(page, 'state-key-trust')).toHaveAttribute('data-value', 'unknown_key');
    await expect(state(page, 'state-chain')).toBeVisible();
    await expect(state(page, 'state-dup-conflict')).toBeVisible();
    await expect(state(page, 'state-withdrawals')).toBeVisible();
    await expect(state(page, 'state-policy')).toHaveAttribute('data-value', 'not met');
    await expect(res).not.toContainText(CLAIMS_VERIFIED);

    // What the server said, as the API itself answers it.
    const text = readFileSync(seed.supplier.feed_path, 'utf8');
    const direct = await (
      await request.post(`${apiBase}/v1/fleet/advisory/signed`, { headers: { 'X-API-Key': seed.key_g }, data: { feed: text } })
    ).json();
    expect(direct.inspect_only).toBe(true);
    expect(direct.trust.key_trust_state).toBe('unknown_key');
    expect((await res.getByTestId('trust-statement').textContent())?.trim()).toBe(direct.trust_statement);

    // Every advisory is inspect-only; the case control is disabled and says why.
    const rows = res.getByTestId('trust-advisory');
    await expect(rows).toHaveCount(direct.advisories.length);
    for (let i = 0; i < direct.advisories.length; i++) {
      const row = rows.nth(i);
      await expect(row).toHaveAttribute('data-permitted', 'false');
      await expect(row.getByTestId('trust-basis')).toContainText('NOT TRUSTED');
      await expect(row.getByRole('button', { name: /^Open assurance case from/ })).toBeDisabled();
      await expect(row.getByTestId('case-disabled-why')).toContainText(/did not permit automated consequences/);
    }
    // The impact is still inspectable, and says it is inspect only.
    await expect(rows.first().getByTestId('signed-impact-summary')).toContainText('inspect only');

    // The record read locally offers no case either: it came in a feed nobody has judged.
    await adv(page)
      .locator(`[data-testid="adv-record"][data-advisory-id="${seed.supplier.first_advisory_id}"]`)
      .getByRole('button', { name: /Check fleet impact/ })
      .click();
    await expect(adv(page).getByTestId('signed-record-no-case')).toContainText(/Inspect only/);
    await expect(adv(page).getByRole('button', { name: 'Open assurance case', exact: true })).toBeDisabled();
    const cases = await (await request.get(`${apiBase}/v1/change/cases`, { headers: { 'X-API-Key': seed.key_g } })).json();
    expect(JSON.stringify(cases)).not.toContain(seed.supplier.first_advisory_id);
  });

  test('pinning asks how the key was obtained apart from the feed, and a mismatching fingerprint is refused', async ({ page, request }) => {
    await enter(page, seed.key_g);
    await expect(keys(page).getByTestId('no-pins')).toBeVisible({ timeout: 15_000 });
    const form = keys(page).getByTestId('trust-form-pin');
    await form.locator('summary').click();
    await expect(form).toContainText(/Do not copy a key or fingerprint out of the feed/);
    await form.locator('[name="pin-supplier_id"]').fill(seed.supplier.supplier_id);
    await form.locator('[name="pin-public_key_pem"]').fill(pem);
    await form.locator('[name="pin-actor"]').fill('v.grimaldi');

    // No "obtained via": nothing is sent.
    await form.getByRole('button', { name: 'Pin key' }).click();
    await expect(form.getByRole('alert')).toContainText(/How you obtained this key/);
    // A fingerprint that is not this key's: the server refuses (409) in its words.
    await form.locator('[name="pin-obtained_via"]').fill('e2e: read out over the phone');
    await form.locator('[name="pin-expected_fingerprint"]').fill('0'.repeat(16));
    await form.getByRole('button', { name: 'Pin key' }).click();
    await expect(form.getByRole('alert')).toContainText('(409)', { timeout: 10_000 });
    const t = await (await request.get(`${apiBase}/v1/supplier/trust`, { headers: { 'X-API-Key': seed.key_g } })).json();
    expect(t.pins).toHaveLength(0);

    // The right fingerprint, obtained independently: pinned, and the pin shows how.
    await form.locator('[name="pin-expected_fingerprint"]').fill(seed.supplier.fingerprint);
    await form.getByRole('button', { name: 'Pin key' }).click();
    await expect(form.getByTestId('trust-pin-done')).toContainText(seed.supplier.fingerprint, { timeout: 10_000 });
    const row = keys(page).getByTestId('pin-row');
    await expect(row).toHaveCount(1);
    await expect(row).toContainText('e2e: read out over the phone');
    await expect(row).toContainText('v.grimaldi');
    await expect(row).toContainText(seed.supplier.fingerprint);
  });

  test('under the pinned key the states change one by one; the page still proves nothing about correctness', async ({ page, request }) => {
    await enter(page, seed.key_g);
    await expect(keys(page).getByTestId('pin-row')).toHaveCount(1, { timeout: 15_000 });
    await evaluate(page, seed.supplier.feed_path);
    const res = adv(page).getByTestId('signed-result');
    await expect(state(page, 'state-key-trust')).toHaveAttribute('data-value', 'pinned');
    await expect(state(page, 'state-signature')).toHaveAttribute('data-value', 'all_valid');
    await expect(res.getByTestId('trust-statement')).toContainText(STATEMENT_GIST);
    const text = readFileSync(seed.supplier.feed_path, 'utf8');
    const direct = await (
      await request.post(`${apiBase}/v1/fleet/advisory/signed`, { headers: { 'X-API-Key': seed.key_g }, data: { feed: text } })
    ).json();
    // The page shows exactly what the server decided.
    await expect(res).toHaveAttribute('data-inspect-only', direct.inspect_only ? 'true' : 'false');
    await expect(state(page, 'state-chain')).toHaveAttribute('data-value', direct.trust.chain_valid ? 'yes' : 'no');
    await expect(state(page, 'state-policy')).toHaveAttribute('data-value', direct.trust.policy_satisfied ? 'met' : 'not met');
    for (const a of direct.advisories) {
      await expect(res.locator(`[data-testid="trust-advisory"][data-advisory-id="${a.advisory_id}"]`)).toHaveAttribute(
        'data-permitted',
        a.automated_consequences_permitted ? 'true' : 'false',
      );
    }
    await expect(res).not.toContainText(CLAIMS_VERIFIED);
  });

  test('a tampered record fails its signature under the pinned key: evidence of tampering, no override offered', async ({ page }) => {
    await enter(page, seed.key_g);
    await expect(keys(page).getByTestId('pin-row')).toHaveCount(1, { timeout: 15_000 });
    await evaluate(page, seed.supplier.tampered_path);
    await expect(state(page, 'state-signature')).toHaveAttribute('data-value', 'some_invalid');
    await expect(adv(page).getByTestId('signed-result')).toHaveAttribute('data-inspect-only', 'true');
    await expect(adv(page).getByTestId('state-signature')).toContainText(/FAILS|tampering/);
    await adv(page).getByText('Per record: signature and key state').click();
    await expect(adv(page).locator('[data-testid="record-trust-row"][data-signature="invalid"]').first()).toBeVisible();
    const rows = adv(page).getByTestId('trust-advisory');
    const n = await rows.count();
    for (let i = 0; i < n; i++) {
      await expect(rows.nth(i).getByRole('button', { name: /^Open assurance case from/ })).toBeDisabled();
    }
    // The server refuses to let a person override a signature that fails.
    await expect(adv(page).getByTestId('override-refused').first()).toContainText(/signature FAILS|tampering/);
    await expect(adv(page).getByTestId('override-flow')).toHaveCount(0);
  });

  test('a manual override asks for who and why, and is shown as an attributed override, not as trust', async ({ page, request }) => {
    await enter(page, seed.key_g);
    await expect(keys(page).getByTestId('pin-row')).toHaveCount(1, { timeout: 15_000 });
    // Pinned key, valid signatures, but the caller expected a different supplier: policy not met.
    await evaluate(page, seed.supplier.feed_path, 'some-other-supplier');
    const res = adv(page).getByTestId('signed-result');
    await expect(res).toHaveAttribute('data-inspect-only', 'true');
    await expect(state(page, 'state-policy')).toHaveAttribute('data-value', 'not met');
    const target = res.locator(`[data-testid="trust-advisory"][data-advisory-id="${seed.supplier.first_advisory_id}"]`);
    await expect(target).toHaveAttribute('data-permitted', 'false');
    await target.getByRole('button', { name: /Override: accept this one advisory anyway/ }).click();
    await expect(target.getByTestId('override-flow')).toContainText(/does not make the feed\s+trusted|does not make the feed trusted/);

    await target.getByRole('button', { name: 'Record override' }).click();
    await expect(target.getByRole('alert')).toContainText(/name and a reason/);
    await target.locator('[name="override-actor"]').fill('v.grimaldi');
    await target.locator('[name="override-reason"]').fill('Supplier confirmed this advisory by phone; feed id mismatch is ours.');
    await target.getByRole('button', { name: 'Record override' }).click();

    const after = res.locator(`[data-testid="trust-advisory"][data-advisory-id="${seed.supplier.first_advisory_id}"]`);
    await expect(after).toHaveAttribute('data-permitted', 'true', { timeout: 15_000 });
    await expect(after.getByTestId('trust-basis')).toHaveAttribute('data-basis', 'manual_override');
    await expect(after.getByTestId('trust-basis')).toContainText('Attributed manual override');
    await expect(after.getByTestId('trust-basis')).toContainText('v.grimaldi');
    await expect(after.getByTestId('trust-basis')).toContainText('feed id mismatch is ours');
    await expect(after.getByTestId('trust-basis')).toContainText(/not trust in the feed/);
    // The feed itself still does not meet policy.
    await expect(state(page, 'state-policy')).toHaveAttribute('data-value', 'not met');

    // The override is on the ledger, attributed.
    const t = await (await request.get(`${apiBase}/v1/supplier/trust`, { headers: { 'X-API-Key': seed.key_g } })).json();
    expect(t.overrides).toHaveLength(1);
    expect(t.overrides[0].actor).toContain('v.grimaldi');
    await expect(keys(page).getByTestId('overrides-list')).toContainText('v.grimaldi', { timeout: 10_000 });
  });

  test('revoking the key makes the feed untrusted again and an override is refused with the server\'s reason', async ({ page }) => {
    await enter(page, seed.key_g);
    await expect(keys(page).getByTestId('pin-row')).toHaveCount(1, { timeout: 15_000 });
    const form = keys(page).getByTestId('trust-form-revoke');
    await form.locator('summary').click();
    await form.locator('[name="revoke-supplier_id"]').fill(seed.supplier.supplier_id);
    await form.locator('[name="revoke-fingerprint"]').fill(seed.supplier.fingerprint);
    await form.locator('[name="revoke-actor"]').fill('v.grimaldi');
    await form.getByRole('button', { name: 'Revoke key' }).click();
    await expect(form.getByRole('alert')).toContainText(/Why \(required\)/);
    await form.locator('[name="revoke-reason"]').fill('e2e: key compromised');
    await form.getByRole('button', { name: 'Revoke key' }).click();
    await expect(keys(page).getByTestId('pin-row')).toHaveAttribute('data-status', 'revoked', { timeout: 10_000 });

    await evaluate(page, seed.supplier.feed_path);
    await expect(state(page, 'state-key-trust')).toHaveAttribute('data-value', 'revoked');
    await expect(adv(page).getByTestId('signed-result')).toHaveAttribute('data-inspect-only', 'true');
    await expect(adv(page).getByTestId('override-refused').first()).toContainText(/revoked key/);
  });

  // ------------------------------------------------------------------ classification
  test('each machine is classified by the engine, unknown and contradictory are never "no match", clear says if it is complete', async ({ page, request }) => {
    await enter(page, seed.key_a);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    for (const which of ['hash', 'mismatch', 'clear'] as const) {
      const advisory = which === 'hash' ? seed.advisories.hash : which === 'mismatch' ? seed.advisories.mismatch : seed.advisories.clear;
      const direct = await (
        await request.post(`${apiBase}/v1/fleet/advisory`, { headers: { 'X-API-Key': seed.key_a }, data: { advisory } })
      ).json();
      await adv(page).getByLabel(/^Advisory or feed/).fill(JSON.stringify(advisory));
      await adv(page).getByRole('button', { name: 'Read advisory' }).click();
      await adv(page).getByRole('button', { name: /Check fleet impact/ }).click();
      const table = adv(page).getByTestId('classification-table');
      await expect(adv(page).getByTestId('impact-result')).toBeVisible({ timeout: 10_000 });
      await expect(adv(page).getByTestId('clear-is-complete')).toHaveAttribute('data-value', String(direct.clear_is_complete));
      if (direct.machine_classification.length === 0) continue;
      await expect(table).toBeVisible();
      for (const c of direct.machine_classification as { machine: string; classification: string; uncertainty: string }[]) {
        const row = adv(page).locator(`[data-testid="classification-row"][data-machine="${c.machine}"]`);
        await expect(row).toHaveAttribute('data-classification', c.classification);
        await expect(row.getByTestId('classification-badge')).toHaveAttribute('data-classification', c.classification);
        await expect(row.getByTestId('classification-uncertainty')).toContainText(c.uncertainty.slice(0, 30));
        if (c.classification === 'unknown') {
          await expect(row.getByTestId('classification-badge')).toContainText('UNKNOWN');
          await expect(row.getByTestId('classification-badge')).not.toContainText('NO MATCH');
        }
        if (c.classification === 'contradictory_label_vs_hash') {
          await expect(row.getByTestId('classification-badge')).toContainText('CONTRADICTORY');
        }
      }
      await expect(adv(page).getByTestId('unknowns')).toContainText(`Unknown machines (${direct.unknown_machines.length})`);
      await expect(adv(page).getByTestId('unknowns')).toContainText(`Unknown safety functions (${direct.unknown_functions.length})`);
      await expect(adv(page).getByTestId('unknowns')).toContainText(`Prior evidence in question (${direct.prior_evidence_in_question.length})`);
    }
  });

  // ------------------------------------------------------------------ fleet record source
  test('every machine says where its record comes from, its completeness and the limits of a submitted observation', async ({ page }) => {
    await enter(page, seed.key_e);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    const row = (m: string) => page.locator(`[data-testid="fleet-row"][data-machine="${m}"]`);
    const ok = row(seed.machines_e.ok);
    await expect(ok.getByTestId('obs-source')).toHaveAttribute('data-source', 'client-reported-watch', { timeout: 15_000 });
    await expect(ok.getByTestId('obs-source')).toContainText('client-reported Watch observation');
    await expect(ok.getByTestId('obs-source')).toContainText('not independent telemetry');
    await expect(ok.getByTestId('obs-source')).toContainText(/Completeness of the latest attempt/);
    await expect(ok.getByTestId('manifest-cell')).toContainText('sealed manifest');
    const blind = row(seed.machines_e.blind_stale);
    await expect(blind.getByTestId('obs-source')).toContainText('NOT COLLECTED');
    await expect(blind.getByTestId('obs-source')).not.toContainText(/complete look/);
    const limits = page.getByTestId('fleet-limits');
    await expect(limits).toContainText('A submitted observation is not independent telemetry');
    await expect(limits).toContainText('A missing report is not evidence the machine is unchanged');

    // A machine nobody reported on is a manifest, and says a missing report proves nothing.
    await enter(page, seed.key_d);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    const only = page.locator(`[data-testid="fleet-row"][data-machine="${seed.d_machine}"]`);
    await expect(only.getByTestId('obs-source')).toHaveAttribute('data-source', 'manifest-only');
    await expect(only.getByTestId('obs-source')).toContainText('A missing report is not evidence the machine is unchanged');
  });

  // ------------------------------------------------------------------ decision credential
  test('no operators: the page says how to create the first one (stubbed list/create, labelled) and shows the key once', async ({ page }) => {
    // Only /v1/operators is stubbed: it is the one state (an account with no operator yet) that the
    // seeded accounts cannot be in once other specs have created theirs.
    let created = false;
    await page.route('**/v1/operators', async (route) => {
      const m = route.request().method();
      if (m === 'GET') {
        await route.fulfill({
          json: { operators: [], you: { operator_id: null, role: 'account-level key' } },
        });
      } else {
        created = true;
        const body = route.request().postDataJSON();
        expect(body).toEqual({ name: 'First Decider', role: 'decider' });
        await route.fulfill({
          status: 201,
          json: {
            operator_id: 'op_stub',
            name: 'First Decider',
            role: 'decider',
            api_key: 'asr_stub_operator_key_shown_once',
            note: 'This key is shown once.',
          },
        });
      }
    });
    await enter(page, seed.key_a);
    await page.getByRole('button', { name: seed.case_id }).click();
    const detail = page.getByTestId('case-detail');
    const cred = detail.getByTestId('decision-credential');
    await expect(cred).toContainText('it is not identity proof', { timeout: 15_000 });
    await expect(cred.getByTestId('no-operators')).toContainText(/no operators/);
    await expect(cred.getByTestId('no-operators')).toContainText(/Create the first one/);
    // The key is never in the address.
    await cred.getByTestId('operator-name').fill('First Decider');
    await cred.getByRole('button', { name: /Create first operator/ }).click();
    expect(created).toBe(true);
    const once = cred.getByTestId('operator-key-once');
    await expect(once).toContainText('shown once');
    await expect(once.getByTestId('operator-key-value')).toHaveValue('asr_stub_operator_key_shown_once');
    expect(page.url()).not.toContain('asr_stub');
    await once.getByRole('button', { name: /Use it as the decision credential/ }).click();
    await expect(cred.getByTestId('decision-credential-input')).toHaveValue('asr_stub_operator_key_shown_once');
    await once.getByRole('button', { name: /I have stored it/ }).click();
    await expect(cred.getByTestId('operator-key-once')).toHaveCount(0);
  });

  test('a contributor key is refused with decider_role_required and the page says what to do', async ({ page, request }) => {
    await operatorKey(request, seed.key_a, 'v.grimaldi');
    const contributor = await operatorKey(request, seed.key_a, 'c.contrib', 'contributor');
    await enter(page, seed.key_a);
    await page.getByRole('button', { name: seed.case_id }).click();
    const detail = page.getByTestId('case-detail');
    await detail.getByTestId('decision-credential-input').fill(contributor, { timeout: 15_000 });
    await detail.getByLabel('Decision reason').fill('Trying to close as a contributor');
    await detail.getByRole('button', { name: 'Reject', exact: true }).click();
    const refusal = detail.getByTestId('action-refusal');
    await expect(refusal).toHaveAttribute('data-code', 'decider_role_required', { timeout: 10_000 });
    await expect(refusal).toContainText(/not a decider/);
    // The contributor key is held in this tab only: it is not in the address or the page text.
    expect(page.url()).not.toContain(contributor);
    await expect(detail).not.toContainText(contributor);
  });
});
