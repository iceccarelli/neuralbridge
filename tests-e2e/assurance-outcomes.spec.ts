import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { call, callText, describeOutcome, keepsLastGood, type ApiOutcome } from '../app/lib/assuranceApi';

// The client the workspace uses (app/lib/assuranceApi.ts), run from Node against the REAL
// local Assurance API. Every refusal the server can give must come back as its own kind,
// carrying the server's remedy text, and none may be turned into a success or an empty list.
//
// Two cases cannot be produced by this server on demand (a 403, a 5xx): those use a stubbed
// `fetch` and are labelled as unit checks of the classifier, not of the API.

const seedPath = process.env.ASSURANCE_E2E_SEED;
const apiBase = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || 'http://127.0.0.1:8001';

type Seed = {
  key_a: string;
  key_g: string;
  key_register: string;
  case_id: string;
  k_manifest: Record<string, unknown>;
  advisories: { clear: Record<string, unknown> };
};

function refusal(o: ApiOutcome<unknown>) {
  if (o.kind === 'ok') throw new Error('expected a refusal, got ok');
  return o;
}

test.describe('assuranceApi against the real API', () => {
  let seed: Seed;
  test.beforeAll(() => {
    test.skip(!seedPath, 'Set ASSURANCE_E2E_SEED (run scripts/e2e-assurance.sh).');
    seed = JSON.parse(readFileSync(seedPath!, 'utf8'));
  });

  test('401: no key, and a key the server does not know', async () => {
    for (const key of ['', 'asr_not_a_real_key']) {
      const o = refusal(await call(apiBase, key, '/v1/fleet/machines'));
      expect(o.kind).toBe('unauthorized');
      const d = describeOutcome(o);
      expect(d.heading).toContain('401');
      expect(d.text).toMatch(/key/i);
    }
  });

  test('402: authenticated but not entitled carries the server remedy verbatim', async () => {
    const o = refusal(await call(apiBase, seed.key_register, '/v1/fleet/machines'));
    expect(o.kind).toBe('upgrade');
    if (o.kind !== 'upgrade') return;
    expect(o.tier).toBe('register');
    expect(o.code).toBe('plan_does_not_include_machine_verification');
    expect(o.remedy).toContain('Machine safety verification is included from the Cell plan upward');
    expect(describeOutcome(o).remedy).toBe(o.remedy);
  });

  test('404: a case that is not in your ledger', async () => {
    const o = refusal(await call(apiBase, seed.key_g, `/v1/change/cases/${seed.case_id}`));
    expect(o.kind).toBe('notfound');
    expect(describeOutcome(o).heading).toContain('404');
  });

  test('409: a close the server refuses is a conflict with its reason', async () => {
    const o = refusal(
      await call(apiBase, seed.key_a, `/v1/change/cases/${seed.case_id}/decision`, {
        method: 'POST',
        body: { disposition: 'closed', reason: 'looks fine', actor: 'v.grimaldi' },
      }),
    );
    expect(o.kind).toBe('conflict');
    if (o.kind === 'conflict') expect(o.message.length).toBeGreaterThan(10);
  });

  test('413: an oversized body is "too large" with the limit, not a network error', async () => {
    const o = refusal(
      await call(apiBase, seed.key_g, '/v1/fleet/advisory', {
        method: 'POST',
        body: { advisory: { summary: 'x'.repeat(1_200_000) } },
      }),
    );
    expect(o.kind).toBe('toolarge');
    if (o.kind === 'toolarge') expect(o.limitBytes).toBe(1_048_576);
    expect(describeOutcome(o).text).toContain('1,048,576');
  });

  test('422: content the server cannot use, in its words (validation list and structured detail)', async () => {
    const bad = refusal(await call(apiBase, seed.key_g, '/v1/fleet/advisory', { method: 'POST', body: { advisory: {} } }));
    expect(bad.kind).toBe('invalid');
    const shape = refusal(await call(apiBase, seed.key_g, '/v1/fleet/advisory', { method: 'POST', body: { nope: 1 } }));
    expect(shape.kind).toBe('invalid');
    if (shape.kind === 'invalid') expect(shape.message).toMatch(/advisory/);
  });

  test('429: the free allowance running out says what removes the cap', async () => {
    // Anonymous callers spend the free daily allowance (10). Only a call that completes is
    // counted (a refused one costs nothing), so the calls here are real, valid ones.
    let last: ApiOutcome<unknown> | null = null;
    for (let i = 0; i < 12 && (last === null || last.kind !== 'ratelimited'); i++) {
      last = await call(apiBase, '', '/v1/fleet/advisory/check', {
        method: 'POST',
        body: { advisory: seed.advisories.clear, manifest: seed.k_manifest },
      });
    }
    const o = refusal(last!);
    expect(o.kind).toBe('ratelimited');
    if (o.kind !== 'ratelimited') return;
    expect(o.remedy).toMatch(/paid plan/i);
    expect(describeOutcome(o).heading).toContain('429');
  });

  test('a public hosted feed that does not exist is a 404, and a feed is read as text without a key', async () => {
    const o = refusal(await callText(apiBase, '/v1/supplier/feed/acc_does_not_exist'));
    expect(o.kind).toBe('notfound');
    if (o.kind === 'notfound') expect(o.message).toContain('No feed has been published');
  });

  test('unreachable and unconfigured are their own outcomes, not empty results', async () => {
    const down = refusal(await call('http://127.0.0.1:1', seed.key_g, '/v1/fleet/machines'));
    expect(down.kind).toBe('unreachable');
    expect(describeOutcome(down).remedy).toMatch(/not an empty result/i);
    const none = refusal(await call('', seed.key_g, '/v1/fleet/machines'));
    expect(none.kind).toBe('unconfigured');
    expect(describeOutcome(none).heading).toBe('No API configured');
  });

  test('ok carries the time it was received', async () => {
    const before = Date.now();
    const o = await call<{ summary: unknown }>(apiBase, seed.key_g, '/v1/fleet/machines');
    expect(o.kind).toBe('ok');
    if (o.kind === 'ok') {
      expect(o.at).toBeGreaterThanOrEqual(before);
      expect(o.at).toBeLessThanOrEqual(Date.now());
    }
  });
});

// Unit checks of the classifier with a stubbed fetch: the real server does not emit these on demand.
test.describe('assuranceApi classifier (stubbed fetch — unit checks, not the API)', () => {
  const real = globalThis.fetch;
  test.afterEach(() => {
    globalThis.fetch = real;
  });
  const stub = (status: number, body: unknown, headers: Record<string, string> = {}) => {
    globalThis.fetch = (async () =>
      new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } })) as typeof fetch;
  };

  test('403 is "refused", with the server text', async () => {
    stub(403, { detail: 'operator keys only' });
    const o = refusal(await call('http://x', 'k', '/v1/anything'));
    expect(o.kind).toBe('forbidden');
    expect(describeOutcome(o).text).toContain('operator keys only');
  });

  test('429 carries Retry-After and the remedy', async () => {
    stub(429, { detail: { error: 'quota_exceeded', remedy: 'A paid plan removes the cap.' } }, { 'retry-after': '3600' });
    const o = refusal(await call('http://x', '', '/v1/anything'));
    expect(o.kind).toBe('ratelimited');
    expect(describeOutcome(o).remedy).toContain('A paid plan removes the cap.');
    expect(describeOutcome(o).remedy).toContain('3600');
  });

  test('5xx is a server error, never an empty list, and keeps last-good data; 401/402/404 do not', async () => {
    stub(500, { detail: 'boom' });
    const o = refusal(await call('http://x', 'k', '/v1/anything'));
    expect(o.kind).toBe('error');
    expect(describeOutcome(o).heading).toContain('500');
    expect(keepsLastGood(o)).toBe(true);
    for (const status of [401, 402, 403, 404, 409, 422]) {
      stub(status, { detail: 'no' });
      expect(keepsLastGood(refusal(await call('http://x', 'k', '/v1/anything')))).toBe(false);
    }
  });

  test('a non-JSON error body still yields a message', async () => {
    globalThis.fetch = (async () => new Response('<html>bad gateway</html>', { status: 502 })) as typeof fetch;
    const o = refusal(await call('http://x', 'k', '/v1/anything'));
    expect(o.kind).toBe('error');
    if (o.kind === 'error') expect(o.message).toBe('HTTP 502');
  });
});
