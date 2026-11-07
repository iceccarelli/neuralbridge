import { expect, type APIRequestContext, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

// Helpers for the /ai journey against the REAL platform API (neuralbridge.main:app on PostgreSQL) and the
// accounts seeded by scripts/e2e_seed_ai.py. Nothing here fakes an entitlement: callers hold real keys of
// real Register / Cell / Validator accounts in the same account store the API reads. Whether a write really
// ran is asserted in PostgreSQL itself (`count`), never from what the UI says.

export type AiSeed = {
  register_a: string;
  register_b: string;
  cell: string;
  free_account: string;
  invalid_key: string;
  customer_db: { host: string; port: number; user: string; password: string; database: string };
};

let cached: AiSeed | undefined;
export function aiSeed(): AiSeed {
  if (!cached) {
    const file = process.env.NEURALBRIDGE_E2E_AI_SEED;
    if (!file) throw new Error('NEURALBRIDGE_E2E_AI_SEED is not set: run these specs through scripts/e2e-local.sh');
    cached = JSON.parse(readFileSync(file, 'utf8')) as AiSeed;
  }
  return cached;
}

export const platformApi = () => {
  const v = process.env.NEXT_PUBLIC_NEURALBRIDGE_API_URL;
  if (!v) throw new Error('NEXT_PUBLIC_NEURALBRIDGE_API_URL is not set: run these specs through scripts/e2e-local.sh');
  return v;
};

/** A marker no other test shares, so a count in PostgreSQL belongs to exactly one plan. */
export const newMarker = (label: string) => `${label}-${randomBytes(4).toString('hex')}`;

/** Rows in the seeded customer database carrying `marker` (the plans the specs propose INSERT it). */
export function executions(marker: string): number {
  const out = execFileSync(
    process.env.ASSURANCE_E2E_PYTHON || 'python',
    [path.join(__dirname, '..', '..', 'scripts', 'e2e_seed_ai.py'), 'count', process.env.NEURALBRIDGE_E2E_AI_SEED!, marker],
    { encoding: 'utf8', env: process.env },
  );
  return Number(out.trim());
}

export const insertSql = (marker: string) => `INSERT INTO e2e_runs (note) VALUES ('${marker}')`;

export const hdr = (key?: string, actor = 'e2e-api') => ({
  'X-NB-Actor': actor,
  'X-NB-Session': 'e2e-session',
  ...(key ? { 'X-API-Key': key } : {}),
});

/** Bind the seeded customer database as the account's OWN connection, through the product's route. */
export async function bindCustomerConnection(request: APIRequestContext, key: string, name: string) {
  const c = aiSeed().customer_db;
  const r = await request.post(`${platformApi()}/ai/connections`, { headers: hdr(key), data: { name, ...c } });
  expect(r.status(), await r.text()).toBe(200);
  const body = await r.json();
  expect(JSON.stringify(body), 'the bind response must not echo the credential').not.toContain(c.password);
  return body as { id: string; name: string };
}

/** Type a key into the Context pane (the real input) and wait until the session reflects it. */
export async function enterKey(page: Page, key: string) {
  await page.getByLabel(/^API key/).fill(key);
}

/** Pick the account's own connection and wait for its permissions to load (the write intent needs execute_sql). */
export async function selectConnection(page: Page, name: string) {
  const select = page.getByLabel('Connection');
  await expect(select.locator('option', { hasText: name })).toHaveCount(1);
  await select.selectOption({ label: name });
  await expect(page.getByText('execute_sql').first()).toBeVisible();
}

export async function say(page: Page, text: string) {
  const box = page.getByLabel('Message');
  await expect(box).toBeEnabled();
  await box.fill(text);
  await box.press('Enter');
}

/** Propose `sql` as a write and return the plan the API created (read off the real response). */
export async function propose(page: Page, sql: string) {
  const planResponse = page.waitForResponse((r) => r.url().endsWith('/ai/plan') && r.request().method() === 'POST');
  await say(page, sql);
  const res = await planResponse;
  expect(res.status()).toBe(200);
  const body = (await res.json()) as { plan: { id: string; status: string }; risk_note: string };
  return body;
}

export async function planStatus(request: APIRequestContext, key: string, planId: string): Promise<string> {
  const r = await request.get(`${platformApi()}/ai/plan/${planId}`, { headers: hdr(key) });
  expect(r.status()).toBe(200);
  return (await r.json()).status;
}
