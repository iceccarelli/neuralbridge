import { expect, type APIRequestContext, type Locator } from '@playwright/test';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

// Case decisions need a key issued to an individual operator with the decider role
// (POST /v1/operators). An operator key is shown once, so the keys created during a run are
// remembered beside the seed file; the specs share one API and one set of seeded accounts.
// Keys live in the run's throwaway directory only, never in the repository.
type Entry = { account: string; name: string; role: string; key: string };

const apiBase = () => process.env.NEXT_PUBLIC_ASSURANCE_API_URL || 'http://127.0.0.1:8001';
const cachePath = () => `${process.env.ASSURANCE_E2E_SEED}.operators.json`;

function load(): Entry[] {
  try {
    return existsSync(cachePath()) ? JSON.parse(readFileSync(cachePath(), 'utf8')) : [];
  } catch {
    return [];
  }
}

export async function operatorKey(
  request: APIRequestContext,
  accountKey: string,
  name: string,
  role: 'decider' | 'contributor' = 'decider',
): Promise<string> {
  const account = accountKey.slice(0, 12);
  const cache = load();
  const hit = cache.find((e) => e.account === account && e.name === name);
  if (hit) return hit.key;
  const live = await (await request.get(`${apiBase()}/v1/operators`, { headers: { 'X-API-Key': accountKey } })).json();
  const existing = (live.operators as { disabled: boolean }[]).filter((o) => !o.disabled);
  // The first operator is created with the account key; later ones need a decider's key.
  const via =
    existing.length === 0 ? accountKey : cache.find((e) => e.account === account && e.role === 'decider')?.key;
  expect(via, 'an account that already has operators needs a remembered decider key').toBeTruthy();
  const res = await request.post(`${apiBase()}/v1/operators`, {
    headers: { 'X-API-Key': via! },
    data: { name, role: existing.length === 0 ? 'decider' : role },
  });
  expect(res.status()).toBe(201);
  const body = await res.json();
  cache.push({ account, name, role: body.role, key: body.api_key });
  writeFileSync(cachePath(), JSON.stringify(cache), { mode: 0o600 });
  return body.api_key;
}

// Enter the decision credential in a case panel (or any container holding the control).
export async function useDecisionCredential(scope: Locator, key: string) {
  await scope.getByTestId('decision-credential-input').fill(key);
}
