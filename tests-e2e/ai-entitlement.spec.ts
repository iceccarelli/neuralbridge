import { test, expect } from './support/fixtures';
import { aiSeed, enterKey, executions, hdr, insertSql, newMarker, platformApi, say } from './support/ai';

// Entitlements on /ai, read from the real account store on every request: 402 when the caller is
// authenticated (or anonymous) but not entitled to the write path, 401 for a key that is not valid. The UI must
// show each refusal as what it is, never a fake success and never a generic "could not reach".

const PLAN_402 = { status: 402, url: /\/ai\/plan$/, why: 'the spec proposes a write as a caller whose plan has no control plane' };

test('no key: reads work, a write shows the real upgrade card (402) and nothing runs', async ({ page, allowHealth }) => {
  allowHealth(PLAN_402);
  const marker = newMarker('free');
  await page.goto('/ai');
  await expect(page.getByText(/writes need upgrade/i)).toBeVisible();

  await say(page, insertSql(marker));
  await expect(page.getByText('Register or Cell required')).toBeVisible();
  await expect(page.getByRole('link', { name: /see pricing/i }).first()).toHaveAttribute('href', '/#pricing');
  await expect(page.getByText(/approval required/i)).toHaveCount(0);
  await expect(page.getByText('Execution receipt')).toHaveCount(0);
  expect(executions(marker)).toBe(0);
});

test('a real key on a Validator (free) account is authenticated but not entitled: 402, nothing runs', async ({ page, request, allowHealth }) => {
  allowHealth(PLAN_402);
  const { free_account: key } = aiSeed();
  const marker = newMarker('freekey');
  await page.goto('/ai');
  await enterKey(page, key);
  await expect(page.getByText(/writes need upgrade/i)).toBeVisible();
  await say(page, insertSql(marker));
  await expect(page.getByText('Register or Cell required')).toBeVisible();
  expect(executions(marker)).toBe(0);

  // Binding a connection and the full audit trail are the same paid door.
  const bind = await request.post(`${platformApi()}/ai/connections`, { headers: hdr(key), data: { name: 'x', ...aiSeed().customer_db } });
  expect(bind.status()).toBe(402);
  expect((await bind.json()).detail.error).toBe('plan_does_not_include_ai_control_plane');
});

test('a key that is not valid gets the honest 401, not "could not reach" and not a free session', async ({ page, allowHealth }) => {
  allowHealth({ status: 401, url: /\/ai\/(session|connections|capabilities)/, why: 'the spec presents a key the account store does not know' });
  await page.goto('/ai');
  await enterKey(page, aiSeed().invalid_key);
  await expect(page.getByText(/invalid or revoked api key|HTTP 401/i).first()).toBeVisible();
  await expect(page.getByText(/could not reach the neuralbridge api/i)).toHaveCount(0);
  await expect(page.getByLabel('Message')).toBeDisabled();
});

test('a 402d write, then a paid key pasted in the same tab, is retried with no retyping and still never runs on the read-only shared demo', async ({ page, allowHealth }) => {
  allowHealth(PLAN_402);
  allowHealth({ status: 403, url: /\/ai\/plan$/, why: 'the shared seeded demo connection is read-only even for a paid account' });
  const marker = newMarker('retry');
  await page.goto('/ai');
  await say(page, insertSql(marker));
  await expect(page.getByText('Register or Cell required')).toBeVisible();
  const retry = page.getByRole('button', { name: /retry now with your key/i });
  await expect(retry).toBeDisabled();
  await expect(page.getByLabel('Message')).toHaveValue('');

  await enterKey(page, aiSeed().register_a);
  await expect(retry).toBeEnabled();
  // Wait for the refusal itself. `getByText(/read-only/i)` alone is satisfied at once by the
  // "Shared demonstration database (read-only)" label already on the page, so without this the
  // test could finish before the 403 arrived and the health fixture then (rightly) reported the
  // 403 allowance as unused (seen on the hosted runner; reproduced by delaying the response).
  const refused = page.waitForResponse((r) => /\/ai\/plan$/.test(r.url()) && r.request().method() === 'POST' && r.status() === 403);
  await retry.click();
  await refused;
  // The free caller only had the shared demo, which no paid account may write: an honest refusal, not an execution.
  await expect(page.getByText(/read-only/i).first()).toBeVisible();
  await expect(page.getByText(/approval required/i)).toHaveCount(0);
  expect(executions(marker)).toBe(0);
});
