import { test, expect } from './support/fixtures';
import {
  aiSeed, bindCustomerConnection, enterKey, executions, hdr, insertSql, newMarker, planStatus, platformApi,
  propose, say, selectConnection,
} from './support/ai';

// The /ai journey against the REAL platform API (neuralbridge.main:app on PostgreSQL) with real accounts:
// discover -> read -> propose -> NOT executed until a human approves -> approve -> executed exactly once ->
// receipt -> audit; the denial path; tenancy; and that the customer's database password never reaches the
// browser. Whether a write really ran is asserted in PostgreSQL (`executions`), never from what the UI says.
//
// Run through scripts/e2e-local.sh (it seeds the accounts and the throwaway customer role and starts the
// services); there is no skip path: without them the specs fail, they do not pass vacuously.

test.describe('/ai as the free caller (no key)', () => {
  test('discover and read work; the connection is the honestly-labelled seeded demo', async ({ page }) => {
    await page.goto('/ai');
    await expect(page.getByRole('heading', { name: /discover, read, plan, approve/i })).toBeVisible();
    await expect(page.getByLabel('Connection').locator('option')).toHaveCount(1);
    await expect(page.getByText(/seeded from env/i)).toBeVisible();
    await expect(page.getByText(/writes need upgrade/i)).toBeVisible();

    await say(page, 'list tables');
    await expect(page.getByText('Read OK')).toBeVisible();
    await expect(page.getByText('demo_customers').first()).toBeVisible();
    await expect(page.getByText(/MOCK DATA/)).toHaveCount(0);
  });
});

test.describe('/ai as a paid (Register) caller', () => {
  test('bind -> discover -> propose is not executed -> approve -> exactly once -> receipt -> audit', async ({ page, request }) => {
    const { register_a: key } = aiSeed();
    const marker = newMarker('journey');
    const name = `customer-db-${marker}`;
    const conn = await bindCustomerConnection(request, key, name);

    await page.goto('/ai');
    await enterKey(page, key);
    await expect(page.getByText(/control plane: full/i)).toBeVisible();
    await selectConnection(page, name);

    // Discover: the capabilities say which operations are reads and which need approval.
    await say(page, 'what can I do?');
    await expect(page.getByText(/execute_sql \(write\)/)).toBeVisible();

    // Propose. It must not run.
    const proposal = await propose(page, insertSql(marker));
    await expect(page.getByText(/approval required/i)).toBeVisible();
    await expect(page.getByRole('button', { name: /approve & execute/i })).toBeVisible();
    await expect(page.getByText('Execution receipt')).toHaveCount(0);
    expect(proposal.plan.status).toBe('pending_approval');
    expect(await planStatus(request, key, proposal.plan.id)).toBe('pending_approval');
    expect(executions(marker), 'a proposed plan must not have executed').toBe(0);

    // A human approves: executed once, receipt shown, and it is in the audit pane.
    await page.getByRole('button', { name: /approve & execute/i }).click();
    await expect(page.getByText('Execution receipt')).toBeVisible();
    await expect(page.getByText(/^Approved by /)).toBeVisible();
    await expect(page.getByText(/execute_sql · success/).first()).toBeVisible();
    expect(executions(marker), 'approval executes exactly once').toBe(1);
    expect(await planStatus(request, key, proposal.plan.id)).toBe('executed');

    // The receipt's claim is the database's too: read the row back through the same connection.
    await say(page, `SELECT note FROM e2e_runs WHERE note = '${marker}'`);
    await expect(page.getByText(`"note": "${marker}"`)).toBeVisible();

    // Approving the executed plan again is refused and runs nothing.
    const again = await request.post(`${platformApi()}/ai/plan/${proposal.plan.id}/approve`, { headers: hdr(key) });
    expect(again.status()).toBe(409);
    expect(executions(marker)).toBe(1);

    // The account's audit trail (API) records the call and carries no credential.
    const audit = await request.get(`${platformApi()}/ai/audit?limit=50`, { headers: hdr(key) });
    expect(audit.status()).toBe(200);
    const entries = (await audit.json()) as { action: string; result: string; resource: string }[];
    expect(entries.some((e) => e.action === 'execute_sql' && e.result === 'success' && e.resource.includes(conn.id))).toBe(true);
    expect(JSON.stringify(entries)).not.toContain(aiSeed().customer_db.password);
  });

  test('the human can deny: nothing executes and the plan cannot be approved afterwards', async ({ page, request }) => {
    const { register_a: key } = aiSeed();
    const marker = newMarker('deny');
    const name = `customer-db-${marker}`;
    await bindCustomerConnection(request, key, name);

    await page.goto('/ai');
    await enterKey(page, key);
    await selectConnection(page, name);
    const proposal = await propose(page, insertSql(marker));
    await page.getByRole('button', { name: /^deny$/i }).click();
    await expect(page.getByText(/denied — nothing executed/i)).toBeVisible();
    await expect(page.getByText('Execution receipt')).toHaveCount(0);
    expect(executions(marker)).toBe(0);
    expect(await planStatus(request, key, proposal.plan.id)).toBe('denied');

    const approve = await request.post(`${platformApi()}/ai/plan/${proposal.plan.id}/approve`, { headers: hdr(key) });
    expect(approve.status()).toBe(409);
    expect(executions(marker)).toBe(0);
  });

  test("another account cannot see, approve or deny this account's plan", async ({ page, request }) => {
    const { register_a: a, register_b: b } = aiSeed();
    const marker = newMarker('tenant');
    const name = `customer-db-${marker}`;
    const conn = await bindCustomerConnection(request, a, name);

    await page.goto('/ai');
    await enterKey(page, a);
    await selectConnection(page, name);
    const proposal = await propose(page, insertSql(marker));

    const list = await request.get(`${platformApi()}/ai/connections`, { headers: hdr(b) });
    expect(JSON.stringify(await list.json())).not.toContain(conn.id);
    for (const path of [`/plan/${proposal.plan.id}/approve`, `/plan/${proposal.plan.id}/deny`]) {
      const r = await request.post(`${platformApi()}/ai${path}`, { headers: hdr(b) });
      expect(r.status(), path).toBe(404);
    }
    const anon = await request.post(`${platformApi()}/ai/plan/${proposal.plan.id}/approve`, { headers: hdr() });
    expect(anon.status()).toBe(402);
    expect(executions(marker)).toBe(0);
    expect(await planStatus(request, a, proposal.plan.id)).toBe('pending_approval');
  });

  test('the customer database credential never reaches the browser', async ({ page, request }) => {
    const { register_a: key, customer_db: db } = aiSeed();
    const marker = newMarker('secret');
    const name = `customer-db-${marker}`;
    const bodies: string[] = [];
    const urls: string[] = [];
    page.on('request', (r) => urls.push(`${r.url()} ${r.postData() ?? ''}`));
    page.on('response', async (r) => {
      if (!r.url().startsWith(platformApi())) return;
      bodies.push(`${r.status()} ${r.url()} ${await r.text().catch(() => '')}`);
    });

    await bindCustomerConnection(request, key, name);
    await page.goto('/ai');
    await enterKey(page, key);
    await selectConnection(page, name);
    await propose(page, insertSql(marker));
    await page.getByRole('button', { name: /approve & execute/i }).click();
    await expect(page.getByText('Execution receipt')).toBeVisible();
    await say(page, 'SELECT current_user');
    await expect(page.getByText('Read OK').last()).toBeVisible();
    await page.getByRole('button', { name: 'Refresh' }).click();

    const dump = await page.evaluate(() => ({
      html: document.documentElement.outerHTML,
      text: document.body.innerText,
      local: JSON.stringify({ ...window.localStorage }),
      session: JSON.stringify({ ...window.sessionStorage }),
      cookie: document.cookie,
    }));
    expect(bodies.length, 'the platform responses were captured').toBeGreaterThan(4);
    // Positive controls: the scan really covers what it claims to (the connection's name is in the DOM and in the
    // API bodies, the key is in this tab's sessionStorage), so an empty haystack cannot pass for a clean one.
    expect(dump.html).toContain(name);
    expect(bodies.join('\n')).toContain(name);
    expect(dump.session).toContain(key);
    for (const [where, haystack] of Object.entries({ ...dump, bodies: bodies.join('\n'), requests: urls.join('\n') })) {
      expect(haystack, `the database password must not appear in ${where}`).not.toContain(db.password);
    }
    // The session key is the one thing this tab is meant to hold (sessionStorage, by design); localStorage holds nothing of it.
    expect(dump.local).not.toContain(key);
    expect(bodies.join('\n')).not.toContain(key);
  });
});

test.describe('/ai when the platform API is unreachable', () => {
  test('says so, offers no connection to act on, and invents nothing', async ({ page, allowHealth }) => {
    allowHealth({ status: 0, url: /\/ai\/(connections|session)/, why: 'the spec severs the platform API on purpose' });
    await page.route('**/api/v1/ai/**', (route) => route.abort('connectionrefused'));
    await page.goto('/ai');
    await expect(page.getByText(/could not reach the neuralbridge api/i)).toBeVisible();
    await expect(page.getByLabel('Message')).toBeDisabled();
    await expect(page.getByLabel('Connection').locator('option')).toHaveCount(0);
    await expect(page.getByText(/Read OK|Execution receipt|approval required/i)).toHaveCount(0);
  });
});
