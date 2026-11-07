import { test, expect, watchBrowserHealth, type HealthAllow } from './support/fixtures';
import {
  aiSeed, bindCustomerConnection, enterKey, executions, insertSql, newMarker, planStatus, propose, selectConnection,
} from './support/ai';

// Two browser pages, one human each, press the button for the SAME plan at the same moment. The store's
// compare-and-set must let exactly one execute it. The assertion is made in PostgreSQL, not in the UI.
//
// Page 2 cannot be shown a plan proposed in page 1 by the product (cards live in one tab's memory), so its
// POST /ai/plan is answered with the REAL response page 1's proposal received (same plan id, same card); the
// approve/deny that follow are real requests from two tabs.

test.describe.configure({ mode: 'serial' });

async function twoPagesOnOnePlan(context: import('@playwright/test').BrowserContext, page1: import('@playwright/test').Page, request: import('@playwright/test').APIRequestContext, marker: string, health2: HealthAllow[]) {
  const { register_a: key } = aiSeed();
  const name = `race-db-${marker}`;
  await bindCustomerConnection(request, key, name);

  await page1.goto('/ai');
  await enterKey(page1, key);
  await selectConnection(page1, name);
  const proposal = await propose(page1, insertSql(marker));

  const page2 = await context.newPage();
  const finish2 = watchBrowserHealth(page2, undefined, health2);
  await page2.route('**/ai/plan', async (route) => {
    if (route.request().method() !== 'POST') return route.fallback();
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(proposal) });
  });
  await page2.goto('/ai');
  await enterKey(page2, key);
  await selectConnection(page2, name);
  const same = await propose(page2, insertSql(marker));
  expect(same.plan.id, 'both tabs hold the same plan').toBe(proposal.plan.id);
  expect(executions(marker)).toBe(0);
  return { key, page2, finish2, planId: proposal.plan.id };
}

test('two pages approve the same plan at once: exactly one execution', async ({ page, context, request, allowHealth }) => {
  const { register_a: key } = aiSeed();
  const losers: string[] = [];
  let page1Lost = false;
  const rounds = 3;
  for (let round = 1; round <= rounds; round++) {
    const marker = newMarker(`race${round}`);
    // Which tab loses is not knowable in advance; the 409 its loser sees is forgiven after the fact, on that tab only.
    const health2: HealthAllow[] = [];
    const { page2, finish2, planId } = await twoPagesOnOnePlan(context, page, request, marker, health2);

    const approve = (p: typeof page) => p.getByRole('button', { name: /approve & execute/i }).last();
    const responses = [page, page2].map((p) => p.waitForResponse((r) => /\/ai\/plan\/[^/]+\/approve$/.test(r.url())));
    await Promise.all([approve(page).click(), approve(page2).click()]);
    const statuses = (await Promise.all(responses)).map((r) => r.status()).sort();
    expect(statuses, `round ${round}: one 200 and one 409`).toEqual([200, 409]);

    expect(executions(marker), `round ${round}: the database saw exactly one execution`).toBe(1);
    expect(await planStatus(request, key, planId)).toBe('executed');
    const [receipt1, receipt2] = await Promise.all([page, page2].map((p) => p.getByText('Execution receipt').count()));
    expect(receipt1 + receipt2, 'exactly one tab shows a receipt').toBe(1);
    const loser = receipt1 ? page2 : page;
    await expect(loser.getByText(/not pending approval/i)).toBeVisible();
    losers.push(receipt1 ? 'page2' : 'page1');

    if (receipt1) health2.push({ status: 409, url: /\/ai\/plan\/[^/]+\/approve$/, why: 'page 2 lost the approve race on purpose' });
    else if (!page1Lost) {
      page1Lost = true;
      allowHealth({ status: 409, url: /\/ai\/plan\/[^/]+\/approve$/, why: 'page 1 lost an approve race on purpose' });
    }
    finish2();
    await page2.close();
  }
  test.info().annotations.push({ type: 'race losers', description: losers.join(',') });
});

test('approve in one page against deny in the other: one outcome, and the database agrees with it', async ({ page, context, request, allowHealth }) => {
  const { register_a: key } = aiSeed();
  const marker = newMarker('approve-deny');
  const health2: HealthAllow[] = [];
  const { page2, finish2, planId } = await twoPagesOnOnePlan(context, page, request, marker, health2);

  const approveResp = page.waitForResponse((r) => /\/ai\/plan\/[^/]+\/approve$/.test(r.url()));
  const denyResp = page2.waitForResponse((r) => /\/ai\/plan\/[^/]+\/deny/.test(r.url()));
  await Promise.all([
    page.getByRole('button', { name: /approve & execute/i }).last().click(),
    page2.getByRole('button', { name: /^deny$/i }).last().click(),
  ]);
  const a = (await approveResp).status();
  const d = (await denyResp).status();
  expect([a, d].sort(), 'exactly one decision is accepted').toEqual([200, 409]);

  const status = await planStatus(request, key, planId);
  if (a === 200) {
    expect(status).toBe('executed');
    expect(executions(marker)).toBe(1);
    health2.push({ status: 409, url: /\/ai\/plan\/[^/]+\/deny/, why: 'denying lost to the approval on purpose' });
  } else {
    expect(status).toBe('denied');
    expect(executions(marker), 'a denied plan never executes').toBe(0);
    allowHealth({ status: 409, url: /\/ai\/plan\/[^/]+\/approve$/, why: 'approving lost to the denial on purpose' });
  }
  finish2();
});
