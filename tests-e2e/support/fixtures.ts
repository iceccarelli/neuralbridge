import { test as base, expect, type Page } from '@playwright/test';

// Shared browser-health fixture. Every spec that imports `test` from here gets, for free and
// without copy-paste, an auto fixture that watches the page for the signals that used to be
// logged or ignored, and FAILS the test at teardown if any occurred:
//
//   - uncaught page errors (`pageerror`)
//   - console messages of type `error`
//   - failed first-party requests (`requestfailed`)
//   - first-party responses with status >= 400 (pages, scripts, styles, fonts, images, API calls)
//
// "First-party" = the site origin (baseURL) and the Assurance API origin
// (NEXT_PUBLIC_ASSURANCE_API_URL) and the NeuralBridge platform API origin (NEXT_PUBLIC_NEURALBRIDGE_API_URL, /ai).
// Third-party failures are not this suite's to judge.
//
// Expected noise is allow-listed PER TEST or per describe block with a written reason, never globally:
//
//   test.use({ healthAllow: [{ status: 409, url: /\/v1\/change\/cases\/[^/]+\/decision$/, why: 'the spec asserts the server refuses an early close' }] });
//
// An entry names the exact HTTP status and a URL pattern. It forgives that response AND the
// browser's own "Failed to load resource ... status of N" console line for the same URL, nothing
// else: a pageerror, a different status or any other console error still fails. An entry that
// matched nothing is itself reported, so stale entries cannot pile up.

// status 0 = the request never got a response (connection refused, reset): only for specs that stop or break the API on purpose.
export type HealthAllow = { status: number; url: RegExp; why: string };

const origins = (): string[] => {
  const out = new Set<string>();
  for (const v of [
    process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:3000',
    process.env.NEXT_PUBLIC_ASSURANCE_API_URL,
    process.env.NEXT_PUBLIC_NEURALBRIDGE_API_URL,
  ]) {
    try {
      if (v) out.add(new URL(v).origin);
    } catch {
      /* not a URL: ignore */
    }
  }
  return [...out];
};

/** Start watching `page`; call the returned function at the end of the test to assert. */
export function watchBrowserHealth(page: Page, baseURL: string | undefined, healthAllow: HealthAllow[] = []) {
  const first = new Set([...origins(), ...(baseURL ? [new URL(baseURL).origin] : [])]);
  const isFirstParty = (u: string) => {
    try {
      return first.has(new URL(u).origin);
    } catch {
      return false;
    }
  };
  type Problem = { text: string; url?: string; status?: number; console?: boolean };
  const problems: Problem[] = [];
  page.on('pageerror', (e) => problems.push({ text: `pageerror ${e.name} - ${e.message}` }));
  page.on('console', (m) => {
    if (m.type() !== 'error') return;
    const url = m.location().url || undefined;
    const code = /Failed to load resource: the server responded with a status of (\d+)/.exec(m.text())?.[1];
    const status = code ? Number(code) : /Failed to load resource: net::ERR_/.test(m.text()) ? 0 : undefined;
    problems.push({ text: `console error ${url ?? ''} ${m.text()}`.trim(), url, status, console: true });
  });
  page.on('requestfailed', (r) => {
    if (!isFirstParty(r.url())) return;
    const err = r.failure()?.errorText ?? 'failed';
    // Why ERR_ABORTED is not a failure: the browser cancels in-flight requests itself when a
    // navigation supersedes them (Next prefetches, RSC fetches, a test navigating away).
    // Every real server-side failure arrives as a response with a status, checked below.
    if (err === 'net::ERR_ABORTED') return;
    problems.push({ text: `requestfailed ${err} ${r.method()} ${r.url()}`, url: r.url(), status: 0 });
  });
  page.on('response', (r) => {
    if (r.status() >= 400 && isFirstParty(r.url())) {
      problems.push({ text: `http ${r.status()} ${r.request().method()} ${r.url()}`, url: r.url(), status: r.status() });
    }
  });
  return () => {
    const used = new Set<HealthAllow>();
    const left = problems.filter((p) => {
      if (p.status === undefined || p.url === undefined) return true;
      const hit = healthAllow.find((a) => a.status === p.status && a.url.test(p.url!));
      if (hit && !p.console) used.add(hit); // only a real response counts as the entry being used
      return !hit;
    });
    const stale = healthAllow.filter((a) => !used.has(a)).map((a) => `unused allow-list entry ${a.status} ${a.url} (${a.why})`);
    expect(left.map((p) => p.text), 'uncaught page errors / console errors / failed or 4xx-5xx first-party requests').toEqual([]);
    expect(stale, 'allow-list entries that matched nothing: delete them').toEqual([]);
  };
}

export const test = base.extend<{
  healthAllow: HealthAllow[];
  healthAllowList: HealthAllow[];
  allowHealth: (e: HealthAllow) => void;
  browserHealth: void;
}>({
  healthAllow: [[], { option: true }],
  // A fresh list per test: the describe-level option plus whatever the test adds.
  healthAllowList: async ({ healthAllow }, use) => use([...healthAllow]),
  // Per-test allow-list, called from inside the test that deliberately provokes the refusal:
  //   allowHealth({ status: 409, url: /\/decision$/, why: '...' });
  allowHealth: async ({ healthAllowList }, use) => use((e) => void healthAllowList.push(e)),
  browserHealth: [
    async ({ page, healthAllowList, baseURL }, use) => {
      const finish = watchBrowserHealth(page, baseURL, healthAllowList);
      await use();
      finish();
    },
    { auto: true },
  ],
});

export { expect };

/** No page-level horizontal scroll: the document is no wider than the viewport. */
export async function expectNoHorizontalOverflow(page: Page, label: string) {
  const m = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
  expect(m.sw, `${label}: horizontal overflow (scrollWidth ${m.sw} > clientWidth ${m.cw})`).toBeLessThanOrEqual(m.cw);
}
