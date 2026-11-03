import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

// Regression guard: no /assurance workspace state may make the PAGE scroll sideways, and every
// table that is allowed to scroll sideways must do so inside its own focusable region.
//
// Found by running tests-e2e/assurance-lifecycle.spec.ts on the mobile project: the case-detail
// "Question" <select> was as wide as its longest option (~970px), which widened the layout
// viewport to 1001px and put a cookie banner and a table header over the "Record answer" button.
//
// Note: on a mobile browser window.innerWidth GROWS with the overflow (it was 1001, not 412), so
// the comparison is against the configured viewport width, not innerWidth.

const seedPath = process.env.ASSURANCE_E2E_SEED;
const apiBase = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || 'http://127.0.0.1:8001';

type Seed = {
  key_a: string;
  key_e: string;
  key_g: string;
  key_k: string;
  case_id: string;
  advisories: { mismatch: Record<string, unknown>; clear: Record<string, unknown> };
  supplier: { feed_path: string };
};

test.describe.configure({ mode: 'serial' });

test.describe('Assurance workspace — no page-level horizontal overflow', () => {
  let seed: Seed;
  let kCase = '';
  test.beforeAll(async ({ request }) => {
    test.skip(!seedPath, 'Set ASSURANCE_E2E_SEED (run scripts/e2e-local.sh) — not faking a fleet.');
    seed = JSON.parse(readFileSync(seedPath!, 'utf8'));
    const r = await request.post(`${apiBase}/v1/change/assess/advisory`, {
      headers: { 'X-API-Key': seed.key_k },
      // A distinct advisory id opens a case of its own, so this spec never depends on (or changes)
      // the case tests-e2e/assurance-lifecycle.spec.ts answers on the same account.
      data: { advisory: { ...seed.advisories.mismatch, advisory_id: 'ADV-E2E-LAYOUT' }, actor: 'e2e.layout.operator' },
    });
    expect(r.status()).toBe(200);
    kCase = (await r.json()).case.case_id;
  });

  async function enter(page: Page, key: string, query = '') {
    await page.goto(`/assurance${query}`);
    await page.getByLabel('API key').fill(key);
    await page.getByRole('button', { name: 'Refresh' }).click();
  }

  async function assertFits(page: Page, state: string) {
    const base = page.viewportSize()!.width;
    const widths = test.info().project.name === 'mobile-chromium' ? [base, 390, 360] : [base];
    for (const w of widths) {
      await page.setViewportSize({ width: w, height: page.viewportSize()!.height });
      const m = await page.evaluate((vw) => {
        const wide: string[] = [];
        for (const el of Array.from(document.body.querySelectorAll('*'))) {
          if (el.closest('.aw-scroll')) continue; // inside its own scroller
          const r = el.getBoundingClientRect();
          if (r.width > 0 && r.right > vw + 1) wide.push(`${el.tagName.toLowerCase()}.${(el as HTMLElement).className} right=${Math.round(r.right)}`);
        }
        return { sw: document.documentElement.scrollWidth, inner: window.innerWidth, wide: wide.slice(0, 5) };
      }, w);
      expect(m.sw, `${state} @${w}px: scrollWidth ${m.sw}, offenders ${JSON.stringify(m.wide)}`).toBeLessThanOrEqual(w);
      expect(m.inner, `${state} @${w}px: layout viewport grew to ${m.inner}`).toBeLessThanOrEqual(w);
    }
    // Every sideways scroller is reachable by keyboard and named.
    const scrollers = page.locator('.aw-scroll');
    for (let i = 0; i < (await scrollers.count()); i++) {
      const s = scrollers.nth(i);
      await expect(s, `${state}: .aw-scroll #${i} tabindex`).toHaveAttribute('tabindex', '0');
      await expect(s).toHaveAttribute('role', 'region');
      await expect(s).toHaveAttribute('aria-label', /\S/);
      expect(await s.evaluate((e) => getComputedStyle(e).overflowX)).toBe('auto');
    }
    await page.setViewportSize({ width: base, height: page.viewportSize()!.height });
  }

  test('signed-out start state', async ({ page }) => {
    await page.goto('/assurance');
    await assertFits(page, 'signed out');
  });

  test('fleet and cases of the seeded account', async ({ page }) => {
    await enter(page, seed.key_a);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('case-table')).toBeVisible();
    await assertFits(page, 'fleet + cases');
  });

  test('fleet that includes watch-only machines', async ({ page }) => {
    await enter(page, seed.key_e);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    await assertFits(page, 'fleet with watch-only machines');
  });

  test('case detail with its history table', async ({ page }) => {
    await enter(page, seed.key_a, `?case=${encodeURIComponent(seed.case_id)}`);
    await expect(page.getByTestId('case-detail')).toContainText(seed.case_id, { timeout: 15_000 });
    await assertFits(page, 'case detail (seed case)');
  });

  test('case detail with the human-question form (long question text)', async ({ page }) => {
    await enter(page, seed.key_k, `?case=${encodeURIComponent(kCase)}`);
    const detail = page.getByTestId('case-detail');
    await expect(detail).toContainText(kCase, { timeout: 15_000 });
    await expect(detail.getByLabel('Question')).toBeVisible();
    await assertFits(page, 'case detail (human question)');
    // The one control the lifecycle spec could not reach on a phone: it must be clickable.
    const record = detail.getByRole('button', { name: 'Record answer' });
    await record.scrollIntoViewIfNeeded();
    const box = (await record.boundingBox())!;
    expect(box.x + box.width).toBeLessThanOrEqual(page.viewportSize()!.width);
    const top = await page.evaluate(({ x, y }) => {
      const el = document.elementFromPoint(x, y);
      return el ? el.tagName + '.' + (el as HTMLElement).className : '';
    }, { x: box.x + box.width / 2, y: box.y + box.height / 2 });
    expect(top.toLowerCase()).toContain('button');
  });

  test('advisory read and fleet-impact result', async ({ page }) => {
    await enter(page, seed.key_g);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    const panel = page.locator('section#aw-advisories');
    await panel.getByLabel(/^Advisory or feed/).fill(JSON.stringify(seed.advisories.mismatch));
    await panel.getByRole('button', { name: 'Read advisory' }).click();
    await expect(panel.getByTestId('adv-provenance')).toBeVisible();
    await panel.getByRole('button', { name: /Check fleet impact/ }).click();
    await expect(panel.getByTestId('impact-verdict')).toBeVisible({ timeout: 10_000 });
    await assertFits(page, 'advisory impact');
  });

  test('supplier feed evaluation and pinned keys', async ({ page }) => {
    await enter(page, seed.key_g);
    await expect(page.getByTestId('fleet-table')).toBeVisible({ timeout: 15_000 });
    const panel = page.locator('section#aw-advisories');
    await panel.getByLabel('Choose an advisory or feed file').setInputFiles(seed.supplier.feed_path);
    await expect(panel.getByTestId('adv-record').first()).toBeVisible({ timeout: 10_000 });
    await panel.getByRole('button', { name: 'Evaluate under my pinned keys' }).click();
    await expect(panel.getByTestId('signed-result')).toBeVisible({ timeout: 15_000 });
    await assertFits(page, 'supplier feed trust');
  });
});
