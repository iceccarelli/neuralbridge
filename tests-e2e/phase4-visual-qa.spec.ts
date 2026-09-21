import { test, devices } from '@playwright/test';
import fs from 'fs';
import path from 'path';

// Phase 4: Tesla-grade UI/UX consistency pass — visual QA screenshots.
// Not an assertion suite (see ai.spec.ts / ai-entitlement.spec.ts / phase3
// for those); this walks every surface named in the phase-4 design pass at
// desktop (1440x900) and mobile (Pixel 7, ~412x915) and saves a full-page
// screenshot to reports/demo/phase4/ for human review. Run explicitly:
//
//   npx playwright test tests-e2e/phase4-visual-qa.spec.ts
//
// against a running `npm run dev` (or build+start) server. No live
// NeuralBridge/Assurance API is required — every surface here renders its
// own honest "not configured" state when NEXT_PUBLIC_*_API_URL is unset,
// which is itself part of what this pass is checking.

const OUT_DIR = path.join(__dirname, '..', 'reports', 'demo', 'phase4');
fs.mkdirSync(OUT_DIR, { recursive: true });

const SURFACES: { name: string; path: string; waitFor?: string }[] = [
  { name: 'homepage-pricing', path: '/#pricing', waitFor: '#pricing' },
  { name: 'console', path: '/console', waitFor: '.console-shell' },
  { name: 'ai', path: '/ai', waitFor: '.ai-shell' },
  { name: 'checkout-success', path: '/checkout/success' },
  { name: 'connectors-mcp', path: '/connectors/mcp' },
  { name: 'connectors-cursor', path: '/connectors/cursor' },
  { name: 'status', path: '/status' },
  { name: 'contact', path: '/contact' },
  { name: 'developers', path: '/developers' },
  { name: 'cli', path: '/cli' },
  { name: 'applications', path: '/applications' },
];

const VIEWPORTS: { label: string; width: number; height: number; userAgent?: string; isMobile?: boolean; hasTouch?: boolean }[] = [
  { label: 'desktop', width: 1440, height: 900 },
  {
    label: 'mobile',
    width: devices['Pixel 7'].viewport.width,
    height: devices['Pixel 7'].viewport.height,
    userAgent: devices['Pixel 7'].userAgent,
    isMobile: devices['Pixel 7'].isMobile,
    hasTouch: devices['Pixel 7'].hasTouch,
  },
];

for (const surface of SURFACES) {
  for (const vp of VIEWPORTS) {
    test(`${surface.name} — ${vp.label}`, async ({ browser }) => {
      const context = await browser.newContext({
        viewport: { width: vp.width, height: vp.height },
        userAgent: vp.userAgent,
        isMobile: vp.isMobile,
        hasTouch: vp.hasTouch,
      });
      const page = await context.newPage();
      const errors: string[] = [];
      page.on('pageerror', (err) => errors.push(String(err)));

      await page.goto(surface.path, { waitUntil: 'networkidle' });
      if (surface.waitFor) {
        await page.locator(surface.waitFor).first().waitFor({ state: 'visible', timeout: 10_000 }).catch(() => {});
      }
      // Let any crossfade/entrance transitions settle.
      await page.waitForTimeout(300);

      // No horizontal overflow at this viewport width.
      const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
      const clientWidth = await page.evaluate(() => document.documentElement.clientWidth);
      if (scrollWidth > clientWidth + 1) {
        console.warn(`[phase4] ${surface.name} (${vp.label}): horizontal overflow — scrollWidth=${scrollWidth} clientWidth=${clientWidth}`);
      }
      if (errors.length) {
        console.warn(`[phase4] ${surface.name} (${vp.label}): page errors — ${errors.join(' | ')}`);
      }

      await page.screenshot({
        path: path.join(OUT_DIR, `${surface.name}-${vp.label}.png`),
        fullPage: true,
      });

      await context.close();
    });
  }
}
