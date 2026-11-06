import { defineConfig, devices } from '@playwright/test';

// Browser tests, desktop + mobile. The CI gate is scripts/e2e-local.sh (job "Browser tests (Playwright)"
// in .github/workflows/ci.yml): it starts an isolated Assurance API and a production `next start`
// and runs the default spec set. Specs that need other services (the /ai Postgres control plane,
// a paid test key) skip with a stated reason when those are absent.
//
// phase4-visual-qa.spec.ts REWRITES the committed screenshots under reports/demo/phase4/, so it is
// excluded unless E2E_VISUAL_QA=1 (restore afterwards by checking reports/ out of the index).
export default defineConfig({
  testDir: './tests-e2e',
  timeout: 30_000,
  fullyParallel: false,
  // A committed test.only must never silently shrink the CI gate.
  forbidOnly: !!process.env.CI,
  retries: 0,
  testIgnore: process.env.E2E_VISUAL_QA === '1' ? [] : ['**/phase4-visual-qa.spec.ts'],
  reporter: process.env.CI ? [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]] : [['list']],
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:3000',
    trace: 'retain-on-failure',
    // This environment ships a pre-installed Chromium pinned to a specific
    // build; when the installed @playwright/test version expects a
    // different revision, point at it explicitly rather than downloading.
    launchOptions: process.env.PLAYWRIGHT_CHROMIUM_PATH
      ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH }
      : undefined,
  },
  projects: [
    { name: 'desktop-chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile-chromium', use: { ...devices['Pixel 7'] } },
  ],
});
