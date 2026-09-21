import { defineConfig, devices } from '@playwright/test';

// Smoke coverage for the /ai vertical slice — desktop + mobile. Requires the
// Next dev server AND the NeuralBridge API (with NEURALBRIDGE_AI_PG_* set)
// both running — see docs/ai-local-setup.md. Not wired into `npm run dev`;
// run explicitly with `npx playwright test`.
export default defineConfig({
  testDir: './tests-e2e',
  timeout: 30_000,
  fullyParallel: false,
  reporter: [['list']],
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
