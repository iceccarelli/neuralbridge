import { expect, test } from '@playwright/test';

// Header / navigation accessibility (WCAG 2.2 AA): modal semantics, focus return, inert background,
// disclosure (not trap) behaviour, lazy search, contact-form errors and 320px reflow. Runs against a
// production build (`next build && next start`); no API is needed.

test.describe('mobile drawer', () => {
  test.beforeEach(({}, info) => test.skip(!info.project.name.startsWith('mobile'), 'drawer is the mobile navigation'));

  test('is a modal dialog, makes the page inert, and returns focus on Escape', async ({ page }) => {
    await page.goto('/');
    const hamburger = page.locator('.hamburger');
    await expect(hamburger).toHaveAttribute('aria-expanded', 'false');
    await expect(hamburger).toHaveAttribute('aria-controls', 'mobile-menu');
    await expect(page.locator('#mobile-menu')).toHaveAttribute('inert', '');

    await hamburger.focus();
    await page.keyboard.press('Enter');
    const drawer = page.locator('#mobile-menu');
    await expect(hamburger).toHaveAttribute('aria-expanded', 'true');
    await expect(drawer).toHaveAttribute('role', 'dialog');
    await expect(drawer).toHaveAttribute('aria-modal', 'true');
    await expect(page.locator('main')).toHaveAttribute('inert', '');
    expect(await page.evaluate(() => !!document.activeElement?.closest('#mobile-menu'))).toBe(true);

    // Drilling in must not drop focus to <body>.
    await drawer.locator('.mobile-drill-item', { hasText: 'Resources' }).click();
    expect(await page.evaluate(() => !!document.activeElement?.closest('#mobile-menu'))).toBe(true);

    await page.keyboard.press('Escape');
    await expect(hamburger).toBeFocused();
    await expect(page.locator('main')).not.toHaveAttribute('inert', '');
  });

  test('primary controls are at least 44x44', async ({ page }) => {
    await page.goto('/');
    for (const sel of ['.hamburger', '.icon-button']) {
      const box = await page.locator(sel).boundingBox();
      expect(box!.width, sel).toBeGreaterThanOrEqual(44);
      expect(box!.height, sel).toBeGreaterThanOrEqual(44);
    }
  });
});

test.describe('desktop mega menu', () => {
  test.beforeEach(({}, info) => test.skip(!info.project.name.startsWith('desktop'), 'mega menus are the desktop navigation'));

  test('is a disclosure: controlled, Escape returns focus, Tab out closes it', async ({ page }) => {
    await page.goto('/');
    const products = page.locator('.topbar-nav button', { hasText: 'Products' });
    await expect(products).not.toHaveAttribute('aria-haspopup', /.*/);
    await expect(products).toHaveAttribute('aria-controls', 'mega-products');
    await expect(page.locator('#mega-products')).toHaveCount(1);

    await products.focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#mega-products.is-open')).toHaveCount(1);
    await page.keyboard.press('Escape');
    await expect(products).toBeFocused();

    await products.click();
    for (let i = 0; i < 80 && (await page.locator('#mega-products.is-open').count()) > 0; i++) await page.keyboard.press('Tab');
    await expect(page.locator('#mega-products.is-open')).toHaveCount(0);
  });

  test('closed mega panels contribute no Tab stops (no invisible focus)', async ({ page }) => {
    await page.goto('/');
    let inClosed = 0;
    for (let i = 0; i < 40; i++) {
      await page.keyboard.press('Tab');
      if (await page.evaluate(() => !!document.activeElement?.closest('.mega-panel:not(.is-open)'))) inClosed++;
    }
    expect(inClosed).toBe(0);
  });

  test('search loads on first open and returns focus on Escape', async ({ page }) => {
    const scripts: string[] = [];
    page.on('response', (r) => r.request().resourceType() === 'script' && scripts.push(r.url()));
    await page.goto('/', { waitUntil: 'networkidle' });
    const before = scripts.length;
    await page.locator('.icon-button').click();
    await page.waitForSelector('.search-overlay');
    expect(scripts.length).toBeGreaterThan(before);
    await page.keyboard.press('Escape');
    await expect(page.locator('.icon-button')).toBeFocused();
  });
});

test('skip link moves focus to main', async ({ page }) => {
  await page.goto('/');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Enter');
  expect(await page.evaluate(() => document.activeElement?.id)).toBe('top');
});

test('contact form reports every problem, announces it, and focuses the first', async ({ page }) => {
  await page.goto('/contact');
  const submit = page.locator('form.contact-form button[type=submit]');
  await expect(submit).toBeEnabled();
  await submit.click();
  await expect(page.locator('.contact-form-errors')).toContainText('3 fields need attention');
  await expect(page.locator('#contact-name')).toBeFocused();
  await expect(page.locator('#contact-name')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#contact-name')).toHaveAttribute('aria-describedby', 'contact-name-error');
  await expect(page.locator('#contact-email')).toHaveAttribute('autocomplete', 'email');
});

test('no horizontal scroll at 320px on key routes', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 640 });
  for (const route of ['/', '/developers', '/contact', '/verify']) {
    await page.goto(route);
    expect(await page.evaluate(() => document.documentElement.scrollWidth), route).toBeLessThanOrEqual(320);
  }
});
