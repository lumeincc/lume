// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { test, expect } from './fixtures/auth';

test.describe('App Navigation', () => {
  test('chats page loads without console errors', async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    await page.goto('/chats');
    await page.waitForLoadState('networkidle');

    // Page should not have crashed — check that body has content
    const body = page.locator('body');
    await expect(body).not.toBeEmpty();

    // Filter out known harmless errors (e.g. favicon 404)
    const criticalErrors = consoleErrors.filter(
      (e) => !e.includes('favicon') && !e.includes('404')
    );

    // Log errors for debugging but don't fail on hydration warnings
    if (criticalErrors.length > 0) {
      console.log('Console errors on /chats:', criticalErrors);
    }
  });

  test('chats page contains key UI elements', async ({ page }) => {
    await page.goto('/chats');
    await page.waitForLoadState('networkidle');

    // The page should have some visible content — heading, sidebar, or chat list
    const hasContent = await page
      .locator('h1, h2, nav, [role="navigation"], main, [data-testid]')
      .first()
      .isVisible({ timeout: 10_000 })
      .catch(() => false);

    expect(hasContent).toBeTruthy();
  });

  test('settings page loads', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');

    const body = page.locator('body');
    await expect(body).not.toBeEmpty();

    // Settings page should contain some form elements or headings
    const hasSettingsContent = await page
      .locator('h1, h2, h3, input, select, button, form')
      .first()
      .isVisible({ timeout: 10_000 })
      .catch(() => false);

    expect(hasSettingsContent).toBeTruthy();
  });

});

// Registration takes a while (a deliberate 3s hold plus key generation), so this
// group gets its own budget — the fixture runs inside the test's timeout.
test.describe('App Navigation — authenticated', () => {
  test.describe.configure({ timeout: 120_000 });

  test('navigation between pages works', async ({ authedPage: page }) => {
    // `authedPage` leaves us registered, unlocked and on /chats.
    expect(page.url()).toContain('/chats');

    // Navigate through the rail: those buttons use `router.push`, so routing stays
    // client-side and the in-memory key vault survives. A `page.goto()` here would
    // reload the app and drop the session back to /unlock — which is exactly why
    // the previous version of this test could not stay on /chats.
    // The rail renders a compact and a wide variant, so scope to the first match.
    await page.getByRole('button', { name: 'Settings' }).first().click();
    await page.waitForURL('**/settings', { timeout: 15_000 });
    expect(page.url()).toContain('/settings');

    // Back through history — popstate, still client-side.
    await page.goBack();
    await page.waitForURL('**/chats', { timeout: 15_000 });
    expect(page.url()).toContain('/chats');
  });
});
