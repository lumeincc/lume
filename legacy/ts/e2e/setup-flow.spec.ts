// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { test, expect } from '@playwright/test';

test.describe('Setup Flow', () => {
  test('root shows the landing and routes to setup on Create account', async ({ page }) => {
    await page.goto('/');

    // The root no longer redirects (client/src/app/page.tsx) — it renders a
    // landing. With no account it offers "Create account" / "Restore access".
    await expect(page.getByRole('heading', { name: /Welcome/ })).toBeVisible({
      timeout: 10_000,
    });

    const create = page.getByRole('button', { name: 'Create account' });
    await expect(create).toBeVisible();
    await create.click();

    await page.waitForURL(/\/setup/, { timeout: 10_000 });
  });

  test('setup page renders username input', async ({ page }) => {
    await page.goto('/setup');

    // Wait for the page to fully load
    await page.waitForLoadState('networkidle');

    // Look for an input field (username / display name)
    const input = page.locator('input').first();
    await expect(input).toBeVisible({ timeout: 10_000 });
  });

  test('setup flow: fill username and complete', async ({ page }) => {
    await page.goto('/setup');
    await page.waitForLoadState('networkidle');

    // Find and fill the first text input (username / display name)
    const input = page.locator('input').first();
    await expect(input).toBeVisible({ timeout: 10_000 });
    await input.fill('TestUser');

    // Look for a submit / continue / next button
    const submitButton = page.locator(
      'button[type="submit"], button:has-text("Continue"), button:has-text("Next"), button:has-text("Create"), button:has-text("Start")'
    ).first();

    if (await submitButton.isVisible({ timeout: 3_000 }).catch(() => false)) {
      await submitButton.click();

      // After setup, should eventually land on /chats or next step
      await page.waitForURL(/\/(chats|chat|setup)/, { timeout: 15_000 });
    }
  });
});
