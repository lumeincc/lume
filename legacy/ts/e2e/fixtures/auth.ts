// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Auth fixture for e2e specs that need an authenticated session.
 *
 * There is no `storageState` shortcut for LUME: identity keys live in IndexedDB
 * (which Playwright's storageState does not capture) and the master key lives
 * only in an in-memory vault, so any full page load drops the session back to
 * /unlock. The session therefore has to be created inside the test's own browser
 * context, and navigation afterwards must stay client-side (rail buttons use
 * `router.push`; `page.goto()` would reload and lose the vault).
 *
 * Added for SEC-20260721-031 — `app-navigation.spec.ts` drove /chats with no
 * session and, under `fullyParallel: true`, could not inherit one from another
 * spec.
 */

import { test as base, expect, type Page } from '@playwright/test';

/**
 * Registers a fresh account through the UI. Leaves the page on /chats with the
 * key vault unlocked. Returns the username it created.
 */
export async function registerAccount(page: Page): Promise<string> {
  const username = `e2e_nav_${Date.now().toString(36)}`;
  const passphrase = 'e2e-pass-1234'; // >= MIN_PIN_LENGTH (SEC-20260721-020)

  await page.goto('/');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.waitForURL('**/setup');

  await expect(page.getByRole('heading', { name: 'Create your account' })).toBeVisible({
    timeout: 10_000,
  });
  await page.locator('#setup-username').fill(username);
  const usernameContinue = page.getByRole('button', { name: 'Continue' });
  await expect(usernameContinue).toBeEnabled({ timeout: 10_000 });
  await usernameContinue.click();

  await expect(page.getByRole('heading', { name: 'Set a PIN' })).toBeVisible({
    timeout: 10_000,
  });
  await page.locator('#setup-pin').fill(passphrase);
  await page.locator('#setup-pin-confirm').fill(passphrase);
  await page.getByRole('button', { name: 'Continue' }).click();

  // "generate" auto-advances into "save-seed"; the confirm button is held for 3s.
  await expect(page.getByRole('heading', { name: 'Save your recovery key' })).toBeVisible({
    timeout: 30_000,
  });
  const savedBtn = page.getByRole('button', { name: 'I saved it' });
  await expect(savedBtn).toBeEnabled({ timeout: 15_000 });
  await savedBtn.click();

  await page.waitForURL('**/chats', { timeout: 20_000 });
  return username;
}

/**
 * `authedPage` — a page already registered and sitting on /chats. Lazy: specs
 * that do not request it pay nothing.
 */
export const test = base.extend<{ authedPage: Page }>({
  authedPage: async ({ page }, use) => {
    await registerAccount(page);
    await use(page);
  },
});

export { expect };
