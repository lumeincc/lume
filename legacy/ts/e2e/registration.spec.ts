// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * E2E test: full registration flow.
 *
 * Current flow (client/src/app/setup/page.tsx):
 *   landing -> username -> PIN -> generate -> save-seed (recovery key) -> complete -> /chats
 *
 * Rewritten for SEC-20260721-031: the previous version walked
 * landing -> backup phrase -> verify words -> username -> PIN, which is the
 * pre-rework order, expected a "Verify Phrase" step that no longer exists, and
 * used a 4-digit PIN that is now below the SEC-20260721-020 minimum.
 *
 * Requires: client dev server on :3000, server on :3001 (both with clean/test DB).
 */

import { test, expect } from '@playwright/test';

test.describe('Registration flow', () => {
  test('new user can register and land on chats page', async ({ page }) => {
    // Registration deliberately pauses: a 3s hold before "I saved it" unlocks and
    // a ~1.8s beat before the redirect, plus key generation.
    test.setTimeout(90_000);

    // 1. Landing — the root renders a landing; it does not redirect.
    await page.goto('/');
    await page.getByRole('button', { name: 'Create account' }).click();
    await page.waitForURL('**/setup');

    // 2. Username step
    await expect(
      page.getByRole('heading', { name: 'Create your account' }),
    ).toBeVisible({ timeout: 10_000 });

    const uniqueUsername = `e2e_test_${Date.now().toString(36)}`;
    await page.locator('#setup-username').fill(uniqueUsername);

    const usernameContinue = page.getByRole('button', { name: 'Continue' });
    await expect(usernameContinue).toBeEnabled({ timeout: 10_000 });
    await usernameContinue.click();

    // 3. PIN step — the unlock secret is now a passphrase of at least 8 characters
    await expect(page.getByRole('heading', { name: 'Set a PIN' })).toBeVisible({
      timeout: 10_000,
    });

    const passphrase = 'e2e-pass-1234';
    await page.locator('#setup-pin').fill(passphrase);
    await page.locator('#setup-pin-confirm').fill(passphrase);
    await page.getByRole('button', { name: 'Continue' }).click();

    // 4. Recovery key — the "generate" step auto-advances into "save-seed"
    await expect(
      page.getByRole('heading', { name: 'Save your recovery key' }),
    ).toBeVisible({ timeout: 30_000 });

    // The words grid is the one directly under the heading (mt-8 grid-cols-2);
    // each cell is "<index>. <word>", so the word is the last span.
    const wordElements = page.locator('div.mt-8.grid-cols-2 > div > span:last-child');
    await expect(wordElements.first()).toBeVisible({ timeout: 10_000 });

    const wordCount = await wordElements.count();
    const mnemonicWords: string[] = [];
    for (let i = 0; i < wordCount; i++) {
      const text = await wordElements.nth(i).textContent();
      mnemonicWords.push(text?.trim() || '');
    }
    expect(mnemonicWords.length).toBeGreaterThanOrEqual(12);
    expect(mnemonicWords.every((w) => w.length > 0)).toBe(true);

    // "I saved it" is held disabled for 3s so the phrase is actually read.
    const savedBtn = page.getByRole('button', { name: 'I saved it' });
    await expect(savedBtn).toBeEnabled({ timeout: 15_000 });
    await savedBtn.click();

    // 5. Completion, then the redirect to /chats
    await expect(page.getByRole('heading', { name: 'Account created' })).toBeVisible({
      timeout: 10_000,
    });
    await page.waitForURL('**/chats', { timeout: 20_000 });
    expect(page.url()).toContain('/chats');
  });
});

test.describe('Landing page', () => {
  test('shows loading spinner then content', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle', { timeout: 10_000 });
    // Page should not be blank
    const body = page.locator('body');
    await expect(body).not.toBeEmpty();
  });
});
