// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * No element id may appear twice in a rendered page.
 *
 * The messenger renders a mobile tree and a desktop tree and hides one with CSS
 * (`md:hidden` / `hidden md:block`) rather than rendering conditionally. Both are
 * in the DOM at all times, so every component below that split is mounted twice
 * — and any hard-coded `id` inside it exists twice in the document.
 *
 * That is not cosmetic. `<label htmlFor>` resolves to the *first* match, so a
 * label can end up pointing at the copy that is currently hidden: clicking it
 * focuses nothing the user can see, and a screen reader announces a control the
 * user cannot reach. Chrome reports it as "Duplicate form field id in the same
 * form" because its autofill heuristics give up on the field.
 *
 * The fix is `useId()` in every component that can be mounted more than once.
 * This spec is the guard, and it has to be end-to-end: the duplication only
 * exists once both trees are rendered together, which no unit test of an
 * individual component can see.
 */

import { test, expect } from './fixtures/auth';
import { test as base } from '@playwright/test';
import type { Page } from '@playwright/test';

/** Ids appearing more than once, as `id ×count`. Empty is the passing state. */
async function duplicateIds(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const counts = new Map<string, number>();
    for (const el of document.querySelectorAll('[id]')) {
      counts.set(el.id, (counts.get(el.id) ?? 0) + 1);
    }
    return [...counts.entries()]
      .filter(([, n]) => n > 1)
      .map(([id, n]) => `${id} ×${n}`)
      .sort();
  });
}

/** Total ids on the page — a page with none would pass the check vacuously. */
async function idCount(page: Page): Promise<number> {
  return page.evaluate(() => document.querySelectorAll('[id]').length);
}

base.describe('unauthenticated pages have unique ids', () => {
  for (const path of ['/setup', '/recover']) {
    base(`${path} renders no duplicate id`, async ({ page }) => {
      await page.goto(path);
      await page.waitForLoadState('networkidle');
      expect(await idCount(page)).toBeGreaterThan(0);
      expect(await duplicateIds(page)).toEqual([]);
    });
  }
});

test.describe('the messenger renders no duplicate id', () => {
  test('/chats, where the mobile and desktop trees are both mounted', async ({
    authedPage,
  }) => {
    await authedPage.waitForLoadState('networkidle');

    // Check we are on the messenger before checking the messenger. Counting ids
    // is not enough on its own: the unlock screen has ids too, so this test
    // reported ok while the browser was sitting on /unlock after a lost
    // session — a green result about a page it never looked at. A test that
    // passes on the wrong page is worse than one that fails, because it is
    // counted as coverage.
    // `toHaveURL` retries; reading `.url()` is a snapshot and races the redirect
    // it is meant to catch.
    await expect(authedPage).toHaveURL(/\/chats$/);

    // Filter on visibility *before* taking the first match. This page mounts the
    // mobile and desktop trees at once — the very duplication this file exists
    // to check — so `New chat` matches twice, and `.first()` can land on the
    // copy that is correctly hidden at this viewport.
    await expect(
      authedPage.getByRole('button', { name: 'New chat' }).filter({ visible: true }).first()
    ).toBeVisible({ timeout: 15_000 });

    expect(await idCount(authedPage)).toBeGreaterThan(0);
    expect(await duplicateIds(authedPage)).toEqual([]);
  });
});
