// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Opening a chat is state, not navigation.
 *
 * It used to push `/chat/[id]`, whose page re-declared the whole dashboard —
 * left rail, chat list, right rail, shell — so switching conversations tore
 * down and rebuilt every panel on screen, including the list you had just
 * clicked in.
 *
 * A unit test cannot see that: both pages rendered correct markup, and the
 * defect was that there were two of them. What is pinned here is what a reader
 * would notice — the address bar never leaves `/chats`, and state living in the
 * shell survives a switch.
 *
 * Three accounts, because two chats are the minimum needed to switch *between*.
 *
 * The surviving `/chat/[id]` route is covered by `chatDeepLink.route.test.tsx`
 * rather than here: the App Router ignores a hand-rolled `pushState`, and a real
 * navigation reloads the page, which drops the in-memory key vault and lands on
 * `/unlock` — correct behaviour, and nothing to do with what this file is about.
 */

import { test, expect, type Page, type Browser } from '@playwright/test';
import { registerAccount } from './fixtures/auth';

/** A fresh browser context per account: identity keys live in IndexedDB. */
async function newAccount(browser: Browser): Promise<{ page: Page; username: string }> {
  const context = await browser.newContext();
  const page = await context.newPage();
  const username = await registerAccount(page);
  return { page, username };
}

/** Starts a chat with `username` from the chats page, the way a reader would. */
async function addContact(page: Page, username: string): Promise<void> {
  await visible(page.getByRole('button', { name: 'New chat' })).click();
  const field = visible(page.getByRole('textbox', { name: 'Recipient username' }));
  await field.waitFor({ state: 'visible', timeout: 10_000 });
  await field.fill(username);
  await visible(page.getByRole('button', { name: 'Start chat' })).click();
  await expect(chatRow(page, username)).toBeVisible({ timeout: 15_000 });
}

/**
 * The messenger renders a mobile tree and a desktop tree at the same time and
 * hides one with CSS, so every control below that split genuinely exists twice.
 * `.first()` alone picks whichever comes first in the DOM — the hidden one at
 * this viewport — so these filter on visibility and then take the survivor.
 */
function visible(locator: ReturnType<Page['locator']>) {
  return locator.filter({ visible: true }).first();
}

/** The row for one contact in the chat list. */
function chatRow(page: Page, username: string) {
  return visible(page.getByRole('button').filter({ hasText: `@${username}` }));
}

/** The open conversation's header — how you tell which chat you are looking at. */
function openConversationWith(page: Page, username: string) {
  return visible(page.locator('header').filter({ hasText: `@${username}` }));
}

test.describe('Switching chats', () => {
  // Three registrations in one test, and each one derives a master key with
  // 600,000 PBKDF2 iterations and holds the recovery-phrase button for three
  // seconds on purpose. The default 30s is for a test that drives one screen.
  test.describe.configure({ timeout: 180_000 });

  test('stays on /chats, and does not reset the shell around it', async ({ browser }) => {
    const alice = await newAccount(browser);
    const bob = await newAccount(browser);
    const carol = await newAccount(browser);

    try {
      await addContact(alice.page, bob.username);
      // Checked here, before the second contact, because adding one opens the
      // conversation — and under the old architecture that was a navigation to
      // `/chat/<id>`. Asserting it this early is what makes a regression fail
      // with "expected /chats, got /chat/…" instead of a timeout twenty steps
      // later that says nothing about the cause.
      await expect(alice.page).toHaveURL(/\/chats$/);

      await addContact(alice.page, carol.username);
      await expect(alice.page).toHaveURL(/\/chats$/);

      // Something owned by the shell rather than by either conversation. Under
      // the old route change this was wiped, because the page holding it was
      // unmounted to render the chat.
      const search = visible(alice.page.getByRole('textbox', { name: 'Search chats' }));
      await search.fill('e2e');

      await chatRow(alice.page, bob.username).click();
      await expect(openConversationWith(alice.page, bob.username)).toBeVisible();
      await expect(alice.page).toHaveURL(/\/chats$/);

      await chatRow(alice.page, carol.username).click();
      await expect(openConversationWith(alice.page, carol.username)).toBeVisible();
      await expect(openConversationWith(alice.page, bob.username)).toHaveCount(0);
      await expect(alice.page).toHaveURL(/\/chats$/);

      // The switch happened without the list being rebuilt.
      await expect(search).toHaveValue('e2e');
    } finally {
      await alice.page.context().close();
      await bob.page.context().close();
      await carol.page.context().close();
    }
  });

});
