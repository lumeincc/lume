// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260721-019 — a hidden chat (locked) must not write its contact's name to
 * the OS notification layer, and must not play a sound. notifyIncomingMessage(null)
 * is the generic, silent path; a normal chat still names the sender.
 */

// @vitest-environment jsdom

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { notifyIncomingMessage } from '@/lib/notifications';

let ctorArgs: Array<{ title: string; opts: NotificationOptions }>;

beforeEach(() => {
  ctorArgs = [];
  class MockNotification {
    static permission = 'granted';
    static requestPermission = vi.fn();
    onclick: (() => void) | null = null;
    close = vi.fn();
    constructor(
      public title: string,
      public opts: NotificationOptions,
    ) {
      ctorArgs.push({ title, opts });
    }
  }
  vi.stubGlobal('Notification', MockNotification);
  vi.spyOn(document, 'hasFocus').mockReturnValue(false);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('notifyIncomingMessage', () => {
  it('names the sender and is audible for a normal chat', () => {
    notifyIncomingMessage('alice');
    expect(ctorArgs).toHaveLength(1);
    expect(ctorArgs[0]!.opts.body).toBe('New message from alice');
    expect(ctorArgs[0]!.opts.silent).toBe(false);
    expect(ctorArgs[0]!.opts.tag).toBe('lume-msg-alice');
  });

  it('is generic and silent for a hidden+locked chat (null)', () => {
    notifyIncomingMessage(null);
    expect(ctorArgs).toHaveLength(1);
    expect(ctorArgs[0]!.opts.body).toBe('You have a new message');
    expect(ctorArgs[0]!.opts.body).not.toContain('alice');
    expect(ctorArgs[0]!.opts.silent).toBe(true);
    expect(ctorArgs[0]!.opts.tag).toBe('lume-msg'); // no per-sender grouping
  });

  it('does not fire when the window is focused', () => {
    (document.hasFocus as unknown as ReturnType<typeof vi.fn>).mockReturnValue(true);
    notifyIncomingMessage('alice');
    expect(ctorArgs).toHaveLength(0);
  });
});
