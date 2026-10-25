// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * The per-contact lock that keeps ratchet session mutations from overlapping.
 *
 * It existed before as a private helper inside useMessengerSync, which meant only
 * the receive path used it; the send path in the chat screen read and wrote the
 * same sessions with nothing holding them apart. These tests pin the properties
 * both paths now depend on.
 */

import { describe, it, expect } from "vitest";
import { withSenderLock } from "@/lib/sessionLock";

/** Model of the read-advance-write cycle a ratchet operation performs. */
function makeSession() {
  let stored = 0;
  return {
    read: () => stored,
    write: (value: number) => {
      stored = value;
    },
    get value() {
      return stored;
    },
  };
}

describe("withSenderLock", () => {
  it("runs operations on one contact strictly one at a time", async () => {
    let active = 0;
    let maxActive = 0;

    const task = async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise((resolve) => setTimeout(resolve, 5));
      active--;
    };

    await Promise.all([
      withSenderLock("contact-a", task),
      withSenderLock("contact-a", task),
      withSenderLock("contact-a", task),
    ]);

    expect(maxActive).toBe(1);
  });

  it("stops a concurrent operation from discarding another's session advance", async () => {
    const session = makeSession();

    // Each operation reads the session, does async work, then writes it back —
    // the shape of both sending and receiving a message.
    const advance = async () => {
      const current = session.read();
      await new Promise((resolve) => setTimeout(resolve, 5));
      session.write(current + 1);
    };

    await Promise.all([
      withSenderLock("contact-a", advance),
      withSenderLock("contact-a", advance),
    ]);

    // Unlocked, both read 0 and both wrote 1: one advance is lost, which on a
    // real session means a message the recipient can never open.
    expect(session.value).toBe(2);
  });

  it("lets different contacts proceed in parallel", async () => {
    let active = 0;
    let maxActive = 0;

    const task = async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise((resolve) => setTimeout(resolve, 5));
      active--;
    };

    await Promise.all([
      withSenderLock("contact-a", task),
      withSenderLock("contact-b", task),
    ]);

    expect(maxActive).toBe(2);
  });

  it("keeps serving a contact after one operation throws", async () => {
    const failing = withSenderLock("contact-c", async () => {
      throw new Error("send failed");
    });
    await expect(failing).rejects.toThrow("send failed");

    // A failed send must not stop the next message on that conversation.
    await expect(
      withSenderLock("contact-c", async () => "ok"),
    ).resolves.toBe("ok");
  });

  it("propagates the result and the error to the caller", async () => {
    await expect(withSenderLock("contact-d", async () => 42)).resolves.toBe(42);
    await expect(
      withSenderLock("contact-d", async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
  });
});

describe("cross-tab serialisation", () => {
  it("uses Web Locks when the platform provides them", async () => {
    // The point of SEC-20260805-003: tabs of one origin share the store, so a
    // module-scoped promise chain leaves the race reachable between them. Only
    // navigator.locks serialises across contexts.
    const requested: string[] = [];
    const real = navigator.locks;
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: {
        request: (name: string, fn: () => Promise<unknown>) => {
          requested.push(name);
          return fn();
        },
      },
    });

    try {
      await withSenderLock("contact-x", async () => "done");
    } finally {
      Object.defineProperty(navigator, "locks", { configurable: true, value: real });
    }

    // Keyed per contact, not one global lock — otherwise every conversation
    // would queue behind the slowest network call in any other conversation.
    expect(requested).toEqual(["lume-ratchet-contact-x"]);
  });

  it("still serialises when Web Locks is unavailable", async () => {
    const real = navigator.locks;
    Object.defineProperty(navigator, "locks", { configurable: true, value: undefined });

    let active = 0;
    let maxActive = 0;
    const task = async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise((r) => setTimeout(r, 5));
      active--;
    };

    try {
      await Promise.all([
        withSenderLock("contact-y", task),
        withSenderLock("contact-y", task),
        withSenderLock("contact-y", task),
      ]);
    } finally {
      Object.defineProperty(navigator, "locks", { configurable: true, value: real });
    }

    expect(maxActive).toBe(1);
  });
});
