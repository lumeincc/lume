// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

// @vitest-environment jsdom
/**
 * Tests for lib/shortcuts.ts — combo normalisation, matching, and the guard
 * that keeps shortcuts from firing while the user is typing.
 */

import { describe, it, expect } from "vitest";
import {
  SHORTCUTS,
  eventToCombo,
  matchShortcut,
  formatCombo,
  isEditableTarget,
} from "@/lib/shortcuts";

function keyEvent(init: KeyboardEventInit): KeyboardEvent {
  return new KeyboardEvent("keydown", init);
}

describe("eventToCombo", () => {
  it("maps ctrl and meta to the same 'mod' token", () => {
    expect(eventToCombo(keyEvent({ key: "b", ctrlKey: true }))).toBe("mod+b");
    expect(eventToCombo(keyEvent({ key: "b", metaKey: true }))).toBe("mod+b");
  });

  it("lowercases letter keys", () => {
    expect(eventToCombo(keyEvent({ key: "B", ctrlKey: true }))).toBe("mod+b");
  });

  it("omits shift for printable keys, which already carry the shifted value", () => {
    expect(eventToCombo(keyEvent({ key: "?", shiftKey: true }))).toBe("?");
  });

  it("keeps shift for named keys, where it is not otherwise represented", () => {
    expect(eventToCombo(keyEvent({ key: "ArrowUp", shiftKey: true }))).toBe("shift+arrowup");
  });

  it("orders modifiers consistently", () => {
    expect(eventToCombo(keyEvent({ key: "k", ctrlKey: true, altKey: true }))).toBe("mod+alt+k");
  });
});

describe("matchShortcut", () => {
  it("resolves a registered combo to its command", () => {
    expect(matchShortcut(keyEvent({ key: ",", ctrlKey: true }))).toBe("openSettings");
    expect(matchShortcut(keyEvent({ key: "b", metaKey: true }))).toBe("toggleContactsPanel");
  });

  it("accepts either combo bound to the same command", () => {
    expect(matchShortcut(keyEvent({ key: "?", shiftKey: true }))).toBe("showHelp");
    expect(matchShortcut(keyEvent({ key: "/", ctrlKey: true }))).toBe("showHelp");
  });

  it("returns null for unbound keys", () => {
    expect(matchShortcut(keyEvent({ key: "b" }))).toBeNull();
    expect(matchShortcut(keyEvent({ key: "x", ctrlKey: true }))).toBeNull();
  });

  it("does not match a bare letter when the binding requires a modifier", () => {
    expect(matchShortcut(keyEvent({ key: "," }))).toBeNull();
  });
});

describe("isEditableTarget", () => {
  it("is true for form fields, so typing never triggers a command", () => {
    for (const tag of ["input", "textarea", "select"]) {
      expect(isEditableTarget(document.createElement(tag))).toBe(true);
    }
  });

  it("is true for contenteditable elements", () => {
    const div = document.createElement("div");
    div.contentEditable = "true";
    // jsdom does not derive isContentEditable from the attribute.
    Object.defineProperty(div, "isContentEditable", { value: true });
    expect(isEditableTarget(div)).toBe(true);
  });

  it("is false for ordinary elements and for a null target", () => {
    expect(isEditableTarget(document.createElement("div"))).toBe(false);
    expect(isEditableTarget(null)).toBe(false);
  });
});

describe("formatCombo", () => {
  it("renders the modifier and key as separate tokens", () => {
    const formatted = formatCombo("mod+b");
    expect(formatted).toMatch(/^(Ctrl|⌘) B$/);
  });
});

describe("SHORTCUTS registry", () => {
  it("has no combo bound to two different commands", () => {
    const seen = new Map<string, string>();

    for (const binding of SHORTCUTS) {
      for (const combo of binding.combos) {
        const existing = seen.get(combo);
        expect(existing, `"${combo}" is bound to both ${existing} and ${binding.id}`).toBeUndefined();
        seen.set(combo, binding.id);
      }
    }
  });

  it("gives every command a description for the help dialog", () => {
    for (const binding of SHORTCUTS) {
      expect(binding.description.length).toBeGreaterThan(0);
      expect(binding.combos.length).toBeGreaterThan(0);
    }
  });
});
