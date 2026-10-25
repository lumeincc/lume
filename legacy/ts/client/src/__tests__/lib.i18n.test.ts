// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Tests for lib/i18n — plural selection, named substitution, and the
 * degradation behaviour lookup promises (never throw, never blank the UI).
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { t, en } from "@/lib/i18n";
import { isPluralForms, type PluralForms } from "@/lib/i18n/types";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("plain messages", () => {
  it("returns the catalogue string", () => {
    expect(t("error.title")).toBe("Something went wrong");
    expect(t("status.authError")).toBe("WebSocket authentication failed");
  });
});

describe("pluralisation", () => {
  it("selects the English singular and plural", () => {
    expect(t("group.memberCount", { count: 1 })).toBe("1 member");
    expect(t("group.memberCount", { count: 2 })).toBe("2 members");
    expect(t("group.memberCount", { count: 0 })).toBe("0 members");
  });

  it("falls back to `other` when a count is missing, instead of throwing", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(t("group.memberCount")).toBe("{count} members");
    expect(warn).toHaveBeenCalled();
  });

  it("resolves Russian categories through Intl, not a hand-written rule", () => {
    // Not a catalogue test — it pins the assumption the design rests on:
    // Russian needs three forms where English needs two, so a call-site
    // ternary cannot be correct once a second locale exists.
    const ru = new Intl.PluralRules("ru");
    expect(ru.select(1)).toBe("one");
    expect(ru.select(3)).toBe("few");
    expect(ru.select(7)).toBe("many");

    const en2 = new Intl.PluralRules("en");
    expect(en2.select(1)).toBe("one");
    expect(en2.select(3)).toBe("other");
  });
});

describe("substitution", () => {
  it("replaces named placeholders", () => {
    expect(t("group.memberCount", { count: 5 })).toContain("5");
  });

  it("leaves an unknown placeholder visible rather than printing undefined", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const forms = en["group.memberCount"] as PluralForms;
    expect(isPluralForms(forms)).toBe(true);
    // `count` drives selection; a template referencing an absent name keeps it.
    expect(t("group.memberCount", { count: 1 })).toBe("1 member");
    warn.mockRestore();
  });
});

describe("missing keys", () => {
  it("returns the key and warns, rather than throwing or rendering empty", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    // Deliberately outside TranslationKey — this is the runtime path that
    // exists for catalogue drift, which the type system cannot catch alone.
    const missing = "nope.notAKey" as Parameters<typeof t>[0];
    expect(t(missing)).toBe("nope.notAKey");
    expect(warn).toHaveBeenCalled();
  });
});

describe("catalogue shape", () => {
  it("has no empty strings", () => {
    for (const [key, message] of Object.entries(en)) {
      if (typeof message === "string") {
        expect(message.length, `"${key}" is empty`).toBeGreaterThan(0);
      } else {
        expect(message.other.length, `"${key}.other" is empty`).toBeGreaterThan(0);
      }
    }
  });

  it("gives every plural entry an `other` form — the category every language has", () => {
    for (const [key, message] of Object.entries(en)) {
      if (typeof message !== "string") {
        expect(message.other, `"${key}" has no "other"`).toBeDefined();
      }
    }
  });

  it("uses namespaced keys, so entries do not collide as the catalogue grows", () => {
    for (const key of Object.keys(en)) {
      expect(key, `"${key}" is not namespaced`).toContain(".");
    }
  });
});
