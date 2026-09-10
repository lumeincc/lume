// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

// @vitest-environment jsdom
/**
 * The locale must start identical on the server and in the first client render.
 *
 * It used to be resolved at module scope, so the client bundle resolved the
 * browser's language while the server had already rendered English. Every `t()`
 * disagreed across the boundary, React found a text mismatch and threw away the
 * whole server-rendered tree to rebuild it — the React #418 that sat in the
 * console on every single load.
 *
 * Nothing about that failure is visible in a unit test of `t()` alone: both
 * sides are individually correct, and only their disagreement is the bug. So
 * what is pinned here is the property that prevents it — the module's starting
 * locale does not depend on the environment — plus the detection that was split
 * out to make that possible.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

/**
 * The environment is made Russian *before* the module under test is imported.
 *
 * Without this the test proves nothing: jsdom reports `en-US`, so the old
 * module-scope detection resolved to English too and the assertions below
 * passed against the very code they exist to reject. Checked by reverting the
 * fix — with this block the first case fails, without it, it does not.
 */
vi.hoisted(() => {
  Object.defineProperty(globalThis.navigator, "language", {
    value: "ru-RU",
    configurable: true,
  });
  globalThis.localStorage?.setItem("lume:locale", "ru");
});

import { getLocale, setLocale, detectLocale, DEFAULT_LOCALE, t } from "@/lib/i18n";

const STORAGE_KEY = "lume:locale";

beforeEach(() => {
  // Not cleared before the module-load block below: that block asserts on state
  // captured at import time, which no amount of later clearing can change.
});

afterEach(() => {
  setLocale(DEFAULT_LOCALE);
  window.localStorage.clear();
});

describe("locale at module load", () => {
  it("starts at the default, whatever the browser says", () => {
    // The module has already been imported by this point — exactly as it would
    // be during hydration, and after jsdom has provided a navigator. If the
    // starting value tracked the environment, this is where it would show.
    expect(getLocale()).toBe(DEFAULT_LOCALE);
  });

  it("renders default-language copy before anything applies a locale", () => {
    // This is the string the server would have sent. The first client render
    // has to produce the same one or React discards the tree.
    expect(t("auth.login")).toBe("Log in");
  });
});

describe("detectLocale", () => {
  it("prefers an explicit stored choice", () => {
    window.localStorage.setItem(STORAGE_KEY, "ru");
    expect(detectLocale()).toBe("ru");
  });

  it("falls back to the browser language", () => {
    const original = Object.getOwnPropertyDescriptor(navigator, "language");
    Object.defineProperty(navigator, "language", { value: "ru-RU", configurable: true });
    expect(detectLocale()).toBe("ru");
    if (original) Object.defineProperty(navigator, "language", original);
  });

  it("falls back to the default for a language with no catalogue", () => {
    const original = Object.getOwnPropertyDescriptor(navigator, "language");
    Object.defineProperty(navigator, "language", { value: "de-DE", configurable: true });
    expect(detectLocale()).toBe(DEFAULT_LOCALE);
    if (original) Object.defineProperty(navigator, "language", original);
  });

  it("ignores a stored value that is not a supported locale", () => {
    window.localStorage.setItem(STORAGE_KEY, "klingon");
    const original = Object.getOwnPropertyDescriptor(navigator, "language");
    Object.defineProperty(navigator, "language", { value: "en-GB", configurable: true });
    expect(detectLocale()).toBe(DEFAULT_LOCALE);
    if (original) Object.defineProperty(navigator, "language", original);
  });
});

describe("applying a locale", () => {
  it("changes what t() returns and persists the choice", () => {
    setLocale("ru");
    expect(getLocale()).toBe("ru");
    expect(t("auth.login")).toBe("Войти");
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe("ru");
  });
});
