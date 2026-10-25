// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * String lookup.
 *
 * Two rules the call sites depend on:
 *
 * - Plural selection happens here, never at the call site. A ternary can only
 *   express two forms; Russian has three and Arabic six, so `count === 1 ? …`
 *   is wrong the moment a second locale exists.
 * - Substitutions are named (`{count}`), never positional. Word order changes
 *   between languages, so an index carries no meaning across a translation.
 *
 * Lookup never throws. A missing key or a missing parameter is a defect in the
 * catalogue, and blanking the interface is a worse response to it than showing
 * imperfect text — so it degrades visibly and complains in development.
 */

import { en, type TranslationKey } from "./en";
import { ru } from "./ru";
import { isPluralForms, type Catalogue, type Message, type MessageParams } from "./types";

export type { TranslationKey };
export type { Message, MessageParams, PluralForms } from "./types";
export { en };

export type Locale = "en" | "ru";

const CATALOGUES: Record<Locale, Catalogue> = { en, ru };

export const DEFAULT_LOCALE: Locale = "en";
export const LOCALES: readonly Locale[] = ["en", "ru"];

/** Names are written in their own language — a chooser you cannot read is useless. */
export const LOCALE_NAMES: Record<Locale, string> = {
  en: "English",
  ru: "Русский",
};

const STORAGE_KEY = "lume:locale";

function isLocale(value: string | null): value is Locale {
  return value !== null && (LOCALES as readonly string[]).includes(value);
}

/**
 * Resolution order: explicit choice, then what the browser reports, then English.
 *
 * The choice lives in localStorage rather than in the settings blob, alongside
 * `lume:contacts-collapsed`. It is a display preference, it must be readable
 * before unlock so the PIN screen is in the right language, and on an anonymous
 * account it is one less attribute to hand the server.
 */
export function detectLocale(): Locale {
  if (typeof window === "undefined") return DEFAULT_LOCALE;

  const stored = window.localStorage.getItem(STORAGE_KEY);
  if (isLocale(stored)) return stored;

  const fromBrowser = navigator.language.split("-")[0];
  return isLocale(fromBrowser ?? null) ? (fromBrowser as Locale) : DEFAULT_LOCALE;
}

/**
 * Starts at the default on *both* sides, deliberately.
 *
 * This used to call `detectLocale()` at module scope, which resolves to the
 * browser's language in the client bundle and to English on the server. Every
 * `t()` then returned different text in the two places, so React found a text
 * mismatch on hydration, threw away the entire server-rendered tree and built
 * it again from scratch — the React #418 in the console.
 *
 * The user saw English for a frame either way. Now that frame is a deliberate
 * re-render after `LocaleBoot` detects the real locale, instead of React
 * discarding a whole tree it had just been handed.
 */
let activeLocale: Locale = DEFAULT_LOCALE;

export function getLocale(): Locale {
  return activeLocale;
}

export function setLocale(locale: Locale): void {
  activeLocale = locale;
  if (typeof window !== "undefined") {
    window.localStorage.setItem(STORAGE_KEY, locale);
    document.documentElement.lang = locale;
  }
}

const PLACEHOLDER = /\{(\w+)\}/g;

function warn(message: string): void {
  if (process.env.NODE_ENV !== "production") console.warn(`[i18n] ${message}`);
}

/**
 * Picks the plural form for `count`, falling back to `other` — the one category
 * every language defines — when a translation omits the exact one.
 */
function selectPluralForm(forms: Exclude<Message, string>, count: number, locale: Locale): string {
  const category = new Intl.PluralRules(locale).select(count);
  const exact = forms[category];
  if (exact !== undefined) return exact;

  if (category !== "other") {
    warn(`missing plural category "${category}" for count ${count} in "${locale}"`);
  }
  return forms.other;
}

function interpolate(template: string, params: MessageParams | undefined, key: string): string {
  return template.replace(PLACEHOLDER, (match, name: string) => {
    const value = params?.[name];
    if (value === undefined) {
      warn(`missing parameter "${name}" for key "${key}"`);
      return match;
    }
    return String(value);
  });
}

export function translate(
  key: TranslationKey,
  params?: MessageParams,
  locale: Locale = activeLocale,
): string {
  const catalogue = CATALOGUES[locale] ?? CATALOGUES[DEFAULT_LOCALE];
  const message = catalogue[key] ?? CATALOGUES[DEFAULT_LOCALE][key];

  if (message === undefined) {
    warn(`missing key "${key}"`);
    return key;
  }

  if (isPluralForms(message)) {
    const count = params?.count;
    if (typeof count !== "number") {
      warn(`key "${key}" is plural but received no numeric "count"`);
      return interpolate(message.other, params, key);
    }
    return interpolate(selectPluralForm(message, count, locale), params, key);
  }

  return interpolate(message, params, key);
}

/** Short alias for call sites, matching how it reads in JSX. */
export const t = translate;
