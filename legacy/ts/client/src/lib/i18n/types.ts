// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * A message that changes with a count.
 *
 * The categories are CLDR's, resolved by `Intl.PluralRules` — not invented here.
 * English needs `one` and `other`; Russian needs `one`, `few` and `many`; Arabic
 * needs all six. Only `other` is required, because it is the one category every
 * language has, which makes it a safe fallback when a translation is partial.
 */
export interface PluralForms {
  zero?: string;
  one?: string;
  two?: string;
  few?: string;
  many?: string;
  other: string;
}

/** A catalogue entry: a plain string, or a set of plural forms. */
export type Message = string | PluralForms;

export type Catalogue = Readonly<Record<string, Message>>;

/** Values substituted into `{named}` placeholders. */
export type MessageParams = Readonly<Record<string, string | number>>;

export function isPluralForms(message: Message): message is PluralForms {
  return typeof message !== "string";
}
