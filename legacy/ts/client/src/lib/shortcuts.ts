// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Keyboard shortcut registry.
 *
 * Bindings are data, not branches: adding a shortcut means adding a row here,
 * and `Record<ShortcutCommandId, ...>` consumers stop compiling when a command
 * is added without being handled.
 */

export type ShortcutCommandId = "showHelp" | "openSettings" | "toggleContactsPanel";

export type ShortcutGroup = "Navigation" | "View" | "Help";

export interface ShortcutBinding {
  readonly id: ShortcutCommandId;
  /** Normalised combos; any one of them triggers the command. */
  readonly combos: readonly string[];
  readonly description: string;
  readonly group: ShortcutGroup;
}

/**
 * `mod` is Cmd on Apple platforms and Ctrl everywhere else, matching what users
 * of each platform already expect from every other app.
 */
export const SHORTCUTS: readonly ShortcutBinding[] = [
  {
    id: "showHelp",
    combos: ["?", "mod+/"],
    description: "Show keyboard shortcuts",
    group: "Help",
  },
  {
    id: "openSettings",
    combos: ["mod+,"],
    description: "Open settings",
    group: "Navigation",
  },
  {
    id: "toggleContactsPanel",
    combos: ["mod+b"],
    description: "Show or hide the contacts panel",
    group: "View",
  },
];

export const SHORTCUT_GROUP_ORDER: readonly ShortcutGroup[] = ["Navigation", "View", "Help"];

function isApplePlatform(): boolean {
  if (typeof navigator === "undefined") return false;
  return /Mac|iPhone|iPad|iPod/.test(navigator.platform || navigator.userAgent);
}

/**
 * Turns a keyboard event into a canonical combo string.
 *
 * Printable keys carry their shifted value already (Shift+/ arrives as "?"), so
 * `shift` is only recorded for named keys like ArrowUp — otherwise "?" would
 * have to be written as "shift+?" and would never match on layouts where "?"
 * is unshifted.
 */
export function eventToCombo(event: KeyboardEvent): string {
  const parts: string[] = [];

  if (event.ctrlKey || event.metaKey) parts.push("mod");
  if (event.altKey) parts.push("alt");

  const isNamedKey = event.key.length > 1;
  if (event.shiftKey && isNamedKey) parts.push("shift");

  parts.push(event.key.toLowerCase());

  return parts.join("+");
}

export function matchShortcut(event: KeyboardEvent): ShortcutCommandId | null {
  const combo = eventToCombo(event);
  const binding = SHORTCUTS.find((s) => s.combos.includes(combo));
  return binding ? binding.id : null;
}

/** Renders a combo for display, e.g. "mod+," → "⌘ ," on Apple, "Ctrl ," elsewhere. */
export function formatCombo(combo: string): string {
  const apple = isApplePlatform();
  return combo
    .split("+")
    .map((part) => {
      if (part === "mod") return apple ? "⌘" : "Ctrl";
      if (part === "alt") return apple ? "⌥" : "Alt";
      if (part === "shift") return apple ? "⇧" : "Shift";
      if (part.length === 1) return part.toUpperCase();
      return part.charAt(0).toUpperCase() + part.slice(1);
    })
    .join(" ");
}

/**
 * Typing must never trigger a command — "?" in the composer is a question mark,
 * not a help request.
 */
export function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;

  const tag = target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;

  // Not every environment defines isContentEditable on plain elements, so coerce
  // rather than returning it directly — the declared boolean must hold.
  return target.isContentEditable === true;
}
