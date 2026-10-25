// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { t } from "@/lib/i18n";
import { Modal } from "@/components/ui";
import {
  SHORTCUTS,
  SHORTCUT_GROUP_ORDER,
  formatCombo,
  type ShortcutGroup,
} from "@/lib/shortcuts";

interface ShortcutsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function ShortcutsModal({ isOpen, onClose }: ShortcutsModalProps) {
  const grouped = SHORTCUT_GROUP_ORDER.map((group) => ({
    group,
    bindings: SHORTCUTS.filter((s) => s.group === group),
  })).filter((section) => section.bindings.length > 0);

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={t("shortcuts.title")}>
      <div className="space-y-6">
        {grouped.map(({ group, bindings }) => (
          <Section key={group} group={group} bindings={bindings} />
        ))}
      </div>
    </Modal>
  );
}

function Section({
  group,
  bindings,
}: {
  group: ShortcutGroup;
  bindings: readonly (typeof SHORTCUTS)[number][];
}) {
  return (
    <section>
      <h3 className="text-[var(--text-muted)] text-xs uppercase tracking-wide mb-2">
        {group}
      </h3>
      <ul className="space-y-2">
        {bindings.map((binding) => (
          <li key={binding.id} className="flex items-center justify-between gap-4">
            <span className="text-[var(--text-secondary)] text-sm">
              {binding.description}
            </span>
            <span className="flex items-center gap-1 shrink-0">
              {binding.combos.map((combo, index) => (
                <span key={combo} className="flex items-center gap-1">
                  {index > 0 ? (
                    <span className="text-[var(--text-muted)] text-xs">or</span>
                  ) : null}
                  <kbd className="rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--surface-alt)] px-2 py-1 text-[var(--text-primary)] text-xs">
                    {formatCombo(combo)}
                  </kbd>
                </span>
              ))}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
