// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Shared UI primitives reused across Settings section components.
 */

"use client";

export function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="text-body font-semibold text-[var(--text-secondary)] mb-4">
      {children}
    </h2>
  );
}

export function ToggleRow({
  label,
  description,
  checked,
  onChange,
}: {
  label: string;
  description?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-4 py-3 select-none">
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-[var(--text-primary)]">
          {label}
        </p>
        {description ? (
          <p className="text-xs text-[var(--text-muted)] mt-0.5">
            {description}
          </p>
        ) : null}
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        onClick={() => onChange(!checked)}
        className={`
          relative w-11 h-6 rounded-full border shrink-0 [transition:background-color_0.2s_ease,border-color_0.2s_ease]
          ${
            checked
              ? "bg-[var(--accent)] border-[var(--accent)]"
              : "bg-[var(--surface-alt)] border-[var(--border)]"
          }
        `}
      >
        <span
          className={`
            absolute top-1/2 left-[3px] w-[18px] h-[18px] rounded-full shadow-[var(--shadow-sm)]
            [transition:transform_0.22s_cubic-bezier(0.22,1,0.36,1),background-color_0.2s_ease]
            ${
              checked
                ? "-translate-y-1/2 translate-x-[20px] bg-[var(--accent-contrast)]"
                : "-translate-y-1/2 translate-x-0 bg-[var(--text-secondary)]"
            }
          `}
        />
      </button>
    </div>
  );
}
