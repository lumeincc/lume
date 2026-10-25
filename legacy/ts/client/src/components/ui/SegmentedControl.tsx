// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useRef, useEffect, useState, useCallback } from "react";

/**
 * Segmented control: one rounded track holding pill options with a single
 * sliding accent indicator. Shared by the theme picker, self-destruct timers
 * (settings + chat + groups), etc. Values may be string | number | null
 * (e.g. `null` for an "Off" option).
 */
export function SegmentedControl<T extends string | number | null>({
  options,
  value,
  onChange,
  className = "",
}: {
  options: { label: string; value: T }[];
  value: T;
  onChange: (v: T) => void;
  className?: string;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [indicator, setIndicator] = useState<{
    left: number;
    top: number;
    width: number;
    height: number;
  }>({ left: 0, top: 0, width: 0, height: 0 });
  const [ready, setReady] = useState(false);

  const updateIndicator = useCallback(() => {
    const container = containerRef.current;
    if (!container) return;
    const activeIndex = options.findIndex((opt) => opt.value === value);
    if (activeIndex < 0) {
      setReady(false);
      return;
    }
    const buttons = container.querySelectorAll<HTMLButtonElement>(
      "[data-seg-option]",
    );
    const activeBtn = buttons[activeIndex];
    if (!activeBtn) return;
    setIndicator({
      left: activeBtn.offsetLeft,
      top: activeBtn.offsetTop,
      width: activeBtn.offsetWidth,
      height: activeBtn.offsetHeight,
    });
    setReady(true);
  }, [options, value]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- sync pill position with DOM layout
    updateIndicator();
  }, [updateIndicator]);

  return (
    <div
      ref={containerRef}
      className={`relative inline-flex flex-wrap gap-1 p-1 rounded-2xl border border-[var(--border)] bg-[var(--surface-alt)] ${className}`}
    >
      {ready && (
        <div
          className="absolute rounded-full z-0 bg-[var(--accent)] shadow-[var(--shadow-sm)]"
          style={{
            left: indicator.left,
            top: indicator.top,
            width: indicator.width,
            height: indicator.height,
            transition:
              "left 0.2s cubic-bezier(0.22, 1, 0.36, 1), top 0.2s cubic-bezier(0.22, 1, 0.36, 1), width 0.2s cubic-bezier(0.22, 1, 0.36, 1), height 0.2s cubic-bezier(0.22, 1, 0.36, 1)",
          }}
        />
      )}
      {options.map((opt) => {
        const active = opt.value === value;
        return (
          <button
            key={String(opt.value)}
            type="button"
            data-seg-option
            onClick={() => onChange(opt.value)}
            className={`relative z-[1] px-4 py-1.5 rounded-full text-body font-medium transition-colors ${
              active
                ? "text-[var(--accent-contrast)]"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

export default SegmentedControl;
