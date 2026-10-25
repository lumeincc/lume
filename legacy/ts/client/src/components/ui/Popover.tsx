// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import React, { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

interface PopoverProps {
  open: boolean;
  onClose: () => void;
  /** The element the panel grows out of. */
  anchorRef: React.RefObject<HTMLElement | null>;
  children: React.ReactNode;
  /** Horizontal edge to align the panel to the anchor. */
  align?: "start" | "end";
  width?: number;
}

/**
 * A small floating panel anchored to a trigger element — it grows out of the
 * control that opened it rather than covering the screen like a dialog.
 *
 * Rendered in a portal with fixed positioning because the messenger panels use
 * `overflow: hidden`, which would clip an in-flow absolutely-positioned panel.
 */
export function Popover({
  open,
  onClose,
  anchorRef,
  children,
  align = "end",
  width = 288,
}: PopoverProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);

  // Position is derived from the anchor's measured layout, which can only be
  // read after render — hence the effect + setState (a legitimate DOM sync).
  useEffect(() => {
    if (!open || !anchorRef.current) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setPos(null);
      return;
    }
    const r = anchorRef.current.getBoundingClientRect();
    const rawLeft = align === "end" ? r.right - width : r.left;
    const left = Math.min(
      Math.max(8, rawLeft),
      Math.max(8, window.innerWidth - width - 8),
    );
    setPos({ top: r.bottom + 8, left });
  }, [open, anchorRef, align, width]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (panelRef.current?.contains(t)) return;
      // Clicks on the trigger are handled by its own toggle.
      if (anchorRef.current?.contains(t)) return;
      onClose();
    };
    // A popover is anchored to a fixed point; if the surface behind it scrolls,
    // close rather than drift out of place.
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onDown);
    window.addEventListener("resize", onClose);
    window.addEventListener("scroll", onClose, true);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onDown);
      window.removeEventListener("resize", onClose);
      window.removeEventListener("scroll", onClose, true);
    };
  }, [open, onClose, anchorRef]);

  if (!open || !pos) return null;

  return createPortal(
    <div
      ref={panelRef}
      role="dialog"
      aria-modal="false"
      style={{ position: "fixed", top: pos.top, left: pos.left, width }}
      className="z-50 rounded-[16px] border border-[var(--border)] bg-[var(--surface-strong)] p-2 reveal-down modal-sheet-glass"
    >
      {children}
    </div>,
    document.body,
  );
}

export default Popover;
