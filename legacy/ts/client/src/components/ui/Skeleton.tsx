// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Skeleton loading placeholders.
 *
 * - ChatListSkeleton — full chat-list panel with shimmer rows
 * - MessagesSkeleton — message bubbles shimmer for the chat area
 * - SettingsSkeleton — settings panel shimmer
 */

"use client";

import React from "react";

/* ──────────── Shimmer bar primitive ──────────── */
function Shimmer({
  className = "",
  style,
}: {
  className?: string;
  style?: React.CSSProperties;
}) {
  return (
    <span
      className={`block rounded-full bg-[var(--surface-alt)] animate-pulse ${className}`}
      style={style}
    />
  );
}

/* ──────────── Chat list row skeleton ──────────── */
function ChatRowSkeleton() {
  return (
    <div className="px-4 py-3 flex items-center gap-3 border-b border-[var(--border)]/55 last:border-b-0">
      {/* Avatar */}
      <Shimmer className="w-11 h-11 rounded-full shrink-0" />

      <div className="flex-1 min-w-0 space-y-2">
        <div className="flex justify-between items-center">
          <Shimmer className="h-3 w-24" />
          <Shimmer className="h-2.5 w-10" />
        </div>
        <Shimmer className="h-2.5 w-40" />
      </div>
    </div>
  );
}

/* ──────────── ChatListSkeleton ──────────── */
export function ChatListSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div aria-busy="true" className="lume-panel h-full min-h-0 rounded-[var(--radius-lg)] border border-[var(--border)] shadow-[var(--shadow-sm)] overflow-hidden">
      {/* Header */}
      <div className="px-5 pt-5 pb-4 border-b border-[var(--border)]/70">
        <div className="flex items-center justify-between gap-3">
          <Shimmer className="h-3 w-20" />
          <Shimmer className="w-8 h-8 rounded-full" />
        </div>
        <div className="mt-4">
          <Shimmer className="h-[46px] w-full rounded-[var(--radius-md)]" />
        </div>
      </div>

      {/* Rows */}
      <div className="py-1">
        {Array.from({ length: rows }, (_, i) => (
          <ChatRowSkeleton key={i} />
        ))}
      </div>
    </div>
  );
}

/* ──────────── Message bubble skeleton ──────────── */
function BubbleSkeleton({ align, index }: { align: "left" | "right"; index: number }) {
  const widths = ["w-48", "w-64", "w-36", "w-56", "w-44"];
  const w = widths[index % widths.length];

  return (
    <div
      className={`flex ${align === "right" ? "justify-end" : "justify-start"} mb-3`}
    >
      <div
        className={`
          ${w} max-w-[70%] rounded-2xl p-4 space-y-2
          ${
            align === "right"
              ? "bg-[var(--accent)]/10 rounded-br-md"
              : "bg-[var(--surface-alt)] rounded-bl-md"
          }
        `}
      >
        <Shimmer className="h-3 w-full" />
        <Shimmer className="h-3 w-3/4" />
      </div>
    </div>
  );
}

/* ──────────── MessagesSkeleton ──────────── */
export function MessagesSkeleton({ count = 8 }: { count?: number }) {
  // Deterministic alternating pattern
  const pattern = Array.from({ length: count }, (_, i) =>
    i % 3 === 0 ? "right" : "left",
  ) as ("left" | "right")[];

  return (
    <div aria-busy="true" className="flex-1 min-h-0 overflow-hidden px-6 py-6 space-y-1">
      {pattern.map((align, i) => (
        <BubbleSkeleton key={i} align={align} index={i} />
      ))}
    </div>
  );
}

/* ──────────── Settings panel skeleton ──────────── */
export function SettingsSkeleton() {
  return (
    <div aria-busy="true" className="lume-panel h-full rounded-[var(--radius-lg)] border border-[var(--border)] shadow-[var(--shadow-sm)] overflow-hidden flex flex-col">
      <div className="px-6 pt-6 pb-5 border-b border-[var(--border)]/70">
        <Shimmer className="h-3 w-16" />
      </div>
      <div className="flex-1 min-h-0 px-6 py-6 space-y-8">
        {/* Section 1 */}
        <div className="space-y-3">
          <Shimmer className="h-2.5 w-20" />
          <Shimmer className="h-3 w-12" />
          <div className="flex gap-2">
            <Shimmer className="h-9 w-16 rounded-full" />
            <Shimmer className="h-9 w-16 rounded-full" />
            <Shimmer className="h-9 w-20 rounded-full" />
          </div>
        </div>
        {/* Section 2 */}
        <div className="space-y-3">
          <Shimmer className="h-2.5 w-24" />
          <div className="flex justify-between items-center">
            <Shimmer className="h-3 w-36" />
            <Shimmer className="h-6 w-11 rounded-full" />
          </div>
        </div>
        {/* Section 3 */}
        <div className="space-y-3">
          <Shimmer className="h-2.5 w-14" />
          <div className="flex gap-2">
            <Shimmer className="h-9 w-12 rounded-full" />
            <Shimmer className="h-9 w-14 rounded-full" />
            <Shimmer className="h-9 w-16 rounded-full" />
            <Shimmer className="h-9 w-16 rounded-full" />
          </div>
          <div className="flex justify-between items-center pt-2">
            <Shimmer className="h-3 w-28" />
            <Shimmer className="h-6 w-11 rounded-full" />
          </div>
        </div>
        {/* Section 4 */}
        <div className="space-y-3">
          <Shimmer className="h-2.5 w-16" />
          <Shimmer className="h-12 w-full rounded-[var(--radius-md)]" />
        </div>
      </div>
    </div>
  );
}
