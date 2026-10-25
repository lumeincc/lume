// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

'use client';

import { t } from "@/lib/i18n";
import React, { useCallback, useEffect, useRef, useState } from 'react';

interface MobileSwipeShellProps {
  profilePanel: React.ReactNode;
  chatListPanel: React.ReactNode;
}

/** Minimum horizontal swipe distance (px) to trigger a panel switch. */
const SWIPE_THRESHOLD = 50;

/**
 * Two-panel swipeable shell for mobile.
 *
 * Panel 0 (left)  — Profile (LeftRail content)
 * Panel 1 (right) — Messages (ChatListPanel content)
 *
 * Uses native touch events and CSS transform — no external libraries.
 * Vertical scroll inside panels is preserved: a swipe is only captured
 * when the horizontal delta exceeds the vertical delta before the
 * threshold is reached.
 */
export default function MobileSwipeShell({ profilePanel, chatListPanel }: MobileSwipeShellProps) {
  const [activePanel, setActivePanel] = useState<0 | 1>(0);
  const [dragOffset, setDragOffset] = useState(0);
  const [isDragging, setIsDragging] = useState(false);

  const touchStartX = useRef(0);
  const touchStartY = useRef(0);
  /** Whether this touch gesture has been classified as a horizontal swipe. */
  const isHorizontalSwipe = useRef<boolean | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const handleTouchStart = useCallback((e: TouchEvent) => {
    // `touches` can be empty — a cancelled or multi-finger gesture reaches these
    // handlers with no entry at index 0, and reading `.clientX` off undefined
    // throws inside a touch listener. Ignoring the event is the correct response.
    const touch = e.touches[0];
    if (!touch) return;
    touchStartX.current = touch.clientX;
    touchStartY.current = touch.clientY;
    isHorizontalSwipe.current = null;
    setIsDragging(false);
    setDragOffset(0);
  }, []);

  const handleTouchMove = useCallback(
    (e: TouchEvent) => {
      const touch = e.touches[0];
      if (!touch) return;
      const deltaX = touch.clientX - touchStartX.current;
      const deltaY = touch.clientY - touchStartY.current;

      // Classify gesture on first significant movement.
      if (isHorizontalSwipe.current === null) {
        if (Math.abs(deltaX) > Math.abs(deltaY) && Math.abs(deltaX) > 5) {
          isHorizontalSwipe.current = true;
        } else if (Math.abs(deltaY) > Math.abs(deltaX) && Math.abs(deltaY) > 5) {
          isHorizontalSwipe.current = false;
        } else {
          return;
        }
      }

      if (!isHorizontalSwipe.current) return;

      // Prevent vertical scroll takeover only for horizontal swipes.
      e.preventDefault();
      setIsDragging(true);

      // Clamp drag so the user can't pull past the outermost panels.
      const rawOffset = deltaX;
      if (activePanel === 0 && rawOffset > 0) {
        // Already at left edge — allow a small rubber-band feel, then stop.
        setDragOffset(Math.min(rawOffset * 0.15, 20));
      } else if (activePanel === 1 && rawOffset < 0) {
        // Already at right edge.
        setDragOffset(Math.max(rawOffset * 0.15, -20));
      } else {
        setDragOffset(rawOffset);
      }
    },
    [activePanel],
  );

  const handleTouchEnd = useCallback(
    (e: TouchEvent) => {
      if (!isHorizontalSwipe.current) {
        setDragOffset(0);
        setIsDragging(false);
        return;
      }

      const endTouch = e.changedTouches[0];
      if (!endTouch) {
        setDragOffset(0);
        setIsDragging(false);
        return;
      }
      const deltaX = endTouch.clientX - touchStartX.current;

      if (deltaX < -SWIPE_THRESHOLD && activePanel === 0) {
        setActivePanel(1);
      } else if (deltaX > SWIPE_THRESHOLD && activePanel === 1) {
        setActivePanel(0);
      }

      setDragOffset(0);
      setIsDragging(false);
    },
    [activePanel],
  );

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    // passive: false is required so we can call preventDefault inside touchmove.
    el.addEventListener('touchstart', handleTouchStart, { passive: true });
    el.addEventListener('touchmove', handleTouchMove, { passive: false });
    el.addEventListener('touchend', handleTouchEnd, { passive: true });

    return () => {
      el.removeEventListener('touchstart', handleTouchStart);
      el.removeEventListener('touchmove', handleTouchMove);
      el.removeEventListener('touchend', handleTouchEnd);
    };
  }, [handleTouchStart, handleTouchMove, handleTouchEnd]);

  // Base translateX for the active panel (0% or -50% of 200vw = -100vw).
  const baseTranslate = activePanel === 0 ? 0 : -50; // percent of 200vw container

  // Convert px drag offset into percent of 200vw (1vw = window.innerWidth / 100).
  const dragPercent =
    dragOffset !== 0 && typeof window !== 'undefined'
      ? (dragOffset / (window.innerWidth * 2)) * 100
      : 0;

  const translateX = `${baseTranslate + dragPercent}%`;

  return (
    <div className="h-full w-full overflow-hidden flex flex-col">
      {/* Sliding track — 200vw wide so each panel occupies 50% = 100vw. */}
      <div className="flex-1 min-h-0 relative overflow-hidden">
        <div
          ref={containerRef}
          style={{
            width: '200%',
            height: '100%',
            display: 'flex',
            transform: `translateX(${translateX})`,
            transition: isDragging ? 'none' : 'transform 300ms ease-out',
            willChange: 'transform',
          }}
        >
          {/* Panel 0 — Profile */}
          <div
            style={{ width: '50%', height: '100%', flexShrink: 0 }}
            className="min-h-0 overflow-hidden"
            aria-hidden={activePanel !== 0}
          >
            {profilePanel}
          </div>

          {/* Panel 1 — Messages */}
          <div
            style={{ width: '50%', height: '100%', flexShrink: 0 }}
            className="min-h-0 overflow-hidden"
            aria-hidden={activePanel !== 1}
          >
            {chatListPanel}
          </div>
        </div>
      </div>

      {/* Indicator dots */}
      <div
        className="flex-shrink-0 flex items-center justify-center gap-2 py-2"
        role="tablist"
        aria-label={t("nav.panels")}
      >
        <button
          type="button"
          role="tab"
          aria-selected={activePanel === 0}
          aria-label={t("nav.profilePanel")}
          onClick={() => setActivePanel(0)}
          className={`
            w-1.5 h-1.5 rounded-full transition-all duration-200
            ${activePanel === 0 ? 'bg-[var(--accent)] w-4' : 'bg-[var(--border)]'}
          `}
        />
        <button
          type="button"
          role="tab"
          aria-selected={activePanel === 1}
          aria-label={t("nav.messagesPanel")}
          onClick={() => setActivePanel(1)}
          className={`
            w-1.5 h-1.5 rounded-full transition-all duration-200
            ${activePanel === 1 ? 'bg-[var(--accent)] w-4' : 'bg-[var(--border)]'}
          `}
        />
      </div>
    </div>
  );
}
