// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import React from 'react';

export default function MessengerShell({
  leftRail,
  chatList,
  main,
  rightRail,
}: {
  leftRail?: React.ReactNode;
  chatList: React.ReactNode;
  main: React.ReactNode;
  rightRail?: React.ReactNode;
}) {
  const hasRightRail = Boolean(rightRail);
  const xlCols = hasRightRail ? 'xl:grid-cols-[76px_340px_1fr_84px]' : 'xl:grid-cols-[76px_340px_1fr]';

  return (
    <div className="h-full w-full p-0">
      <div
        className={`
          h-full w-full grid min-h-0
          grid-cols-1
          md:grid-cols-[340px_1fr]
          lg:grid-cols-[76px_340px_1fr]
          ${xlCols}
        `}
      >
        {leftRail ? <div className="hidden lg:block min-h-0 border-r border-[var(--border)]">{leftRail}</div> : null}
        <div className="hidden md:block min-h-0 border-r border-[var(--border)]">{chatList}</div>
        <div className="min-h-0">{main}</div>
        {rightRail ? <div className="hidden xl:block min-h-0 border-l border-[var(--border)]">{rightRail}</div> : null}
      </div>
    </div>
  );
}
