// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useEffect } from "react";

/**
 * A dedication, printed once to the browser console.
 *
 * This is the one deliberate `console.log` in the client, and it is here rather
 * than inline in a component so nobody later mistakes it for stray debug output
 * and deletes it. It prints no data of any kind — no keys, no identifiers, no
 * message content — and runs once per page load.
 *
 * It lives in a client component because the root layout is a server component:
 * a log there would go to the server's terminal, where the person it is written
 * for would never see it.
 */

const ACCENT = "#4ade80";
const MUTED = "rgba(160,160,160,0.9)";

// Module scope, not a ref: React mounts effects twice in development, and this
// should read as a note left once, not a stutter.
let printed = false;

export default function Dedication() {
  useEffect(() => {
    if (printed) return;
    printed = true;

    console.log(
      "%cFor my grandmother, for Valera, for Sasha.\n" +
        "%cThank you for being there through all of it — the weeks it went well,\nand the ones where nothing worked at all.\n\n" +
        "%cFor Alisa.\n" +
        "%cThank you — for the patience, for the late nights,\nand for being the reason any of this got finished.\n\n" +
        "%cI love you.\n\n" +
        "%cAnd to you, reading this:\n" +
        "%cthank you for being curious enough to look. What you write here\nstays yours — that was the whole point of building it.\n",
      `color:${ACCENT};font-size:13px;font-weight:600`,
      `color:${MUTED};font-size:13px;line-height:1.6`,
      `color:${ACCENT};font-size:13px;font-weight:600`,
      `color:${MUTED};font-size:13px;line-height:1.6`,
      `color:${ACCENT};font-size:13px;font-weight:600`,
      `color:${ACCENT};font-size:13px;font-weight:600`,
      `color:${MUTED};font-size:13px;line-height:1.6`,
    );
  }, []);

  return null;
}
