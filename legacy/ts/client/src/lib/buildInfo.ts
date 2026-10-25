// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Which build this is.
 *
 * Without it, "is the fix deployed?" is answered by guessing. A version alone
 * does not settle it either — `0.1.0` was the version for months while dozens of
 * commits shipped — so the commit is what actually identifies a build, and the
 * version is what a human can say out loud.
 *
 * Everything here is baked in at build time. `NEXT_PUBLIC_*` variables are
 * inlined by Next into the client bundle, so these are constants in the shipped
 * JavaScript rather than a runtime lookup — there is nothing to fetch and
 * nothing that can disagree with the code around it.
 *
 * Vercel provides `VERCEL_GIT_COMMIT_SHA` during a build; `next.config` maps it
 * onto `NEXT_PUBLIC_BUILD_COMMIT` so a local build and a deployed one populate
 * the same field. A build with neither reports `dev`, which is the honest answer
 * for something built on someone's laptop.
 */

/** Human-facing version, from package.json. */
export const BUILD_VERSION = process.env.NEXT_PUBLIC_BUILD_VERSION || "0.0.0";

/** Short commit the build came from, or `dev` when built outside CI. */
export const BUILD_COMMIT = (process.env.NEXT_PUBLIC_BUILD_COMMIT || "dev").slice(0, 7);

/** ISO timestamp of the build, empty when unknown. */
export const BUILD_TIME = process.env.NEXT_PUBLIC_BUILD_TIME || "";

/**
 * One line, safe to render anywhere: `v0.1.0 · a1b2c3d`.
 *
 * Deliberately not the build time — a timestamp in the UI invites people to
 * read staleness into it, and what actually answers "which code is this" is the
 * commit. The time is exported separately for anyone who needs it.
 */
export const BUILD_LABEL = `v${BUILD_VERSION} · ${BUILD_COMMIT}`;
