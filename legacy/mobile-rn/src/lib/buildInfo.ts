// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Which build this is.
 *
 * A phone build is harder to identify than a web one: there is no URL to read,
 * no deploy log within reach, and an APK sideloaded a week ago looks exactly
 * like one sideloaded this morning. "Which build is on the device?" has to be
 * answerable from the device.
 *
 * The version is what a person says out loud; the commit is what actually
 * identifies the build, because the version string stays put across dozens of
 * shipped commits. Both are baked in at build time — `EXPO_PUBLIC_*` variables
 * are inlined into the bundle, so this is a constant in the shipped JavaScript
 * rather than something fetched or computed.
 *
 * A build with no commit reports `dev`, which is the honest answer for
 * something built on a laptop and not traceable to anything.
 */

import appConfig from '../../app.json'

/** Human-facing version, from app.json — the same value Android shows. */
export const BUILD_VERSION: string = appConfig.expo.version ?? '0.0.0'

/** Short commit the build came from, or `dev` when built outside CI. */
export const BUILD_COMMIT: string = (process.env.EXPO_PUBLIC_BUILD_COMMIT || 'dev').slice(0, 7)

/**
 * One line, safe to render anywhere: `v0.1.0 · a1b2c3d`.
 *
 * Kept identical in shape to the web client's, so a screenshot from either one
 * reads the same way and a bug report does not need to explain which is which.
 */
export const BUILD_LABEL = `v${BUILD_VERSION} · ${BUILD_COMMIT}`
