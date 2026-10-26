#!/bin/sh
# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

root="$RUNNER_TEMP/vcpkg"
cache="$RUNNER_TEMP/vcpkg-cache"
echo "VCPKG_ROOT=$root" >> "$GITHUB_ENV"
echo "VCPKG_DEFAULT_BINARY_CACHE=$cache" >> "$GITHUB_ENV"
mkdir -p "$cache"
git clone --quiet https://github.com/microsoft/vcpkg "$root"
git -C "$root" checkout --quiet "$VCPKG_COMMIT"
"$root/bootstrap-vcpkg.sh" -disableMetrics
