#!/bin/sh
# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

workflow=${1:-linux}
case "$workflow" in
    linux) build=linux-gcc-asan ;;
    *) echo "unknown workflow: $workflow" >&2; exit 2 ;;
esac
if [ -z "${VCPKG_ROOT:-}" ]; then
    echo "Set VCPKG_ROOT to a vcpkg checkout first" >&2
    exit 2
fi

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
results="build/$build/test-results.xml"
rm -f "$results"
status=0
cmake --workflow --preset "$workflow" || status=$?
if [ ! -f "$results" ]; then
    echo "No test results: the configure or build step failed. See the output above." >&2
    exit $((status == 0 ? 1 : status))
fi
report_status=0
python3 tools/test_report.py "$results" "build/$build/test-report.html" || report_status=$?
if [ "$status" -eq 0 ]; then
    status=$report_status
fi
exit "$status"
