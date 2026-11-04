# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

import pathlib
import re
import subprocess
import sys

INCLUDE = re.compile(r'^\s*#\s*include\s+"([^"]+)"')
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp"}
ONLY_INCLUDED_BY = {
    "vault/key_access.hpp": ("core/src/vault/keys.cpp", "core/src/vault/records.cpp"),
}
ONLY_INCLUDED_UNDER = {
    "vault/vault_internal.hpp": ("core/src/vault/", "core/tests/"),
}
PUBLIC_PREFIX = "core/include/"
PUBLIC_INCLUDE_PREFIX = "lume/"


def tracked_sources(repository: pathlib.Path) -> list[str]:
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=repository,
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8")
    names = {name for name in listing.split("\0") if name}
    return sorted(
        name
        for name in names
        if pathlib.PurePosixPath(name).suffix in SOURCE_SUFFIXES
        and not name.startswith(("legacy/", "core/third_party/"))
        and (repository / name).is_file()
    )


def violations(name: str, included: str) -> list[str]:
    found = []
    allowed = ONLY_INCLUDED_BY.get(included)
    if allowed is not None and name not in allowed:
        found.append(f"{included} may be included only by {', '.join(allowed)}")
    prefixes = ONLY_INCLUDED_UNDER.get(included)
    if prefixes is not None and not name.startswith(prefixes):
        found.append(f"{included} may be included only under {', '.join(prefixes)}")
    if name.startswith(PUBLIC_PREFIX) and not included.startswith(PUBLIC_INCLUDE_PREFIX):
        found.append(f"a public header includes {included}, which is not a public header")
    return found


def main() -> int:
    repository = pathlib.Path(__file__).resolve().parent.parent
    failures = []
    for name in tracked_sources(repository):
        text = (repository / name).read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            match = INCLUDE.match(line)
            if match is None:
                continue
            for problem in violations(name, match.group(1)):
                failures.append(f"{name}:{number}: {problem}")
    for failure in failures:
        print(failure)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
