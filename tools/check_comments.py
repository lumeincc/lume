# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

import pathlib
import re
import sys

ROOTS = ("core", "cmake", "tools")
SLASH_COMMENT_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp", ".kt", ".kts", ".mjs", ".js"}
HASH_COMMENT_SUFFIXES = {".cmake", ".py", ".yml", ".yaml", ".toml"}
HASH_COMMENT_NAMES = {"CMakeLists.txt", ".clang-tidy"}
SPDX = re.compile(r"SPDX-(FileCopyrightText|License-Identifier):")
STRING_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"' + r"|'(?:\\.|[^'\\])*'")


def comment_style(path: pathlib.Path) -> str | None:
    if path.suffix in SLASH_COMMENT_SUFFIXES:
        return "slash"
    if path.suffix in HASH_COMMENT_SUFFIXES or path.name in HASH_COMMENT_NAMES:
        return "hash"
    return None


def offending_lines(path: pathlib.Path, style: str) -> list[int]:
    found = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if SPDX.search(line):
            continue
        code = STRING_LITERAL.sub('""', line)
        if style == "slash" and ("//" in code or "/*" in code):
            found.append(number)
        if style == "hash" and "#" in code.split('""')[0] and not code.lstrip().startswith("#!"):
            found.append(number)
    return found


def main() -> int:
    repository = pathlib.Path(__file__).resolve().parent.parent
    failures = []
    for root in ROOTS + (".github",):
        base = repository / root
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            style = comment_style(path) if path.is_file() else None
            if style is None or "vectors" in path.parts:
                continue
            failures.extend(f"{path.relative_to(repository)}:{line}" for line in offending_lines(path, style))
    for name in HASH_COMMENT_NAMES:
        path = repository / name
        if path.is_file():
            failures.extend(f"{name}:{line}" for line in offending_lines(path, "hash"))
    for failure in failures:
        print(f"comment found: {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
