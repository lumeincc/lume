# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

import pathlib
import re
import subprocess
import sys

EXCLUDED = (
    "legacy/",
    "brand/",
    "LICENSES/",
    "core/third_party/",
    "core/tests/vectors/wycheproof/",
    "core/tests/vectors/trezor/",
)
SLASH_COMMENT_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp", ".kt", ".kts", ".mjs", ".js"}
HASH_COMMENT_SUFFIXES = {".cmake", ".py", ".yml", ".yaml", ".toml", ".sh"}
HASH_COMMENT_NAMES = {"CMakeLists.txt", ".clang-tidy", ".gitignore", ".gitattributes"}
SPDX = re.compile(r"^(//|#) SPDX-(FileCopyrightText|License-Identifier): ")
STRING_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"' + r"|'(?:\\.|[^'\\])*'" + r"|`(?:\\.|[^`\\])*`")


def comment_style(path: pathlib.PurePosixPath) -> str | None:
    if path.suffix in SLASH_COMMENT_SUFFIXES:
        return "slash"
    if path.suffix in HASH_COMMENT_SUFFIXES or path.name in HASH_COMMENT_NAMES:
        return "hash"
    return None


def header_length(lines: list[str]) -> int:
    count = 1 if lines and lines[0].startswith("#!") else 0
    for line in lines[count:]:
        if not SPDX.match(line):
            break
        count += 1
    return count


def offending_lines(text: str, style: str) -> list[int]:
    lines = text.splitlines()
    found = []
    for number, line in enumerate(lines[header_length(lines):], start=header_length(lines) + 1):
        code = STRING_LITERAL.sub('""', line)
        if style == "slash" and ("//" in code or "/*" in code):
            found.append(number)
        if style == "hash" and "#" in code:
            found.append(number)
    return found


def tracked_files(repository: pathlib.Path) -> list[str]:
    listing = subprocess.run(
        ["git", "ls-files", "-z"], cwd=repository, check=True, capture_output=True
    ).stdout.decode("utf-8")
    return [name for name in listing.split("\0") if name and not name.startswith(EXCLUDED)]


def main() -> int:
    repository = pathlib.Path(__file__).resolve().parent.parent
    failures = []
    for name in tracked_files(repository):
        style = comment_style(pathlib.PurePosixPath(name))
        path = repository / name
        if style is None or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        failures.extend(f"{name}:{line}" for line in offending_lines(text, style))
    for failure in failures:
        print(f"comment found: {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
