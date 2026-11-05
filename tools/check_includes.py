# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

import pathlib
import posixpath
import re
import subprocess
import sys

DIRECTIVE = re.compile(r"^\s*#\s*include\b(.*)$")
NAMED = re.compile(r'^\s*(?:"([^"]+)"|<([^>]+)>)')
SOURCE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".h++", ".ipp", ".inl", ".ixx", ".tpp", ".cppm",
}
EXCLUDED = ("legacy/", "core/third_party/")
INCLUDE_ROOTS = ("core/include", "core/src", "core/tests", "tools/lab")
PUBLIC = "core/include/"
GUARDED = {
    "core/src/vault/key_access.hpp": {
        "files": ("core/src/vault/keys.cpp", "core/src/vault/records.cpp"),
        "under": (),
    },
    "core/src/vault/vault_internal.hpp": {
        "files": ("core/src/vault/keys.cpp", "core/src/vault/records.cpp"),
        "under": ("core/tests/",),
    },
}


def is_source(name: str) -> bool:
    return pathlib.PurePosixPath(name).suffix.lower() in SOURCE_SUFFIXES


def resolve(including: str, written: str, quoted: bool, known: dict[str, str]) -> str | None:
    folders = [posixpath.dirname(including)] if quoted else []
    folders.extend(INCLUDE_ROOTS)
    for folder in folders:
        candidate = posixpath.normpath(posixpath.join(folder, written.replace("\\", "/")))
        if candidate.startswith("../"):
            continue
        found = known.get(candidate.casefold())
        if found is not None:
            return found
    return None


def problems_in(name: str, text: str, known: dict[str, str]) -> list[str]:
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        directive = DIRECTIVE.match(line)
        if directive is None:
            continue
        named = NAMED.match(directive.group(1))
        if named is None:
            found.append(f"{name}:{number}: an include must name its header in quotes or angle brackets")
            continue
        quoted = named.group(1) is not None
        written = named.group(1) if quoted else named.group(2)
        target = resolve(name, written, quoted, known)
        if target is None:
            continue
        guard = GUARDED.get(target)
        if guard is not None and name not in guard["files"] and not name.startswith(guard["under"]):
            allowed = ", ".join(guard["files"] + guard["under"])
            found.append(f"{name}:{number}: {target} may be included only by {allowed}")
        if name.startswith(PUBLIC) and not target.startswith(PUBLIC):
            found.append(f"{name}:{number}: a public header includes {target}, which is not a public header")
    return found


def check(files: dict[str, str], others: tuple[str, ...] = ()) -> list[str]:
    known = {name.casefold(): name for name in (*files, *others)}
    failures = []
    for name in sorted(files):
        failures.extend(problems_in(name, files[name], known))
    return failures


def repository_files(repository: pathlib.Path) -> list[str]:
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=repository,
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8")
    return sorted(
        {name for name in listing.split("\0") if name and not name.startswith(EXCLUDED) and (repository / name).is_file()}
    )


def main() -> int:
    repository = pathlib.Path(__file__).resolve().parent.parent
    names = repository_files(repository)
    sources = {name: (repository / name).read_text(encoding="utf-8") for name in names if is_source(name)}
    failures = check(sources, tuple(names))
    for failure in failures:
        print(failure)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
