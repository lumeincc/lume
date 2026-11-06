# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

import pathlib
import posixpath
import re
import subprocess
import sys

DIRECTIVE = re.compile(r"^\s*(?:#|%:)\s*include\b(.*)$")
NAMED = re.compile(r'^\s*(?:"([^"]+)"|<([^>]+)>)')
ABSOLUTE = re.compile(r"^(?:[A-Za-z]:)?[\\/]")
SOURCE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".h++", ".ipp", ".inl", ".ixx", ".tpp", ".cppm",
}
EXCLUDED = ("legacy/", "core/third_party/")
INCLUDE_ROOTS = ("core/include", "core/src", "core/tests", "tools/lab")
PUBLIC = "core/include/"
STANDARD_HEADER = re.compile(r"^[a-z_]+$")
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


def logical_lines(text: str) -> list[tuple[int, str]]:
    lines = []
    pending = ""
    start = 1
    for number, line in enumerate(text.splitlines(), start=1):
        if not pending:
            start = number
        if line.endswith("\\"):
            pending += line[:-1]
            continue
        lines.append((start, pending + line))
        pending = ""
    if pending:
        lines.append((start, pending))
    return lines


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


def includes_of(name: str, text: str, known: dict[str, str]) -> tuple[list[tuple[int, str]], list[str]]:
    edges = []
    problems = []
    for number, line in logical_lines(text):
        directive = DIRECTIVE.match(line)
        if directive is None:
            continue
        named = NAMED.match(directive.group(1))
        if named is None:
            problems.append(f"{name}:{number}: an include must name its header in quotes or angle brackets")
            continue
        quoted = named.group(1) is not None
        written = named.group(1) if quoted else named.group(2)
        if ABSOLUTE.match(written):
            problems.append(f"{name}:{number}: an include must not use an absolute path")
            continue
        target = resolve(name, written, quoted, known)
        if target is None:
            if quoted:
                problems.append(f"{name}:{number}: \"{written}\" is not a file of this repository")
            elif name.startswith(PUBLIC) and not STANDARD_HEADER.match(written):
                problems.append(f"{name}:{number}: a public header includes <{written}>, which is not a standard header")
            continue
        if not is_source(target):
            problems.append(f"{name}:{number}: {target} is included but is not a C or C++ source, so it is never checked")
        if name.startswith(PUBLIC) and not target.startswith(PUBLIC):
            problems.append(f"{name}:{number}: a public header includes {target}, which is not a public header")
        edges.append((number, target))
    return edges, problems


def allowed(name: str, guarded: str) -> bool:
    guard = GUARDED[guarded]
    return name in guard["files"] or name.startswith(guard["under"])


def check(files: dict[str, str], others: tuple[str, ...] = ()) -> list[str]:
    known = {name.casefold(): name for name in (*files, *others)}
    graph = {}
    failures = []
    for name in sorted(files):
        edges, problems = includes_of(name, files[name], known)
        graph[name] = edges
        failures.extend(problems)
    reach = {}

    def reached(name: str, trail: frozenset[str]) -> frozenset[str]:
        if name in reach:
            return reach[name]
        if name in trail:
            return frozenset()
        found = set()
        for _, target in graph.get(name, ()):
            if target in GUARDED:
                found.add(target)
            found |= reached(target, trail | {name})
        reach[name] = frozenset(found)
        return reach[name]

    for name in sorted(graph):
        for number, target in graph[name]:
            carried = set(reached(target, frozenset({name})))
            if target in GUARDED:
                carried.add(target)
            for guarded in sorted(carried):
                if not allowed(name, guarded):
                    through = "" if guarded == target else f" through {target}"
                    guard = GUARDED[guarded]
                    owners = ", ".join(guard["files"] + guard["under"])
                    failures.append(f"{name}:{number}: {guarded}{through} may be included only by {owners}")
    return failures


def repository_files(repository: pathlib.Path) -> tuple[list[str], list[str]]:
    staged = subprocess.run(
        ["git", "ls-files", "-z", "-s"], cwd=repository, check=True, capture_output=True
    ).stdout.decode("utf-8")
    links = sorted(
        entry.split("\t", 1)[1] for entry in staged.split("\0") if entry.startswith("120000 ") and "\t" in entry
    )
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=repository,
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8")
    names = sorted(
        {name for name in listing.split("\0") if name and not name.startswith(EXCLUDED) and (repository / name).is_file()}
    )
    return names, [link for link in links if not link.startswith(EXCLUDED)]


def main() -> int:
    repository = pathlib.Path(__file__).resolve().parent.parent
    names, links = repository_files(repository)
    sources = {name: (repository / name).read_text(encoding="utf-8") for name in names if is_source(name)}
    failures = [f"{link}: a symbolic link hides what a file is; use a real file" for link in links]
    failures.extend(check(sources, tuple(names)))
    for failure in failures:
        print(failure)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
