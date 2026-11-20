# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

import argparse
import hashlib
import http.server
import json
import posixpath
import re
import shutil
import string
import sys
import tomllib
from dataclasses import dataclass
from functools import partial
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import logo
import render

SITE = Path(__file__).resolve().parent
ROOT = SITE.parent
OUTPUT = ROOT / "build" / "site"
CACHE = ROOT / "build" / "site-cache"
POLICY = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'"
HEADERS = {
    "Content-Security-Policy": POLICY + "; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}
REVISION = re.compile(r"\brevision (\d+)\b")
TOKEN = re.compile(r"\{\{([a-z0-9-]+)\}\}")
STYLE_URL = re.compile(r"url\(([^)]*)\)")
DOCS_GROUPS = ("guide", "open-source", "legal", "spec")
LEADING_COMMENT = re.compile(r"\A\s*<!--.*?-->\s*", re.S)
LEADING_STYLE_COMMENT = re.compile(r"\A\s*/\*.*?\*/\s*", re.S)
URL_ATTRIBUTE = re.compile(r'\b(href|src)="([^"]*)"')
TAG = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>")
ATTRIBUTE = re.compile(r'\b(href|src|srcset)="([^"]*)"')
SCRIPT = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.S | re.I)
SOURCE = re.compile(r'\bsrc="([^"]*)"')
SCRIPT_NAME = "site.js"
IDENTIFIER = re.compile(r'\bid="([^"]*)"')
FORBIDDEN_TAGS = {"iframe", "object", "embed", "form", "base", "frame", "frameset"}
HANDLER_ATTRIBUTE = re.compile(r"\bon[a-z]+\s*=", re.I)
STYLE_ATTRIBUTE = re.compile(r"\bstyle\s*=", re.I)
EXTERNAL = ("https://", "http://", "mailto:")


class BuildError(Exception):
    pass


@dataclass(frozen=True)
class Page:
    route: str
    source: PurePosixPath | None
    group: str
    summary: str
    generate: str
    title: str

    @property
    def directory(self) -> PurePosixPath:
        return PurePosixPath(self.route)

    @property
    def output(self) -> PurePosixPath:
        if self.generate == "not-found":
            return PurePosixPath("404.html")
        return self.directory / "index.html"


@dataclass
class Rendered:
    title: str
    main: str
    kind: str


def relative(start: PurePosixPath, target: PurePosixPath, directory: bool) -> str:
    path = posixpath.relpath(str(target), str(start))
    if directory:
        return "./" if path == "." else path + "/"
    return path


def strip_leading_comment(text: str) -> str:
    return LEADING_COMMENT.sub("", text, count=1)


def spec_revision() -> str:
    match = REVISION.search((ROOT / "docs" / "CRYPTO.md").read_text(encoding="utf-8"))
    if match is None:
        raise BuildError("docs/CRYPTO.md does not state its revision")
    return match[1]


class Site:
    def __init__(self, config: dict, output: Path, base: str = "/") -> None:
        self.config = config
        self.output = output
        self.base = base
        self.repository = config["repository"]
        self.reference = config["reference"]
        self.language: str = config["language"]
        self.moved: list[str] = config.get("moved", [])
        self.strings: dict = config["strings"]
        self.pages: list[Page] = []
        for entry in config["pages"]:
            source = entry.get("source")
            self.pages.append(Page(
                route=entry["route"],
                source=PurePosixPath(source) if source else None,
                group=entry.get("group", ""),
                summary=entry.get("summary", ""),
                generate=entry.get("generate", ""),
                title=entry.get("title", ""),
            ))
        self.by_source = {page.source: page for page in self.pages if page.source}
        self.by_route = {page.route: page for page in self.pages if page.generate != "not-found"}
        for prefix in self.moved:
            if prefix in self.by_route:
                raise BuildError(f"the moved prefix {prefix} is also a page")
        self.tokens = {"spec-revision": spec_revision(), "repository": self.repository}
        self.documents: dict[Page, render.Document] = {}

    def page_root(self, page: Page) -> str:
        if page.generate == "not-found":
            return self.base
        return relative(page.directory, PurePosixPath(), True)

    def link_to_page(self, page: Page, target: Page, fragment: str) -> str:
        if page.generate == "not-found":
            href = self.base + "".join(part + "/" for part in target.directory.parts)
        else:
            href = relative(page.directory, target.directory, True)
        return href + (f"#{fragment}" if fragment else "")

    def repository_url(self, path: PurePosixPath, fragment: str) -> str:
        kind = "tree" if (ROOT / path).is_dir() else "blob"
        url = f"{self.repository}/{kind}/{self.reference}/{quote(str(path))}"
        return url + (f"#{fragment}" if fragment else "")

    def resolve(self, page: Page, href: str) -> str:
        if href.startswith(EXTERNAL) or href.startswith("#"):
            return href
        path, _, fragment = href.partition("#")
        if path.startswith("/"):
            return self.resolve_route(page, path, fragment)
        assert page.source is not None
        source = PurePosixPath(posixpath.normpath(posixpath.join(str(page.source.parent), path)))
        target = self.by_source.get(source)
        if target is not None:
            return self.link_to_page(page, target, fragment)
        if not (ROOT / source).exists():
            raise BuildError(f"{page.source}: link to a missing file: {href}")
        return self.repository_url(source, fragment)

    def resolve_route(self, page: Page, path: str, fragment: str) -> str:
        route = path.strip("/")
        if PurePosixPath(route).suffix:
            if page.generate == "not-found":
                return self.base + route
            return relative(page.directory, PurePosixPath(route), False)
        first, _, rest = route.partition("/")
        if first in self.moved:
            route = rest
        target = self.by_route.get(route)
        if target is None:
            raise BuildError(f"{page.source or page.route}: no page at {path}")
        return self.link_to_page(page, target, fragment)

    def substitute(self, page: Page, text: str) -> str:
        def token(match: re.Match[str]) -> str:
            if match[1] not in self.tokens:
                raise BuildError(f"{page.source}: unknown token {match[0]}")
            return self.tokens[match[1]]

        return TOKEN.sub(token, text)

    def resolve_fragment_links(self, page: Page, text: str) -> str:
        return URL_ATTRIBUTE.sub(lambda match: f'{match[1]}="{render.attribute(self.resolve(page, match[2]))}"', text)

    def document(self, page: Page) -> render.Document:
        if page not in self.documents:
            assert page.source is not None
            text = (ROOT / page.source).read_text(encoding="utf-8")
            if page.source.parts[0] == "site":
                text = self.substitute(page, text)
            self.documents[page] = render.render(text, partial(self.resolve, page))
        return self.documents[page]

    def build(self) -> None:
        if self.output.exists():
            shutil.rmtree(self.output)
        self.output.mkdir(parents=True)
        stylesheet = LEADING_STYLE_COMMENT.sub("", (SITE / "style.css").read_text(encoding="utf-8"), count=1)
        (self.output / "style.css").write_text(stylesheet, encoding="utf-8", newline="\n")
        shutil.copytree(SITE / "fonts", self.output / "fonts")
        shutil.copyfile(SITE / SCRIPT_NAME, self.output / SCRIPT_NAME)
        shutil.copyfile(ROOT / "brand" / "lume-favicon.svg", self.output / "favicon.svg")
        self.images()
        layout = string.Template(strip_leading_comment((SITE / "layout.html").read_text(encoding="utf-8")))
        for page in self.pages:
            rendered = self.render_page(page)
            self.write(page.output, layout.substitute(self.layout_values(page, rendered)))
        for prefix in self.moved:
            for page in self.pages:
                if page.generate != "not-found":
                    self.write(PurePosixPath(prefix) / page.output, layout.substitute(self.moved_values(prefix, page)))

    def write(self, name: PurePosixPath, html: str) -> None:
        target = self.output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(html, encoding="utf-8", newline="\n")

    def render_page(self, page: Page) -> Rendered:
        if page.generate == "legal":
            return self.legal_index(page)
        if page.generate == "docs":
            return self.docs_index(page)
        assert page.source is not None
        if page.source.suffix == ".html":
            text = strip_leading_comment((ROOT / page.source).read_text(encoding="utf-8"))
            main = self.resolve_fragment_links(page, self.substitute(page, text))
            if page.generate == "not-found":
                kind = "not-found"
            else:
                kind = "home" if page.route == "" else "page"
            return Rendered(page.title, main, kind)
        if page.source.suffix == ".md":
            return Rendered(self.document(page).title, self.article(page, self.document(page)), "page")
        text = render.escape((ROOT / page.source).read_text(encoding="utf-8"))
        main = self.article_frame(page, page.title, "", f'<pre class="licence">{text}</pre>')
        return Rendered(page.title, main, "page")

    def article(self, page: Page, document: render.Document) -> str:
        words = self.strings
        sections = [heading for heading in document.headings if heading.level == 2]
        contents = ""
        if len(sections) >= 4:
            entries = "".join(
                f'<li><a href="#{render.attribute(heading.anchor)}">{render.escape(heading.text)}</a></li>'
                for heading in sections
            )
            contents = f'<nav class="contents" aria-label="{words["contents"]}"><p>{words["contents"]}</p><ul>{entries}</ul></nav>'
        return self.article_frame(page, document.title, contents, f'<div class="prose">\n{document.body}\n</div>')

    def article_frame(self, page: Page, title: str, contents: str, body: str) -> str:
        words = self.strings
        eyebrow = words["groups"].get(page.group, "")
        home = self.link_to_page(page, self.by_route[""], "")
        group = f"<span>{eyebrow}</span>" if eyebrow else ""
        eyebrow_html = f'<p class="eyebrow"><a href="{home}">LUME</a>{group}</p>'
        note = words["notes"].get(page.group, "")
        note_html = f'<p class="note">{self.substitute(page, note)}</p>' if note else ""
        source = ""
        if page.source is not None and page.source.parts[0] != "site":
            view = self.repository_url(page.source, "")
            history = f"{self.repository}/commits/{self.reference}/{quote(str(page.source))}"
            source = (
                f'<p class="source">{words["source"]} <a href="{view}"><code>{page.source}</code></a>'
                f' · <a href="{history}">{words["history"]}</a></p>'
            )
        width = " wide" if page.group == "spec" else ""
        return (
            f'<article class="doc{width}">\n<header class="doc-head">{eyebrow_html}<h1>{render.escape(title)}</h1>{note_html}</header>\n'
            f"{contents}\n{body}\n{source}\n</article>"
        )

    def docs_index(self, page: Page) -> Rendered:
        words = self.strings
        groups = []
        for group in DOCS_GROUPS:
            items = []
            for target in self.pages:
                if target.group != group:
                    continue
                title = target.title or self.document(target).title
                items.append(
                    f'<li><a href="{self.link_to_page(page, target, "")}"><span class="title">{render.escape(title)}</span>'
                    f'<span class="summary">{render.escape(target.summary)}</span></a></li>'
                )
            groups.append(f'<section class="docs-group"><h2>{words["groups"][group]}</h2><ul class="index">{"".join(items)}</ul></section>')
        return Rendered(page.title, self.article_frame(page, page.title, "", "\n".join(groups)), "page")

    def legal_index(self, page: Page) -> Rendered:
        words = self.strings
        items = []
        for target in self.pages:
            if target.group != "legal":
                continue
            title = self.document(target).title
            href = self.link_to_page(page, target, "")
            items.append(
                f'<li><a href="{href}"><span class="title">{render.escape(title)}</span>'
                f'<span class="summary">{render.escape(target.summary)}</span></a></li>'
            )
        intro = "".join(f"<p>{self.substitute(page, paragraph)}</p>" for paragraph in words["legal-intro"])
        body = f'<div class="prose">{intro}</div>\n<ul class="index">{"".join(items)}</ul>'
        return Rendered(page.title, self.article_frame(page, page.title, "", body), "page")

    def footer(self, page: Page) -> str:
        if page.generate == "not-found":
            return ""
        words = self.strings
        home = self.link_to_page(page, self.by_route[""], "")
        docs = self.link_to_page(page, self.by_route["docs"], "")
        privacy = self.link_to_page(page, self.by_route["legal/privacy"], "")
        return (
            '<footer class="site-footer"><div class="bar">'
            f'<div class="footer-top"><a class="wordmark" href="{home}">LUME</a></div>'
            f'<p class="imprint"><span>{words["imprint"]}</span><a href="{docs}">{words["footer-docs"]}</a>'
            f'<a href="{privacy}">{words["footer-privacy"]}</a></p>'
            "</div></footer>"
        )

    def title_of(self, page: Page, rendered: Rendered) -> str:
        title = rendered.title or self.strings["site-title"]
        if page.route and page.generate != "not-found" and "LUME" not in title:
            title = f"{title} — LUME"
        return title

    def layout_values(self, page: Page, rendered: Rendered) -> dict[str, str]:
        return {
            "lang": self.language,
            "title": render.escape(self.title_of(page, rendered)),
            "description": render.attribute(page.summary or self.strings["description"]),
            "policy": POLICY,
            "root": self.page_root(page),
            "kind": rendered.kind,
            "skip": self.strings["skip"],
            "main": rendered.main,
            "footer": self.footer(page),
            "head": "",
        }

    def moved_values(self, prefix: str, page: Page) -> dict[str, str]:
        directory = PurePosixPath(prefix) / page.directory
        target = relative(directory, page.directory, True)
        title = self.title_of(page, self.render_page(page))
        return {
            "lang": self.language,
            "title": render.escape(title),
            "description": render.attribute(page.summary or self.strings["description"]),
            "policy": POLICY,
            "root": relative(directory, PurePosixPath(), True),
            "kind": "moved",
            "skip": self.strings["skip"],
            "main": f'<p class="moved"><a href="{render.attribute(target)}">{self.strings["moved"]}</a></p>',
            "footer": "",
            "head": f'<meta http-equiv="refresh" content="0; url={render.attribute(target)}">\n<link rel="canonical" href="{render.attribute(target)}">',
        }

    def images(self) -> None:
        code = (SITE / "logo.py").read_bytes()
        for entry in self.config["images"]:
            source = ROOT / entry["source"]
            key = hashlib.sha256(code + source.read_bytes() + json.dumps(entry, sort_keys=True).encode()).hexdigest()
            cached = CACHE / key
            if not cached.exists():
                self.make_images(source, entry, cached)
            for name, _ in entry["outputs"]:
                target = self.output / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(cached / PurePosixPath(name).name, target)

    def make_images(self, source: Path, entry: dict, cached: Path) -> None:
        image = logo.read(source)
        margin = entry["margin"]
        side = min(image.width, image.height) - 2 * margin
        image = logo.crop(image, (image.width - side) // 2, (image.height - side) // 2, side)
        largest = max(size for _, size in entry["outputs"])
        image = logo.shrink(image, max(1, side // largest))
        staging = cached.with_suffix(".tmp")
        staging.mkdir(parents=True, exist_ok=True)
        for name, size in entry["outputs"]:
            sized = image if image.width == size else logo.resize(image, size)
            logo.write(sized, staging / PurePosixPath(name).name)
        staging.replace(cached)

    def gap_report(self) -> list[str]:
        lines = []
        for page, document in self.documents.items():
            count = document.alerts.get("important", 0)
            if count:
                lines.append(f"  {page.source}: {count}")
        return sorted(lines)


def check(output: Path, base: str = "/") -> list[str]:
    problems: list[str] = []
    pages = sorted(output.rglob("*.html"))
    identifiers = {path: set(IDENTIFIER.findall(path.read_text(encoding="utf-8"))) for path in pages}
    for path in pages:
        text = path.read_text(encoding="utf-8")
        name = path.relative_to(output).as_posix()
        found = IDENTIFIER.findall(text)
        for identifier in sorted({identifier for identifier in found if found.count(identifier) > 1}):
            problems.append(f"{name}: id {identifier} is used more than once")
        scripts = SCRIPT.findall(text)
        if len(scripts) != sum(1 for tag, _ in TAG.findall(text) if tag.lower() == "script"):
            problems.append(f"{name}: carries a <script> that is not closed")
        for attributes, body in scripts:
            source = SOURCE.search(attributes)
            if body.strip() or source is None or PurePosixPath(source[1]).name != SCRIPT_NAME:
                problems.append(f"{name}: carries a script other than {SCRIPT_NAME}")
        for tag, attributes in TAG.findall(text):
            if tag.lower() in FORBIDDEN_TAGS:
                problems.append(f"{name}: contains <{tag}>")
            if HANDLER_ATTRIBUTE.search(attributes) or STYLE_ATTRIBUTE.search(attributes):
                problems.append(f"{name}: <{tag}> carries a style or event handler attribute")
            for attribute, value in ATTRIBUTE.findall(attributes):
                for url in [part.strip().split(" ")[0] for part in value.split(",")] if attribute == "srcset" else [value]:
                    problems += check_url(output, base, path, name, tag.lower(), url, identifiers)
    stylesheet = (output / "style.css").read_text(encoding="utf-8")
    if "@import" in stylesheet or "/*" in stylesheet:
        problems.append("style.css: imports a stylesheet or carries a comment")
    for target in STYLE_URL.findall(stylesheet):
        location = target.strip("\"'")
        if not location.startswith("fonts/") or ".." in location or not (output / location).is_file():
            problems.append(f"style.css: loads {location}, which is not a font served by this site")
    script = output / SCRIPT_NAME
    if script.is_file():
        code = script.read_text(encoding="utf-8")
        for forbidden in ("://", "eval(", "Function(", "innerHTML", "fetch(", "XMLHttpRequest", "import("):
            if forbidden in code:
                problems.append(f"{SCRIPT_NAME}: uses {forbidden}")
    return problems


def check_url(output: Path, base: str, path: Path, name: str, tag: str, url: str, identifiers: dict[Path, set[str]]) -> list[str]:
    if url.startswith(EXTERNAL):
        return [] if tag == "a" else [f"{name}: <{tag}> loads {url} from another server"]
    if url.startswith("//") or ":" in url.split("/")[0]:
        return [f"{name}: unexpected URL {url}"]
    location, _, fragment = url.partition("#")
    if not location:
        target = path
    elif location.startswith("/"):
        if not location.startswith(base):
            return [f"{name}: link outside the site {url}"]
        target = output / location[len(base):]
    else:
        target = path.parent / location
    if target.is_dir():
        target = target / "index.html"
    target = target.resolve()
    if not target.exists() or output.resolve() not in target.parents:
        return [f"{name}: broken link {url}"]
    if fragment and target.suffix == ".html" and fragment not in identifiers.get(target, set()):
        return [f"{name}: missing anchor {url}"]
    return []


class PreviewHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self) -> None:
        for header, value in HEADERS.items():
            self.send_header(header, value)
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the LUME website into a static directory.")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--serve", action="store_true", help="serve the result on 127.0.0.1 after building")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--base", default="/", help="the path the site is served under, such as /lume/")
    arguments = parser.parse_args()
    if not (arguments.base.startswith("/") and arguments.base.endswith("/")):
        print("--base must start and end with /", file=sys.stderr)
        return 1
    with (SITE / "site.toml").open("rb") as handle:
        config = tomllib.load(handle)
    output = arguments.output.resolve()
    try:
        site = Site(config, output, arguments.base)
        site.build()
    except BuildError as error:
        print(f"build failed: {error}", file=sys.stderr)
        return 1
    problems = check(output, arguments.base)
    for problem in problems:
        print(f"check failed: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"built {len(site.pages)} pages into {output}")
    gaps = site.gap_report()
    if gaps:
        print("open gaps to fill before release:")
        print("\n".join(gaps))
    if arguments.serve:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", arguments.port), partial(PreviewHandler, directory=str(output)))
        print(f"serving http://127.0.0.1:{arguments.port}/")
        server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
