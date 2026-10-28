# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

import html
import re
from collections.abc import Callable
from dataclasses import dataclass, field

FENCE = re.compile(r"^( {0,3})(`{3,})(.*)$")
HEADING = re.compile(r"^ {0,3}(#{1,6})[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$")
RULE = re.compile(r"^ {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$")
QUOTE = re.compile(r"^ {0,3}> ?(.*)$")
ITEM = re.compile(r"^( {0,3})([-*+]|\d{1,9}[.)])(?:( {1,4})(.*))?$")
DELIMITER_CELL = re.compile(r"^:?-+:?$")
ALERT = re.compile(r"^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\][ \t]*$")
CODE_SPAN = re.compile(r"(`+)(.+?)(?<!`)\1(?!`)", re.S)
ESCAPED = re.compile(r"\\([!\"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~])")
AUTOLINK = re.compile(r"<(https?://[^>\s]+|mailto:[^>\s]+)>")
LINK = re.compile(r"\[((?:[^\[\]]|\[[^\[\]]*\])*)\]\(<?([^)\s>]*)>?(?:[ \t]+\"([^\"]*)\")?\)")
STRONG = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*", re.S)
EMPHASIS = re.compile(r"(?<![*\w])\*(?=[^\s*])(.+?)(?<=[^\s*])\*(?![*\w])", re.S)
PLACEHOLDER = re.compile("\ue000(\\d+)\ue001")
TAG = re.compile(r"<[^>]+>")


@dataclass
class Heading:
    level: int
    text: str
    anchor: str


@dataclass
class Document:
    title: str
    body: str
    headings: list[Heading] = field(default_factory=list)
    alerts: dict[str, int] = field(default_factory=dict)


def escape(text: str) -> str:
    return html.escape(text, quote=False)


def attribute(text: str) -> str:
    return html.escape(text, quote=True)


def slug(text: str) -> str:
    kept = "".join(char for char in text.strip().lower() if char.isalnum() or char in " -_")
    return kept.replace(" ", "-")


def strip_indent(line: str, width: int) -> str:
    removable = len(line) - len(line.lstrip(" "))
    return line[min(width, removable):]


def table_cells(line: str) -> list[str]:
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|") and not text.endswith("\\|"):
        text = text[:-1]
    cells: list[str] = []
    current: list[str] = []
    in_code = False
    position = 0
    while position < len(text):
        char = text[position]
        if char == "\\" and text[position + 1:position + 2] == "|":
            current.append("\\|")
            position += 2
            continue
        if char == "`":
            in_code = not in_code
        if char == "|" and not in_code:
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        position += 1
    cells.append("".join(current).strip())
    return cells


def alignment(cell: str) -> str:
    if cell.startswith(":") and cell.endswith(":"):
        return "center"
    if cell.endswith(":"):
        return "right"
    return ""


def same_list(marker: str, first: str) -> bool:
    if first[-1] in ".)":
        return marker[-1] == first[-1]
    return marker == first


def plain_text(rendered: str) -> str:
    return html.unescape(TAG.sub("", rendered)).strip()


class Renderer:
    def __init__(self, link: Callable[[str], str] = lambda href: href) -> None:
        self.link = link
        self.title = ""
        self.headings: list[Heading] = []
        self.anchors: dict[str, int] = {}
        self.alerts: dict[str, int] = {}

    def document(self, text: str) -> Document:
        lines = text.replace("\r\n", "\n").expandtabs(4).split("\n")
        body = self.blocks(lines, top=True)
        return Document(self.title, body, self.headings, self.alerts)

    def blocks(self, lines: list[str], tight: bool = False, top: bool = False) -> str:
        out: list[str] = []
        index = 0
        while index < len(lines):
            line = lines[index]
            if not line.strip():
                index += 1
            elif line.lstrip().startswith("<!--"):
                index = self.skip_comment(lines, index)
            elif fence := FENCE.match(line):
                index = self.code(lines, index, fence, out)
            elif heading := HEADING.match(line):
                self.heading(len(heading[1]), heading[2], top, out)
                index += 1
            elif RULE.match(line):
                out.append("<hr>")
                index += 1
            elif QUOTE.match(line):
                index = self.quote(lines, index, out)
            elif self.table_starts(lines, index):
                index = self.table(lines, index, out)
            elif ITEM.match(line):
                index = self.list(lines, index, out)
            else:
                index = self.paragraph(lines, index, tight, out)
        return "\n".join(out)

    def skip_comment(self, lines: list[str], index: int) -> int:
        while index < len(lines) and "-->" not in lines[index]:
            index += 1
        return index + 1

    def code(self, lines: list[str], index: int, fence: re.Match[str], out: list[str]) -> int:
        indent = len(fence[1])
        marker = fence[2]
        body: list[str] = []
        index += 1
        while index < len(lines):
            closing = FENCE.match(lines[index])
            if closing and closing[2].startswith(marker) and not closing[3].strip():
                index += 1
                break
            body.append(strip_indent(lines[index], indent))
            index += 1
        code = escape("\n".join(body))
        out.append(f"<pre><code>{code}</code></pre>")
        return index

    def heading(self, level: int, text: str, top: bool, out: list[str]) -> None:
        rendered = self.inline(text)
        if top and level == 1 and not self.title:
            self.title = plain_text(rendered)
            return
        anchor = self.unique_anchor(slug(plain_text(rendered)))
        self.headings.append(Heading(level, plain_text(rendered), anchor))
        out.append(f'<h{level} id="{attribute(anchor)}">{rendered}</h{level}>')

    def unique_anchor(self, anchor: str) -> str:
        count = self.anchors.get(anchor, 0)
        self.anchors[anchor] = count + 1
        return anchor if count == 0 else f"{anchor}-{count}"

    def quote(self, lines: list[str], index: int, out: list[str]) -> int:
        inner: list[str] = []
        while index < len(lines) and (match := QUOTE.match(lines[index])):
            inner.append(match[1])
            index += 1
        alert = ALERT.match(inner[0].strip()) if inner else None
        if alert:
            kind = alert[1].lower()
            self.alerts[kind] = self.alerts.get(kind, 0) + 1
            out.append(f'<div class="callout {kind}">\n{self.blocks(inner[1:])}\n</div>')
        else:
            out.append(f"<blockquote>\n{self.blocks(inner)}\n</blockquote>")
        return index

    def table_starts(self, lines: list[str], index: int) -> bool:
        if "|" not in lines[index] or index + 1 >= len(lines) or "|" not in lines[index + 1]:
            return False
        delimiters = table_cells(lines[index + 1])
        return all(DELIMITER_CELL.match(cell) for cell in delimiters)

    def table(self, lines: list[str], index: int, out: list[str]) -> int:
        header = table_cells(lines[index])
        aligns = [alignment(cell) for cell in table_cells(lines[index + 1])]
        aligns += [""] * (len(header) - len(aligns))
        index += 2
        rows: list[list[str]] = []
        while index < len(lines) and lines[index].strip() and "|" in lines[index]:
            cells = table_cells(lines[index])
            rows.append((cells + [""] * len(header))[:len(header)])
            index += 1
        parts = ['<div class="table"><table>', "<thead><tr>"]
        parts += [self.cell("th", cell, align) for cell, align in zip(header, aligns)]
        parts += ["</tr></thead>", "<tbody>"]
        for row in rows:
            parts.append("<tr>" + "".join(self.cell("td", cell, align) for cell, align in zip(row, aligns)) + "</tr>")
        parts += ["</tbody>", "</table></div>"]
        out.append("\n".join(parts))
        return index

    def cell(self, tag: str, text: str, align: str) -> str:
        opening = f'<{tag} class="{align}">' if align else f"<{tag}>"
        return f"{opening}{self.inline(text)}</{tag}>"

    def list(self, lines: list[str], index: int, out: list[str]) -> int:
        first = ITEM.match(lines[index])
        assert first is not None
        marker = first[2]
        ordered = marker[-1] in ".)"
        items: list[list[str]] = []
        loose = False
        while index < len(lines):
            match = ITEM.match(lines[index])
            if not match or RULE.match(lines[index]) or not same_list(match[2], marker):
                break
            offset = len(match[1]) + len(match[2]) + (len(match[3]) if match[4] else 1)
            body = [match[4] or ""]
            index += 1
            while index < len(lines):
                line = lines[index]
                if not line.strip():
                    body.append("")
                elif len(line) - len(line.lstrip(" ")) >= offset:
                    body.append(line[offset:])
                elif body[-1].strip() and not FENCE.match(body[-1]) and not ITEM.match(line) and not self.interrupts(line):
                    body.append(line.strip())
                else:
                    break
                index += 1
            while body and not body[-1].strip():
                body.pop()
                if index < len(lines) and ITEM.match(lines[index]):
                    loose = True
            loose = loose or self.has_inner_blank(body)
            items.append(body)
        tag = "ol" if ordered else "ul"
        start = int(marker[:-1]) if ordered else 1
        opening = f'<{tag} start="{start}">' if start != 1 else f"<{tag}>"
        rendered = [f"<li>{self.blocks(item, tight=not loose)}</li>" for item in items]
        out.append(opening + "\n" + "\n".join(rendered) + f"\n</{tag}>")
        return index

    def has_inner_blank(self, body: list[str]) -> bool:
        in_fence = False
        for line in body:
            if FENCE.match(line):
                in_fence = not in_fence
            elif not line.strip() and not in_fence:
                return True
        return False

    def interrupts(self, line: str) -> bool:
        if HEADING.match(line) or FENCE.match(line) or RULE.match(line) or QUOTE.match(line):
            return True
        if line.lstrip().startswith("<!--"):
            return True
        item = ITEM.match(line)
        if item and item[4]:
            return item[2] in "-*+" or item[2][:-1] == "1"
        return False

    def paragraph(self, lines: list[str], index: int, tight: bool, out: list[str]) -> int:
        text = [lines[index].strip()]
        index += 1
        while index < len(lines) and lines[index].strip() and not self.interrupts(lines[index]):
            text.append(lines[index].strip())
            index += 1
        content = self.inline("\n".join(text))
        out.append(content if tight else f"<p>{content}</p>")
        return index

    def inline(self, text: str) -> str:
        stash: list[str] = []
        rendered = self.spans(text, stash)
        while PLACEHOLDER.search(rendered):
            rendered = PLACEHOLDER.sub(lambda match: stash[int(match[1])], rendered)
        return rendered

    def spans(self, text: str, stash: list[str]) -> str:
        def keep(fragment: str) -> str:
            stash.append(fragment)
            return f"\ue000{len(stash) - 1}\ue001"

        text = CODE_SPAN.sub(lambda match: keep(f"<code>{escape(self.code_text(match[2]))}</code>"), text)
        text = ESCAPED.sub(lambda match: keep(escape(match[1])), text)
        text = AUTOLINK.sub(lambda match: keep(self.anchor(match[1], escape(match[1]))), text)
        text = LINK.sub(lambda match: keep(self.anchor(match[2], self.spans(match[1], stash))), text)
        text = escape(text)
        text = STRONG.sub(r"<strong>\1</strong>", text)
        return EMPHASIS.sub(r"<em>\1</em>", text)

    def code_text(self, text: str) -> str:
        text = text.replace("\n", " ")
        if len(text) > 2 and text.startswith(" ") and text.endswith(" ") and text.strip():
            return text[1:-1]
        return text

    def anchor(self, href: str, label: str) -> str:
        return f'<a href="{attribute(self.link(html.unescape(href)))}">{label}</a>'


def render(text: str, link: Callable[[str], str] = lambda href: href) -> Document:
    return Renderer(link).document(text)
