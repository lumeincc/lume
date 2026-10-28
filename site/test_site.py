# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

import tempfile
import tomllib
import unittest
from pathlib import Path

import build
import logo
import render


def body(text: str) -> str:
    return render.render(text).body


class Headings(unittest.TestCase):
    def test_first_heading_is_the_title_and_leaves_the_body(self) -> None:
        document = render.render("<!--\nlicence header\n-->\n\n# Title\n\nText.")
        self.assertEqual(document.title, "Title")
        self.assertEqual(document.body, "<p>Text.</p>")

    def test_anchors_follow_github(self) -> None:
        document = render.render("# T\n\n## 5.6 Why hybrid\n\n## 10. Vault — data at rest\n\n## От чего LUME не защищает\n\n## 5.6 Why hybrid")
        self.assertEqual(
            [heading.anchor for heading in document.headings],
            ["56-why-hybrid", "10-vault--data-at-rest", "от-чего-lume-не-защищает", "56-why-hybrid-1"],
        )

    def test_code_in_a_heading_does_not_reach_the_anchor_as_markup(self) -> None:
        document = render.render("# T\n\n## The `ratchet` state")
        self.assertEqual(document.headings[0].anchor, "the-ratchet-state")


class Blocks(unittest.TestCase):
    def test_a_fence_can_open_a_list_item(self) -> None:
        text = "1. First.\n2. ```\n   a = b\n   ```\n   Then more.\n3. Last."
        self.assertEqual(
            body(text),
            '<ol>\n<li>First.</li>\n<li><pre><code>a = b</code></pre>\nThen more.</li>\n<li>Last.</li>\n</ol>',
        )

    def test_a_blank_line_between_items_makes_the_list_loose(self) -> None:
        self.assertEqual(body("- a\n\n- b"), "<ul>\n<li><p>a</p></li>\n<li><p>b</p></li>\n</ul>")

    def test_nested_lists_and_lazy_continuation(self) -> None:
        self.assertEqual(
            body("- outer\ncontinued\n  - inner\n- next"),
            "<ul>\n<li>outer\ncontinued\n<ul>\n<li>inner</li>\n</ul></li>\n<li>next</li>\n</ul>",
        )

    def test_an_ordered_list_keeps_its_start(self) -> None:
        self.assertTrue(body("3. three\n4. four").startswith('<ol start="3">'))

    def test_tables_keep_alignment_and_escaped_pipes(self) -> None:
        html = body("| a | b |\n|---|:-:|\n| `x|y` | c \\| d |")
        self.assertIn('<th class="center">b</th>', html)
        self.assertIn("<td><code>x|y</code></td>", html)
        self.assertIn('<td class="center">c | d</td>', html)

    def test_alerts_become_callouts_and_are_counted(self) -> None:
        document = render.render("> [!IMPORTANT]\n> **To be filled in:** x\n\n> plain")
        self.assertEqual(document.alerts, {"important": 1})
        self.assertIn('<div class="callout important">', document.body)
        self.assertIn("<blockquote>", document.body)

    def test_a_rule_is_not_a_list(self) -> None:
        self.assertEqual(body("text\n\n---\n\nmore"), "<p>text</p>\n<hr>\n<p>more</p>")


class Inline(unittest.TestCase):
    def test_markup_in_text_is_escaped(self) -> None:
        self.assertEqual(body('<script>alert("x")</script> & 1 < 2'), '<p>&lt;script&gt;alert("x")&lt;/script&gt; &amp; 1 &lt; 2</p>')

    def test_code_spans_protect_their_content(self) -> None:
        self.assertEqual(body("`**a** <b>` and **b**"), "<p><code>**a** &lt;b&gt;</code> and <strong>b</strong></p>")

    def test_emphasis_needs_word_boundaries(self) -> None:
        self.assertEqual(body("*Non-discoverable* hides, 2 * 3 * 4"), "<p><em>Non-discoverable</em> hides, 2 * 3 * 4</p>")

    def test_links_are_rewritten_and_keep_code_labels(self) -> None:
        document = render.render("[`docs/CRYPTO.md`](../docs/CRYPTO.md#1-goals)", lambda href: "rewritten/" + href)
        self.assertEqual(document.body, '<p><a href="rewritten/../docs/CRYPTO.md#1-goals"><code>docs/CRYPTO.md</code></a></p>')

    def test_link_targets_are_escaped(self) -> None:
        document = render.render('[x](a"b)', lambda href: href)
        self.assertIn('href="a&quot;b"', document.body)


class Images(unittest.TestCase):
    def test_a_written_image_reads_back_without_metadata(self) -> None:
        rows = [bytearray((x * 40 + y * 3 + c) % 256 for x in range(6) for c in range(3)) for y in range(6)]
        image = logo.Image(6, 6, 3, rows)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.png"
            logo.write(image, path)
            self.assertEqual(logo.read(path).rows, rows)
            self.assertEqual([kind for kind, _ in logo.chunks(path.read_bytes())], [b"IHDR", b"IDAT", b"IEND"])

    def test_shrinking_averages_blocks(self) -> None:
        rows = [bytearray([0, 0, 0, 255, 255, 255]), bytearray([255, 255, 255, 0, 0, 0])]
        self.assertEqual(logo.shrink(logo.Image(2, 2, 3, rows), 2).rows, [bytearray([127, 127, 127])])

    def test_resizing_gives_the_requested_size(self) -> None:
        image = logo.Image(5, 5, 3, [bytearray(15) for _ in range(5)])
        resized = logo.resize(image, 3)
        self.assertEqual((resized.width, len(resized.rows), len(resized.rows[0])), (3, 3, 9))


class Site(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with (build.SITE / "site.toml").open("rb") as handle:
            cls.config = tomllib.load(handle)
        cls.directory = tempfile.TemporaryDirectory()
        cls.output = Path(cls.directory.name) / "site"
        cls.site = build.Site(cls.config, cls.output)
        cls.site.build()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def test_the_built_site_passes_every_check(self) -> None:
        self.assertEqual(build.check(self.output), [])

    def test_every_policy_is_published_in_every_language(self) -> None:
        sources = {str(page.source) for page in self.site.pages if page.source}
        for policy in (build.ROOT / "legal").glob("*.md"):
            if policy.name == "README.md":
                continue
            self.assertIn(f"legal/{policy.name}", sources)
        published = {(page.language, page.route) for page in self.site.pages if page.group in ("legal", "guide", "open-source")}
        everywhere = {route for _, route in published}
        for language in self.config["languages"]:
            routes = {route for page_language, route in published if page_language == language}
            self.assertEqual(routes, everywhere - {"licence"} if language != "en" else everywhere, language)

    def test_every_page_states_the_content_security_policy(self) -> None:
        for page in self.output.rglob("*.html"):
            self.assertIn(f'content="{build.POLICY}"', page.read_text(encoding="utf-8"))

    def test_the_check_catches_scripts_styles_and_foreign_resources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "style.css").write_text("", encoding="utf-8")
            (output / "index.html").write_text(
                '<script></script><p style="x"></p><img src="https://example.com/a.png">'
                '<a href="missing/">x</a><a href="#nowhere">y</a>',
                encoding="utf-8",
            )
            problems = build.check(output)
        self.assertEqual(len(problems), 5, problems)

    def test_the_stylesheet_may_load_only_this_sites_fonts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "fonts").mkdir()
            (output / "fonts" / "a.woff2").write_bytes(b"font")
            (output / "style.css").write_text(
                "a{src:url(fonts/a.woff2)}b{src:url(fonts/missing.woff2)}c{src:url(https://example.com/f.woff2)}"
                "d{src:url(fonts/../style.css)}e{background:url(img.png)}",
                encoding="utf-8",
            )
            problems = build.check(output)
        self.assertEqual(len(problems), 4, problems)

    def test_the_policy_allows_fonts_only_from_this_site(self) -> None:
        self.assertIn("font-src 'self'", build.POLICY)
        self.assertIn("default-src 'none'", build.POLICY)

    def test_the_policy_allows_scripts_only_from_this_site(self) -> None:
        self.assertIn("script-src 'self'", build.POLICY)
        self.assertNotIn("unsafe-inline", build.POLICY)

    def test_only_the_consent_script_may_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "style.css").write_text("", encoding="utf-8")
            (output / build.SCRIPT_NAME).write_text('fetch("/x")', encoding="utf-8")
            (output / "other.js").write_text("", encoding="utf-8")
            (output / "index.html").write_text(
                f'<script src="{build.SCRIPT_NAME}" defer></script><script>alert(1)</script>'
                '<script src="other.js"></script><p id="a"></p><p id="a"></p>',
                encoding="utf-8",
            )
            problems = build.check(output)
        self.assertEqual(len(problems), 4, problems)

    def test_every_language_page_offers_the_cookie_choice(self) -> None:
        for language in self.config["languages"]:
            text = (self.output / language / "index.html").read_text(encoding="utf-8")
            self.assertIn('<section class="consent"', text)
            self.assertIn('id="consent-preferences"', text)
            self.assertIn('data-consent="reject"', text)
            footer = text[text.index('<footer class="site-footer">'):]
            self.assertIn('data-consent="open"', footer)
        chooser = (self.output / "index.html").read_text(encoding="utf-8")
        self.assertIn(build.SCRIPT_NAME, chooser)
        self.assertNotIn('class="consent"', chooser)

    def test_the_documentation_page_lists_every_guide_policy_and_specification(self) -> None:
        for language in self.config["languages"]:
            text = (self.output / language / "docs" / "index.html").read_text(encoding="utf-8")
            docs = self.site.by_route[(language, "docs")]
            for page in self.site.pages:
                if page.group not in build.DOCS_GROUPS:
                    continue
                if page.language == language or (page.group == "spec" and page.language == self.config["languages"][0]):
                    self.assertIn(f'href="{self.site.link_to_page(docs, page, "")}"', text, (language, page.route))

    def test_every_page_footer_links_documentation_and_privacy(self) -> None:
        for language in self.config["languages"]:
            text = (self.output / language / "how-it-works" / "index.html").read_text(encoding="utf-8")
            footer = text[text.index('<footer class="site-footer">'):]
            self.assertIn('href="../docs/"', footer)
            self.assertIn('href="../legal/privacy/"', footer)
            self.assertNotIn("<header", text[:text.index("<main")])

    def test_the_not_found_page_links_under_the_base_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "site"
            build.Site(self.config, output, "/lume/").build()
            text = (output / "404.html").read_text(encoding="utf-8")
            self.assertIn('href="/lume/ru/"', text)
            self.assertIn('href="/lume/style.css"', text)
            self.assertEqual(build.check(output, "/lume/"), [])
            self.assertNotEqual(build.check(output, "/"), [])

    def test_links_between_languages_resolve(self) -> None:
        privacy = self.site.by_route[("ru", "legal/privacy")]
        self.assertEqual(self.site.resolve(privacy, "PRIVACY.md"), "../../../en/legal/privacy/")
        self.assertEqual(self.site.resolve(privacy, "/en/spec/crypto/#1-goals-and-non-goals"), "../../../en/spec/crypto/#1-goals-and-non-goals")
        self.assertEqual(self.site.resolve(privacy, "/legal/terms/"), "../terms/")
        self.assertTrue(self.site.resolve(privacy, "../CONTRIBUTING.md").startswith(self.config["repository"] + "/blob/"))


if __name__ == "__main__":
    unittest.main()
