import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import build_docs_page as b


SAMPLE = """# The language

## Contents

- [one](#1-notation)
- [two](#2-lexical-structure)

## 1. Notation

Read [the README](../README.md) and [the tests](TESTING.md).

## 2. Lexical structure

| Token | Meaning |
| --- | --- |
| `{` | open |

```
Block = "system" ;
```
"""


class StripContentsTests(unittest.TestCase):
    def test_removes_the_contents_section(self):
        result = b.strip_contents(SAMPLE)
        self.assertNotIn("## Contents", result)
        self.assertNotIn("- [one](#1-notation)", result)

    def test_keeps_every_other_section(self):
        result = b.strip_contents(SAMPLE)
        self.assertIn("## 1. Notation", result)
        self.assertIn("## 2. Lexical structure", result)

    def test_keeps_the_title(self):
        self.assertTrue(b.strip_contents(SAMPLE).startswith("# The language"))


class BuildTocTests(unittest.TestCase):
    def test_holds_one_bracketed_link_for_each_second_level_heading(self):
        toc = b.build_toc(b.strip_contents(SAMPLE))
        self.assertIn('<a class="blink" href="#1-notation">notation</a>', toc)
        self.assertIn(
            '<a class="blink" href="#2-lexical-structure">lexical structure</a>',
            toc,
        )

    def test_drops_the_contents_heading(self):
        self.assertNotIn("#contents", b.build_toc(b.strip_contents(SAMPLE)))

    def test_ignores_third_level_headings(self):
        toc = b.build_toc("## 4. Four\n\n### 4.1 Grammar\n")
        self.assertNotIn("grammar", toc)


class RewriteLinksTests(unittest.TestCase):
    def test_rewrites_a_link_that_leaves_the_docs_directory(self):
        html = '<a href="../README.md">readme</a>'
        self.assertIn(
            'href="https://github.com/craigjbass/threat-modeller/blob/main/README.md"',
            b.rewrite_links(html),
        )

    def test_rewrites_a_link_beside_the_guide(self):
        html = '<a href="TESTING.md">tests</a>'
        self.assertIn(
            'href="https://github.com/craigjbass/threat-modeller/blob/main/docs/TESTING.md"',
            b.rewrite_links(html),
        )

    def test_keeps_the_fragment_of_a_rewritten_link(self):
        html = '<a href="../README.md#scoring">scoring</a>'
        self.assertIn("/blob/main/README.md#scoring", b.rewrite_links(html))

    def test_leaves_an_anchor_alone(self):
        html = '<a href="#7-diagnostics">diagnostics</a>'
        self.assertEqual(html, b.rewrite_links(html))

    def test_leaves_an_absolute_link_alone(self):
        html = '<a href="https://example.com/x">x</a>'
        self.assertEqual(html, b.rewrite_links(html))


class BuildTests(unittest.TestCase):
    TEMPLATE = "<nav></nav>{{TOC}}<main>{{BODY}}</main>"

    def test_fills_both_slots(self):
        page = b.build(self.TEMPLATE, SAMPLE)
        self.assertNotIn("{{TOC}}", page)
        self.assertNotIn("{{BODY}}", page)

    def test_renders_the_headings_with_an_id(self):
        page = b.build(self.TEMPLATE, SAMPLE)
        self.assertIn('<h2 id="1-notation">', page)

    def test_renders_a_table(self):
        self.assertIn("<table>", b.build(self.TEMPLATE, SAMPLE))

    def test_renders_a_fenced_block(self):
        self.assertIn("<pre>", b.build(self.TEMPLATE, SAMPLE))

    def test_rewrites_the_links_of_the_body(self):
        page = b.build(self.TEMPLATE, SAMPLE)
        self.assertNotIn('href="../README.md"', page)

    def test_refuses_a_template_without_a_toc_slot(self):
        with self.assertRaises(ValueError):
            b.build("<main>{{BODY}}</main>", SAMPLE)

    def test_refuses_a_template_without_a_body_slot(self):
        with self.assertRaises(ValueError):
            b.build("{{TOC}}", SAMPLE)


if __name__ == "__main__":
    unittest.main()
