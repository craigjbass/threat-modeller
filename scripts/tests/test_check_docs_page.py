import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check_docs_page as c


GOOD = """<style>A</style>
<div class="toc"><a class="blink" href="#1-notation">notation</a></div>
<h2 id="1-notation">1. Notation</h2>
<table><tr><td>x</td></tr></table>
<pre><code>Block = "system" ;</code></pre>
<a href="#1-notation">up</a>
<a href="https://github.com/craigjbass/threat-modeller">source</a>
"""


class CheckTests(unittest.TestCase):
    def test_reports_a_slot_that_the_build_left_behind(self):
        faults = c.faults(GOOD + "{{BODY}}", headings=1)
        self.assertIn("slot", " ".join(faults))

    def test_reports_too_few_headings(self):
        faults = c.faults(GOOD, headings=2)
        self.assertIn("heading", " ".join(faults))

    def test_reports_a_missing_table(self):
        page = GOOD.replace("<table><tr><td>x</td></tr></table>", "")
        self.assertIn("table", " ".join(c.faults(page, headings=1)))

    def test_reports_a_missing_code_block(self):
        page = GOOD.replace('<pre><code>Block = "system" ;</code></pre>', "")
        self.assertIn("code block", " ".join(c.faults(page, headings=1)))

    def test_reports_a_relative_link(self):
        page = GOOD + '<a href="../README.md">readme</a>'
        self.assertIn("relative link", " ".join(c.faults(page, headings=1)))

    def test_leaves_the_navigation_link_of_the_other_page_alone(self):
        page = GOOD + '<a href="index.html">home</a>'
        self.assertNotIn("relative link", " ".join(c.faults(page, headings=1)))

    def test_leaves_a_navigation_link_with_a_fragment_alone(self):
        page = GOOD + '<a href="index.html#download">download</a>'
        self.assertNotIn("relative link", " ".join(c.faults(page, headings=1)))

    def test_reports_a_heading_the_contents_does_not_link_to(self):
        page = GOOD + '<h2 id="2-lexical-structure">2. Lexical structure</h2>'
        self.assertIn("2-lexical-structure", " ".join(c.faults(page, headings=1)))

    def test_finds_no_fault_in_a_good_page(self):
        self.assertEqual([], c.faults(GOOD, headings=1))

    def test_reports_a_picture_the_directory_lacks(self):
        faults = c.asset_faults('<img src="screenshot.png" />', ".")
        self.assertIn("screenshot.png", " ".join(faults))

    def test_finds_no_fault_when_the_picture_is_there(self):
        directory = str(Path(__file__).resolve().parents[2] / "docs")
        self.assertEqual([], c.asset_faults('<img src="LANGUAGE.md" />', directory))

    def test_leaves_a_picture_on_another_host_alone(self):
        self.assertEqual([], c.asset_faults('<img src="https://x/y.png" />', "."))

    def test_reports_a_style_block_that_differs(self):
        self.assertEqual([], c.style_faults("<style>A</style>", "<style>A</style>"))
        self.assertEqual(
            1, len(c.style_faults("<style>A</style>", "<style>B</style>"))
        )


if __name__ == "__main__":
    unittest.main()
