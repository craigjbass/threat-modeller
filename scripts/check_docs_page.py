#!/usr/bin/env python3
"""Checks the rendered documentation page, and the style block of both pages."""

import argparse
import re
import sys

HEADING_ID = re.compile(r'<h2 id="([^"]+)"')
TOC_LINK = re.compile(r'<a class="blink" href="#([^"]+)"')
HREF = re.compile(r'href="([^"]*)"')
STYLE = re.compile(r"<style>.*?</style>", re.DOTALL)

MINIMUM_HEADINGS = 10


def faults(page, headings=MINIMUM_HEADINGS):
    """Gives one line for each fault of the rendered page."""
    found = []
    if "{{TOC}}" in page or "{{BODY}}" in page:
        found.append("the page still holds a template slot")
    identifiers = HEADING_ID.findall(page)
    if len(identifiers) < headings:
        found.append(
            "the page holds %d second-level headings, and needs %d"
            % (len(identifiers), headings)
        )
    if "<table>" not in page:
        found.append("the page holds no table")
    if "<pre>" not in page:
        found.append("the page holds no code block")
    for target in HREF.findall(page):
        if target.startswith(("#", "http:", "https:", "mailto:")):
            continue
        if target.partition("#")[0].endswith(".html"):
            continue  # the navigation bar points at the other page of the site
        found.append("the page holds a relative link: %s" % target)
    linked = set(TOC_LINK.findall(page))
    for identifier in identifiers:
        if identifier not in linked:
            found.append("the contents links to no heading %s" % identifier)
    return found


def style_faults(index, template):
    """Gives one line when the two style blocks are not the same."""
    first = STYLE.search(index)
    second = STYLE.search(template)
    if not first or not second:
        return ["one of the two pages holds no style block"]
    if first.group(0) != second.group(0):
        return ["the style block of the two pages is not the same"]
    return []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--page", required=True)
    parser.add_argument("--index", required=True)
    parser.add_argument("--template", required=True)
    arguments = parser.parse_args()
    with open(arguments.page, encoding="utf-8") as handle:
        page = handle.read()
    with open(arguments.index, encoding="utf-8") as handle:
        index = handle.read()
    with open(arguments.template, encoding="utf-8") as handle:
        template = handle.read()
    found = faults(page) + style_faults(index, template)
    for line in found:
        print("check_docs_page: %s" % line, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
