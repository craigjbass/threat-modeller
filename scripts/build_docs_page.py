#!/usr/bin/env python3
"""Renders docs/LANGUAGE.md into the documentation page template.

The template holds two slots. {{TOC}} takes one bracketed link for each
second-level heading of the guide. {{BODY}} takes the rendered guide.
"""

import argparse
import posixpath
import re
import sys

import markdown

REPOSITORY = "https://github.com/craigjbass/threat-modeller"
BLOB = REPOSITORY + "/blob/main"
SOURCE_DIRECTORY = "docs"

HEADING = re.compile(r"^## +(.*?)\s*$", re.MULTILINE)
LEADING_NUMBER = re.compile(r"^\d+(\.\d+)*\.?\s+")
HREF = re.compile(r'href="([^"]*)"')


def strip_contents(text):
    """Removes the `## Contents` section, up to the next second-level heading."""
    output = []
    inside = False
    for line in text.split("\n"):
        if line.startswith("## "):
            inside = line[3:].strip().lower() == "contents"
        if not inside:
            output.append(line)
    return "\n".join(output)


def slug(title):
    """Gives the id the toc extension of markdown writes for a heading."""
    text = title.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"[\s_]+", "-", text).strip("-")


def build_toc(text):
    """Gives one bracketed link for each second-level heading."""
    links = []
    for title in HEADING.findall(text):
        label = LEADING_NUMBER.sub("", title).lower()
        links.append('<a class="blink" href="#%s">%s</a>' % (slug(title), label))
    return "".join(links)


def rewrite_links(html):
    """Points every relative link at the file in the repository."""

    def replace(match):
        target = match.group(1)
        if target.startswith(("#", "http:", "https:", "mailto:")):
            return match.group(0)
        path, _, fragment = target.partition("#")
        resolved = posixpath.normpath(posixpath.join(SOURCE_DIRECTORY, path))
        url = BLOB + "/" + resolved
        if fragment:
            url = url + "#" + fragment
        return 'href="%s"' % url

    return HREF.sub(replace, html)


def render(text):
    return markdown.markdown(text, extensions=["tables", "fenced_code", "toc"])


def build(template, source):
    if "{{TOC}}" not in template:
        raise ValueError("the template holds no {{TOC}} slot")
    if "{{BODY}}" not in template:
        raise ValueError("the template holds no {{BODY}} slot")
    guide = strip_contents(source)
    body = rewrite_links(render(guide))
    return template.replace("{{TOC}}", build_toc(guide)).replace("{{BODY}}", body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    try:
        with open(arguments.template, encoding="utf-8") as handle:
            template = handle.read()
        with open(arguments.source, encoding="utf-8") as handle:
            source = handle.read()
        page = build(template, source)
    except (OSError, ValueError) as fault:
        print("build_docs_page: %s" % fault, file=sys.stderr)
        return 1
    with open(arguments.output, "w", encoding="utf-8") as handle:
        handle.write(page)
    return 0


if __name__ == "__main__":
    sys.exit(main())
