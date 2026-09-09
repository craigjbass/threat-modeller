# GitHub Pages Marketing Site Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a two-page marketing site for threat-modeller on GitHub Pages: a landing page written by hand, and a documentation page the build renders from `docs/LANGUAGE.md`.

**Architecture:** Two self-contained HTML files in `docs/`, each holding the same `<style>` block. A Python script fills two slots in a template with a table of contents and the rendered language guide. A GitHub Actions workflow copies `docs/` into a staging directory, runs the script, and uploads the directory to GitHub Pages. No Jekyll, no bundler, no web font, no analytics.

**Tech Stack:** HTML5, CSS custom properties, plain JavaScript for one release-lookup, Python 3.12 with the `markdown` package, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-09-marketing-site-design.md`

## Global Constraints

- The pages load no file from a third-party host. No web font, no CDN, no analytics script.
- One dark theme. Palette exactly: `--bg #0a0a0a`, `--fg #e7e7e7`, `--dim #888888`, `--faint #555555`, `--green #9fef00`, `--red #ef4444`, `--border #222222`.
- One font stack: `ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace`. No font size above 18px.
- `--red` marks an unanswered threat and a non-zero exit code, and nothing else.
- Prose follows the writing rules in `CLAUDE.md`: short declarative sentences, active voice, present tense, one word for one meaning, no benefit-statement marketing framing.
- The licence line reads `MIT`. The catalogue line reads `Threat Model Library v1.0.1 (CC BY 4.0)`.
- The repository is `craigjbass/threat-modeller`. The site URL is `https://craigjbass.github.io/threat-modeller/`.
- Every GitHub Action is pinned by commit sha, as `release.yml` and `pr-test.yml` already do.
- `markdown==3.9` is the only Python dependency, pinned by sha256.
- Python tests use the standard library `unittest`. Do not add pytest.

---

### Task 1: The documentation build script

**Files:**
- Create: `scripts/build_docs_page.py`
- Create: `scripts/tests/test_build_docs_page.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `strip_contents(text: str) -> str`
  - `build_toc(text: str) -> str`
  - `rewrite_links(html: str) -> str`
  - `build(template: str, source: str) -> str`
  - Command line: `python3 scripts/build_docs_page.py --template <path> --source <path> --output <path>`

- [ ] **Step 1: Install the dependency for local work**

Run:

```bash
python3 -m pip install --user "markdown==3.9"
```

- [ ] **Step 2: Write the failing tests**

Create `scripts/tests/test_build_docs_page.py`:

````python
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
````

- [ ] **Step 3: Run the tests to see them fail**

Run: `python3 -m unittest discover -s scripts/tests -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'build_docs_page'`.

- [ ] **Step 4: Write the script**

Create `scripts/build_docs_page.py`:

```python
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
BLOB = f"{REPOSITORY}/blob/main"
SOURCE_DIRECTORY = "docs"

HEADING = re.compile(r"^## +(.*?)\s*$", re.MULTILINE)
LEADING_NUMBER = re.compile(r"^\d+(\.\d+)*\.?\s+")
HREF = re.compile(r'href="([^"]*)"')


def strip_contents(text: str) -> str:
    """Removes the `## Contents` section, up to the next second-level heading."""
    lines = text.split("\n")
    output = []
    inside = False
    for line in lines:
        if line.startswith("## "):
            inside = line[3:].strip().lower() == "contents"
        if not inside:
            output.append(line)
    return "\n".join(output)


def slug(title: str) -> str:
    """Gives the id the toc extension of markdown writes for a heading."""
    text = title.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"[\s_]+", "-", text).strip("-")


def build_toc(text: str) -> str:
    """Gives one bracketed link for each second-level heading."""
    links = []
    for title in HEADING.findall(text):
        label = LEADING_NUMBER.sub("", title).lower()
        links.append(f'<a class="blink" href="#{slug(title)}">{label}</a>')
    return "".join(links)


def rewrite_links(html: str) -> str:
    """Points every relative link at the file in the repository."""

    def replace(match: "re.Match[str]") -> str:
        target = match.group(1)
        if target.startswith(("#", "http:", "https:", "mailto:")):
            return match.group(0)
        path, _, fragment = target.partition("#")
        resolved = posixpath.normpath(posixpath.join(SOURCE_DIRECTORY, path))
        url = f"{BLOB}/{resolved}"
        if fragment:
            url = f"{url}#{fragment}"
        return f'href="{url}"'

    return HREF.sub(replace, html)


def render(text: str) -> str:
    return markdown.markdown(text, extensions=["tables", "fenced_code", "toc"])


def build(template: str, source: str) -> str:
    if "{{TOC}}" not in template:
        raise ValueError("the template holds no {{TOC}} slot")
    if "{{BODY}}" not in template:
        raise ValueError("the template holds no {{BODY}} slot")
    guide = strip_contents(source)
    body = rewrite_links(render(guide))
    return template.replace("{{TOC}}", build_toc(guide)).replace("{{BODY}}", body)


def main() -> int:
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
        print(f"build_docs_page: {fault}", file=sys.stderr)
        return 1
    with open(arguments.output, "w", encoding="utf-8") as handle:
        handle.write(page)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run the tests to see them pass**

Run: `python3 -m unittest discover -s scripts/tests -v`
Expected: PASS, 18 tests.

- [ ] **Step 6: Check the failure path by hand**

Run: `python3 scripts/build_docs_page.py --template /nonexistent --source docs/LANGUAGE.md --output /tmp/x.html; echo "exit=$?"`
Expected: one line on standard error that names the file, and `exit=1`.

- [ ] **Step 7: Commit**

```bash
git add scripts/build_docs_page.py scripts/tests/test_build_docs_page.py
git commit -m "feat: render the language guide into the documentation page"
```

---

### Task 2: The landing page

**Files:**
- Create: `docs/index.html`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: the canonical `<style>` block. Task 3 pastes the same block, byte for byte, into `docs/documentation.template.html`.

- [ ] **Step 1: Write the page**

Create `docs/index.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="description" content="threat-modeller — a threat model your team writes as text files in git. A macOS application and a command line executable that read .arch and .controls files, raise the threats and fail the build while one has no answer." />
  <title>threat-modeller — a threat model your team writes as text files in git</title>
  <style>
    /* ============================================================
       THREAT-MODELLER DESIGN SYSTEM — canonical CSS
       Pasted verbatim into index.html and documentation.template.html
       ============================================================ */

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:     #0a0a0a;
      --fg:     #e7e7e7;
      --dim:    #888888;
      --faint:  #555555;
      --green:  #9fef00;
      --red:    #ef4444;
      --border: #222222;
    }

    html, body {
      background: var(--bg);
      color: var(--fg);
      font-family: ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace;
      font-size: 13px;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }

    .page {
      max-width: 720px;
      margin: 0 auto;
      padding: 24px 20px 80px;
    }

    /* nav */
    .nav {
      font-size: 12px;
      color: var(--dim);
      padding: 4px 0 32px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 32px;
    }
    .nav a { color: var(--fg); text-decoration: none; }
    .nav a:hover { color: var(--green); }
    .sep { color: var(--faint); margin: 0 8px; }
    .nav a[aria-current="page"] { color: var(--dim); }

    /* section header */
    .sh {
      color: var(--dim);
      font-size: 12px;
      margin: 40px 0 14px;
    }

    /* document headings */
    h1, h2, h3, h4 {
      color: var(--fg);
      font-weight: normal;
      margin: 32px 0 14px;
    }
    h1 { font-size: 18px; }
    h2 { font-size: 15px; }
    h3 { font-size: 13px; }
    h4 { font-size: 13px; }
    h2::before { content: "## "; color: var(--dim); }
    h3::before { content: "### "; color: var(--dim); }

    /* prose */
    p { margin: 0 0 14px; max-width: 80ch; }
    p.lead { color: var(--fg); font-size: 15px; margin-bottom: 24px; }
    p.dim { color: var(--dim); }

    /* links */
    a { color: var(--fg); text-decoration: underline; text-underline-offset: 3px; }
    a:hover { color: var(--green); }

    /* bracketed link */
    .blink {
      color: var(--fg);
      text-decoration: none;
      margin-right: 14px;
      display: inline-block;
    }
    .blink::before { content: "[ "; color: var(--dim); }
    .blink::after  { content: " ]"; color: var(--dim); }
    .blink:hover { color: var(--green); }
    .blink:hover::before, .blink:hover::after { color: var(--green); }

    /* ascii diagram */
    pre.ascii {
      color: var(--green);
      line-height: 1.4;
      margin: 0 0 18px;
      white-space: pre;
      overflow-x: auto;
      border-left: none;
      padding: 0;
    }
    pre.ascii.fg { color: var(--fg); }

    /* stats line */
    .stats {
      color: var(--fg);
      margin: 0 0 24px;
      white-space: pre;
      font-family: inherit;
      overflow-x: auto;
    }
    .k { color: var(--dim); }
    .no { color: var(--red); }

    /* numbered steps */
    ol.steps {
      list-style: none;
      counter-reset: step;
      margin: 0 0 18px;
    }
    ol.steps li {
      counter-increment: step;
      padding-left: 32px;
      position: relative;
      margin-bottom: 8px;
    }
    ol.steps li::before {
      content: counter(step) ".";
      position: absolute;
      left: 0;
      color: var(--dim);
    }

    /* bullet list */
    ul.bullets { list-style: none; margin: 0 0 18px; }
    ul.bullets > li {
      padding-left: 16px;
      position: relative;
      margin-bottom: 14px;
    }
    ul.bullets > li::before {
      content: "-";
      position: absolute;
      left: 0;
      color: var(--dim);
    }
    ul.bullets > li > .desc {
      color: var(--dim);
      display: block;
      margin-top: 2px;
    }

    /* definition list */
    dl.paths { margin: 0 0 18px; }
    dl.paths dt { color: var(--green); margin-top: 14px; }
    dl.paths dt:first-child { margin-top: 0; }
    dl.paths dd { color: var(--dim); margin: 2px 0 0; padding-left: 16px; }

    /* two column comparison */
    .compare {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 32px;
      margin: 0 0 18px;
    }
    .compare h4 {
      margin: 0 0 10px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 6px;
    }
    .compare ul { list-style: none; }
    .compare li {
      padding-left: 16px;
      position: relative;
      margin-bottom: 6px;
      color: var(--dim);
    }
    .compare li::before {
      content: "-";
      position: absolute;
      left: 0;
      color: var(--faint);
    }
    @media (max-width: 768px) {
      .compare { grid-template-columns: 1fr; gap: 18px; }
    }

    /* shell-prompt block */
    pre.shell {
      color: var(--fg);
      background: transparent;
      margin: 0 0 14px;
      white-space: pre;
      overflow-x: auto;
      border-left: none;
      padding: 0;
    }
    pre.shell .p { color: var(--green); }
    pre.shell .c { color: var(--dim); }

    /* inline code */
    code { color: var(--green); background: transparent; }

    /* code blocks */
    pre {
      background: transparent;
      border-left: 1px solid var(--border);
      padding: 0 0 0 14px;
      margin: 0 0 14px;
      overflow-x: auto;
      color: var(--fg);
    }
    pre code { color: inherit; }

    /* tables */
    table {
      border-collapse: collapse;
      margin: 0 0 18px;
      font-size: 13px;
      width: 100%;
    }
    th, td {
      text-align: left;
      padding: 6px 14px 6px 0;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      color: var(--fg);
    }
    th { color: var(--dim); font-weight: normal; }

    /* footer */
    .foot {
      color: var(--dim);
      font-size: 12px;
      padding: 32px 0 0;
      border-top: 1px solid var(--border);
      margin-top: 48px;
    }

    /* toc */
    .toc { margin: 0 0 32px; color: var(--dim); line-height: 1.8; }
  </style>
</head>
<body>
  <div class="page">

    <div class="nav">
      <a href="index.html">threat-modeller</a><span class="sep">·</span><a href="index.html" aria-current="page">home</a><span class="sep">·</span><a href="documentation.html">docs</a><span class="sep">·</span><a href="#download">download</a><span class="sep">·</span><a href="https://github.com/craigjbass/threat-modeller">source</a>
    </div>

    <!-- HERO -->
    <div class="sh">// threat-modeller</div>
<pre class="ascii">┌───────────────────────────────────────┐
│  THREAT-MODELLER                      │
│  .arch + .controls → .md              │
└───────────────────────────────────────┘</pre>
    <p class="lead">A threat model your team writes as text files in git.</p>
    <p>
      <a class="blink" href="#download">download</a>
      <a class="blink" href="documentation.html">docs</a>
      <a class="blink" href="https://github.com/craigjbass/threat-modeller">source</a>
    </p>

    <!-- STATS -->
    <div class="stats"><span class="k">sources=</span>2  <span class="k">outputs=</span>1  <span class="k">catalogue=</span>v1.0.1  <span class="k">platforms=</span>macos+linux  <span class="k">net=</span>0</div>

    <!-- DOWNLOAD -->
    <div class="sh" id="download">// download</div>
    <p>
      <span class="k">version:</span> <a id="version-link" href="https://github.com/craigjbass/threat-modeller/releases/latest">latest</a>
      <span class="sep">·</span>
      <span class="k">source:</span> <a href="https://github.com/craigjbass/threat-modeller">github.com/craigjbass/threat-modeller</a>
      <span class="sep">·</span>
      <span class="k">license:</span> MIT
    </p>
    <dl class="paths">
      <dt><a id="dmg-link" href="https://github.com/craigjbass/threat-modeller/releases/latest">threatmodeller.dmg</a></dt>
      <dd>The macOS application, with the command line executable inside it.</dd>
      <dt><a id="cli-macos-link" href="https://github.com/craigjbass/threat-modeller/releases/latest">threatmodeller-cli-macos.tar.gz</a></dt>
      <dd>The command line executable for macOS, with the catalogue beside it.</dd>
      <dt><a id="cli-linux-x86-link" href="https://github.com/craigjbass/threat-modeller/releases/latest">threatmodeller-cli-linux-x86_64.tar.gz</a></dt>
      <dd>The command line executable for Linux on x86_64. Static, so it runs in any container.</dd>
      <dt><a id="cli-linux-arm-link" href="https://github.com/craigjbass/threat-modeller/releases/latest">threatmodeller-cli-linux-aarch64.tar.gz</a></dt>
      <dd>The command line executable for Linux on aarch64.</dd>
    </dl>

    <!-- HOW IT WORKS -->
    <div class="sh" id="how-it-works">// how it works</div>
<pre class="ascii">┌──────────┐   compile   ┌──────────────┐   check   ┌──────────┐
│  .arch   │ ──────────▶ │  .controls   │ ────────▶ │ exit 0/1 │
└──────────┘             └──────┬───────┘           └──────────┘
                                │ report
                                ▼
                          ┌──────────┐
                          │   .md    │
                          └──────────┘</pre>
    <ol class="steps">
      <li>A person writes <code>payments.arch</code>: the technologies, the zones, the components and the flows.</li>
      <li><code>threatmodeller compile</code> reads the architecture, raises every threat the catalogue holds for it, and writes a stanza into <code>payments.controls</code>.</li>
      <li>A person fills in each stanza: the status of every control, a note, and a compensating control where one applies.</li>
      <li><code>threatmodeller check</code> exits <code class="no">1</code> while a threat has no answer, so a pull request that adds a database and answers nothing fails the build.</li>
    </ol>

    <!-- THE TWO FILES -->
    <div class="sh" id="files">// the two files</div>
    <p class="dim">threatmodel/payments.arch — a person writes it.</p>
<pre><code>system "Payments" {
  catalogue = "v1.0.1"

  zone "app" {
    kind            = "private"
    network         = "vpc"
    reduces_risk_by = 30

    component "api" {
      technology = "aws-ec2"
      name       = "Application Server"
      data       = "confidential"
    }
  }

  component "attacker" {
    technology = "actor-attacker"
    data       = "public"
  }

  flow attacker -&gt; api
}</code></pre>
    <p class="dim">threatmodel/payments.controls — the compiler writes it, then a person fills it in.</p>
<pre><code>controls for "Payments" {
  catalogue = "v1.0.1"

  threat "t-credential-theft" on component "api" {
    severity = "critical"
    score    = 90

    control "Enforce MFA on all administrative access" {
      status = "implemented"
      note   = "Okta, enforced group-wide"
    }

    compensating "Break-glass account watched by the SIEM" {
      reduces_risk_by = 40
      rationale       = "Standing keys are gone; the one account left alerts on use."
    }
  }

  threat "t-mitm" on flow "attacker-&gt;api" { }
}</code></pre>
    <p class="dim">A threat with an empty block has no answer, and <code>check</code> exits <code class="no">1</code> until somebody writes one.</p>

    <!-- FEATURES -->
    <div class="sh" id="features">// features</div>
    <ul class="bullets">
      <li>the architecture language
        <span class="desc">One file states the technologies, the zones, the components and the flows. The language guide states the grammar of every block and attribute.</span>
      </li>
      <li>the generated controls file
        <span class="desc">The compiler writes a stanza for every threat the architecture raises, and merges new threats into the file a person has already answered. An answer a threat no longer needs stays in the file, marked stale.</span>
      </li>
      <li>the build gate
        <span class="desc">The executable exits 1 for an unanswered threat, a stale answer, or a library file that does not match the lock file. A diagnostic prints as threatmodel/payments.arch:12:5: error: no technology "aws-ec3" in catalogue v1.0.1, which an editor and a build log both read.</span>
      </li>
      <li>the macOS canvas
        <span class="desc">The application draws the same files, and Auto Sync writes the files when the model changes and redraws the diagram when a file changes on disk.</span>
      </li>
      <li>shared element libraries
        <span class="desc">A team writes technologies, threats and controls into a .lib file and shares it. The label prefixes every id it declares, so two teams cannot clash. library.lock.json records the repository, the tag and the sha256 of each file.</span>
      </li>
      <li>a fixed scoring order
        <span class="desc">Base severity, then a severity override, then the zone reduction, then the pathway mitigation, then one compensating control. Two compensating controls give the stronger of the two, not the sum.</span>
      </li>
      <li>markdown reports
        <span class="desc">threatmodeller report writes one .md file for each system. A report is an artefact, so a synchronise does not write it.</span>
      </li>
      <li>your own git, no credential
        <span class="desc">The application runs git as a child process, so a private repository works through the ssh-agent key and the credential helper you already have. This application holds no credential, reads none and prompts for none.</span>
      </li>
    </ul>

    <!-- WHY TEXT FILES -->
    <div class="sh" id="why">// why text files, not a diagram tool</div>
    <div class="compare">
      <div>
        <h4>a diagram tool</h4>
        <ul>
          <li>The model lives in a file only that tool opens.</li>
          <li>A reviewer reads an image, and cannot see what changed.</li>
          <li>The diagram and the code drift apart, and nothing measures the distance.</li>
          <li>The answer to a threat lives in a spreadsheet beside it, or in nobody's head.</li>
          <li>The build knows nothing about the model.</li>
        </ul>
      </div>
      <div>
        <h4>threat-modeller</h4>
        <ul>
          <li>The model is two text files beside the code.</li>
          <li>A reviewer reads the diff, line by line, in the pull request.</li>
          <li>A new component raises its threats the moment the file changes.</li>
          <li>The answer to a threat sits in the .controls file, with a note and a status.</li>
          <li>The build fails while a threat has no answer.</li>
        </ul>
      </div>
    </div>

    <!-- INSTALL -->
    <div class="sh" id="install">// install</div>
    <p class="dim">The application:</p>
<pre class="shell"><span class="p">$</span> open threatmodeller.dmg
<span class="c"># drag threatmodeller to Applications</span></pre>
    <p class="dim">The command line executable:</p>
<pre class="shell"><span class="p">$</span> tar xzf threatmodeller-cli-macos.tar.gz
<span class="p">$</span> ln -sf "$PWD/threatmodeller" ~/.local/bin/threatmodeller
<span class="p">$</span> export PATH="$HOME/.local/bin:$PATH"</pre>
    <p class="dim">In continuous integration:</p>
<pre class="shell"><span class="p">$</span> threatmodeller library verify &amp;&amp; threatmodeller check</pre>
    <p class="dim">The application installs the same executable: <em>threatmodeller ▸ Install Command Line Tool…</em> writes a link in <code>~/.local/bin</code>, and asks for no password.</p>

    <div class="foot">
      <span class="k">// license:</span> MIT
      <span class="sep">·</span>
      <span class="k">catalogue:</span> <a href="https://github.com/jib1337/threat-model-library">Threat Model Library</a> v1.0.1 (CC BY 4.0)
      <span class="sep">·</span>
      <span class="k">source:</span> <a href="https://github.com/craigjbass/threat-modeller">github.com/craigjbass/threat-modeller</a>
      <span class="sep">·</span>
      <span class="k">version:</span> <a id="version-link-foot" href="https://github.com/craigjbass/threat-modeller/releases/latest">latest</a>
    </div>

  </div>

<script>
(function(){
  var assets = [
    { id: 'dmg-link',            pattern: /\.dmg$/i },
    { id: 'cli-macos-link',      pattern: /-macos\.tar\.gz$/i },
    { id: 'cli-linux-x86-link',  pattern: /-linux-x86_64\.tar\.gz$/i },
    { id: 'cli-linux-arm-link',  pattern: /-linux-aarch64\.tar\.gz$/i }
  ];
  fetch('https://api.github.com/repos/craigjbass/threat-modeller/releases?per_page=1', { headers: { Accept: 'application/vnd.github+json' } })
    .then(function(r){ return r.ok ? r.json() : null; })
    .then(function(list){
      if (!list || !list.length) return;
      var release = list[0];
      if (release.tag_name) {
        ['version-link', 'version-link-foot'].forEach(function(id){
          var element = document.getElementById(id);
          if (element) element.textContent = release.tag_name;
        });
      }
      assets.forEach(function(asset){
        var match = (release.assets || []).find(function(a){ return asset.pattern.test(a.name); });
        var element = document.getElementById(asset.id);
        if (match && element) {
          element.href = match.browser_download_url;
          element.textContent = match.name;
        }
      });
    })
    .catch(function(){});
})();
</script>
</body>
</html>
```

- [ ] **Step 2: Look at the page**

Run: `open docs/index.html`

Check: the page is black, one column, monospace. Every ASCII box aligns. The four download links show a filename and point at a release asset. The `1` in step 4 and in the two-files note is red, and nothing else is red.

- [ ] **Step 3: Check the page with JavaScript off**

In Safari, turn off JavaScript in the Develop menu, reload, and check that every download link still points at `https://github.com/craigjbass/threat-modeller/releases/latest`.

- [ ] **Step 4: Check the page at three widths**

Run: `open -a Safari docs/index.html`, then resize to 375px, 768px and 1440px. Check the comparison stacks below 768px, left column first, and no ASCII box scrolls at 1440px.

- [ ] **Step 5: Commit**

```bash
git add docs/index.html
git commit -m "feat: add the landing page"
```

---

### Task 3: The documentation page

**Files:**
- Create: `docs/documentation.template.html`
- Create: `scripts/check_docs_page.py`
- Create: `scripts/tests/test_check_docs_page.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `build(template, source)` and the command line of `scripts/build_docs_page.py` from Task 1. The `<style>` block of `docs/index.html` from Task 2.
- Produces: `python3 scripts/check_docs_page.py --page <path> --index docs/index.html --template docs/documentation.template.html`, which exits `0` when every check passes and `1` when one fails.

- [ ] **Step 1: Write the template**

Create `docs/documentation.template.html`. The `<head>` and the `<style>` block are the same as `docs/index.html`, except for the `<title>` and the description. Copy the style block byte for byte:

```bash
python3 - <<'PY'
from pathlib import Path
index = Path('docs/index.html').read_text(encoding='utf-8')
style = index[index.index('  <style>'):index.index('  </style>') + len('  </style>')]
template = '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="description" content="The threat-modeller language guide — the lexical rules, the grammar, every block and attribute of .arch, .controls and .lib, the diagnostics and the canonical form." />
  <title>Documentation — threat-modeller</title>
STYLE
</head>
<body>
  <div class="page">

    <div class="nav">
      <a href="index.html">threat-modeller</a><span class="sep">·</span><a href="index.html">home</a><span class="sep">·</span><a href="documentation.html" aria-current="page">docs</a><span class="sep">·</span><a href="index.html#download">download</a><span class="sep">·</span><a href="https://github.com/craigjbass/threat-modeller">source</a>
    </div>

    <div class="sh">// documentation</div>

    <div class="toc">{{TOC}}</div>

{{BODY}}

    <div class="foot">
      <span class="k">// license:</span> MIT
      <span class="sep">·</span>
      <span class="k">catalogue:</span> <a href="https://github.com/jib1337/threat-model-library">Threat Model Library</a> v1.0.1 (CC BY 4.0)
      <span class="sep">·</span>
      <span class="k">source:</span> <a href="https://github.com/craigjbass/threat-modeller">github.com/craigjbass/threat-modeller</a>
    </div>

  </div>
</body>
</html>
'''.replace('STYLE', style)
Path('docs/documentation.template.html').write_text(template, encoding='utf-8')
PY
```

- [ ] **Step 2: Write the failing checks**

Create `scripts/tests/test_check_docs_page.py`:

```python
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

    def test_reports_a_heading_the_contents_does_not_link_to(self):
        page = GOOD + '<h2 id="2-lexical-structure">2. Lexical structure</h2>'
        self.assertIn("2-lexical-structure", " ".join(c.faults(page, headings=1)))

    def test_finds_no_fault_in_a_good_page(self):
        self.assertEqual([], c.faults(GOOD, headings=1))

    def test_reports_a_style_block_that_differs(self):
        self.assertEqual([], c.style_faults("<style>A</style>", "<style>A</style>"))
        self.assertEqual(
            1, len(c.style_faults("<style>A</style>", "<style>B</style>"))
        )


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run the tests to see them fail**

Run: `python3 -m unittest discover -s scripts/tests -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'check_docs_page'`.

- [ ] **Step 4: Write the check script**

Create `scripts/check_docs_page.py`:

```python
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


def faults(page: str, headings: int = MINIMUM_HEADINGS) -> list:
    """Gives one line for each fault of the rendered page."""
    found = []
    if "{{TOC}}" in page or "{{BODY}}" in page:
        found.append("the page still holds a template slot")
    identifiers = HEADING_ID.findall(page)
    if len(identifiers) < headings:
        found.append(
            f"the page holds {len(identifiers)} second-level headings, and needs {headings}"
        )
    if "<table>" not in page:
        found.append("the page holds no table")
    if "<pre>" not in page:
        found.append("the page holds no code block")
    for target in HREF.findall(page):
        if target.startswith(("#", "http:", "https:", "mailto:")):
            continue
        if target.endswith(".html"):
            continue  # the navigation bar points at the other page of the site
        found.append(f"the page holds a relative link: {target}")
    linked = set(TOC_LINK.findall(page))
    for identifier in identifiers:
        if identifier not in linked:
            found.append(f"the contents links to no heading {identifier}")
    return found


def style_faults(index: str, template: str) -> list:
    """Gives one line when the two style blocks are not the same."""
    first = STYLE.search(index)
    second = STYLE.search(template)
    if not first or not second:
        return ["one of the two pages holds no style block"]
    if first.group(0) != second.group(0):
        return ["the style block of the two pages is not the same"]
    return []


def main() -> int:
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
        print(f"check_docs_page: {line}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run the tests to see them pass**

Run: `python3 -m unittest discover -s scripts/tests -v`
Expected: PASS, 27 tests.

- [ ] **Step 6: Build the real page and check it**

Run:

```bash
python3 scripts/build_docs_page.py \
  --template docs/documentation.template.html \
  --source docs/LANGUAGE.md \
  --output docs/documentation.html
python3 scripts/check_docs_page.py \
  --page docs/documentation.html \
  --index docs/index.html \
  --template docs/documentation.template.html
echo "exit=$?"
```

Expected: no output, `exit=0`.

**If the check reports a heading the contents does not link to:** the `slug()` function of `build_docs_page.py` and the `toc` extension of markdown disagree about one heading. Print both, and change `slug()` to match the extension.

- [ ] **Step 7: Look at the page**

Run: `open docs/documentation.html`

Check: the contents holds eleven bracketed links. Each one jumps to its heading. The grammar blocks keep their line breaks. The tables of section 2 and section 7 have a dim header row. A link to `ProjectConvention.swift` opens the file on github.com.

- [ ] **Step 8: Ignore the build output**

Add one line to `.gitignore`:

```
docs/documentation.html
```

- [ ] **Step 9: Commit**

```bash
git add docs/documentation.template.html scripts/check_docs_page.py scripts/tests/test_check_docs_page.py .gitignore
git commit -m "feat: add the documentation page template and its checks"
```

---

### Task 4: Build and deploy the site

**Files:**
- Create: `.github/workflows/pages.yml`
- Create: `.github/workflows/pages-requirements.txt`
- Modify: `.github/workflows/pr-test.yml`

**Interfaces:**
- Consumes: `scripts/build_docs_page.py`, `scripts/check_docs_page.py`, `docs/index.html`, `docs/documentation.template.html`.
- Produces: the deployed site, and a `docs-site` job that fails a pull request when the documentation page does not build or does not pass its checks.

- [ ] **Step 1: Write the pinned requirements**

Create `.github/workflows/pages-requirements.txt`:

```
markdown==3.9 \
    --hash=sha256:9f4d91ed810864ea88a6f32c07ba8bee1346c0cc1f6b1f9f6c822f2a9667d280 \
    --hash=sha256:d2900fe1782bd33bdbbd56859defef70c2e78fc46668f8eb9df3128138f2cb6a
```

- [ ] **Step 2: Check the requirements install**

Run:

```bash
python3 -m venv /tmp/pages-venv
/tmp/pages-venv/bin/pip install --require-hashes -r .github/workflows/pages-requirements.txt
```

Expected: `Successfully installed markdown-3.9`.

- [ ] **Step 3: Write the pull request job**

Add this job to `.github/workflows/pr-test.yml`, after the `linux` job and before the `test` job. Keep the two-space indentation the file already uses:

```yaml
  docs-site:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Set up Python
        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: '3.12'

      - name: Install the renderer
        run: pip install --require-hashes -r .github/workflows/pages-requirements.txt

      - name: Test the scripts
        run: python3 -m unittest discover -s scripts/tests -v

      - name: Build the documentation page
        run: |
          python3 scripts/build_docs_page.py \
            --template docs/documentation.template.html \
            --source docs/LANGUAGE.md \
            --output documentation.html

      - name: Check the documentation page
        run: |
          python3 scripts/check_docs_page.py \
            --page documentation.html \
            --index docs/index.html \
            --template docs/documentation.template.html
```

**Before you commit the sha of `actions/setup-python`,** confirm it:

```bash
gh api repos/actions/setup-python/git/ref/tags/v5.6.0 --jq '.object.sha'
```

Use the sha this command prints. When the object type is `tag`, follow it:

```bash
gh api repos/actions/setup-python/git/tags/<sha> --jq '.object.sha'
```

- [ ] **Step 4: Write the deployment workflow**

Create `.github/workflows/pages.yml`:

```yaml
name: Deploy GitHub Pages

on:
  release:
    types: [published]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: false

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deploy.outputs.page_url }}

    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Set up Python
        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: '3.12'

      - name: Install the renderer
        run: pip install --require-hashes -r .github/workflows/pages-requirements.txt

      - name: Stage the site
        run: |
          cp -R docs site
          rm -rf site/superpowers
          rm -f site/documentation.template.html

      - name: Build the documentation page
        run: |
          python3 scripts/build_docs_page.py \
            --template docs/documentation.template.html \
            --source docs/LANGUAGE.md \
            --output site/documentation.html

      - name: Check the documentation page
        run: |
          python3 scripts/check_docs_page.py \
            --page site/documentation.html \
            --index docs/index.html \
            --template docs/documentation.template.html

      - name: Setup Pages
        uses: actions/configure-pages@45bfe0192ca1faeb007ade9deae92b16b8254a0d # v6.0.0

      - name: Upload Pages artifact
        uses: actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9 # v5.0.0
        with:
          path: site/

      - name: Deploy to GitHub Pages
        id: deploy
        uses: actions/deploy-pages@cd2ce8fcbc39b97be8ca5fce6e763baed58fa128 # v5.0.0
```

- [ ] **Step 5: Run the staging steps by hand**

Run:

```bash
rm -rf /tmp/site && cp -R docs /tmp/site && rm -rf /tmp/site/superpowers && rm -f /tmp/site/documentation.template.html
python3 scripts/build_docs_page.py --template docs/documentation.template.html --source docs/LANGUAGE.md --output /tmp/site/documentation.html
python3 scripts/check_docs_page.py --page /tmp/site/documentation.html --index docs/index.html --template docs/documentation.template.html
ls /tmp/site
```

Expected: `exit 0`, and `ls` shows `index.html`, `documentation.html`, `LANGUAGE.md`, `RELEASING.md`, `TESTING.md`, and no `superpowers` directory and no template.

- [ ] **Step 6: Check the workflow files parse**

Run:

```bash
python3 -c "import sys,yaml;[yaml.safe_load(open(p)) for p in ['.github/workflows/pages.yml','.github/workflows/pr-test.yml']];print('ok')"
```

Expected: `ok`. Install `pyyaml` into the temporary environment first when the import fails.

- [ ] **Step 7: Commit**

```bash
git add .github/workflows/pages.yml .github/workflows/pages-requirements.txt .github/workflows/pr-test.yml
git commit -m "ci: build and deploy the marketing site to GitHub Pages"
```

- [ ] **Step 8: Push the branch and open the pull request**

```bash
git push -u origin marketing-site
gh pr create --fill
```

Check the `docs-site` job passes on the pull request.

---

## After the merge — two manual steps

A person does these once. Neither is a code change, and the assistant cannot do either.

1. Settings ▸ Pages ▸ Source: **GitHub Actions**. Then run the `Deploy GitHub Pages` workflow by hand once, because the workflow otherwise waits for the next published release.
2. Settings ▸ General: set the description to `A threat model your team writes as text files in git.` and the website to `https://craigjbass.github.io/threat-modeller/`.

## Manual checks after the first deployment

- Open `https://craigjbass.github.io/threat-modeller/` at 375px, 768px and 1440px.
- Press every bracketed link of the contents on the documentation page.
- Turn JavaScript off and reload the landing page. Every download link points at the releases page.
- Check the four download links carry the filenames of the newest release.
