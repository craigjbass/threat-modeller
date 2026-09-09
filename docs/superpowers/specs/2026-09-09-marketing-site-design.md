---
title: GitHub Pages Marketing Site
date: 2026-09-09
status: Approved
scope: docs/index.html, docs/documentation.template.html, scripts/build-docs-page.py, .github/workflows/pages.yml, .github/workflows/pages-requirements.txt, .github/workflows/pr-test.yml
---

# GitHub Pages Marketing Site

## Goal

Publish a marketing site for threat-modeller at
`https://craigjbass.github.io/threat-modeller/`. The site holds two pages: a
landing page that states what the product does, and a documentation page that
renders `docs/LANGUAGE.md`.

The site copies the visual system and the deployment model of
`craigjbass/clearancekit`: one dark monospace design, self-contained HTML files
in `docs/`, and a GitHub Actions workflow that deploys on a published release.

## Non-goals

- No Jekyll, no bundler, no npm, no CSS framework.
- No web fonts. The pages load no file from a third-party host.
- No analytics. The pages run no `gtag` script.
- No light theme and no theme control. One dark theme.
- No animation. A link changes colour on hover; nothing else moves.
- No screenshot, no diagram image, no icon. ASCII art draws every diagram.
- No copy of the language guide by hand. The build renders `docs/LANGUAGE.md`.
- No change to the application, the executable, or any Swift source file.

## Facts the site states

The pages state these facts, and no page states a fact this list does not hold:

- The project holds two source files for each system, `<name>.arch` and
  `<name>.controls`, and the compiler writes `<name>.md`.
- A `library/<name>.lib` file holds technologies, threats and controls that
  every system in the project reads.
- The command line executable exits `1` when a threat has no answer, so a pull
  request that adds a database and answers nothing fails the build.
- A diagnostic prints as
  `threatmodel/payments.arch:12:5: error: no technology "aws-ec3" in catalogue v1.0.1`.
- The application draws the same files on a canvas, and Auto Sync writes the
  files and redraws the diagram both ways.
- `library add` records the repository, the tag and the `sha256` of each file in
  `library.lock.json`. `library verify` reaches no server.
- The application runs the user's own `git`. It holds no credential, reads none
  and prompts for none.
- The licence is MIT. The vendored catalogue is the Threat Model Library at tag
  `v1.0.1`, Copyright (c) 2026 Jack Nelson, under CC BY 4.0, and it holds MITRE
  ATT&CK content reproduced with the permission of The MITRE Corporation.

## Visual system

The site uses the clearancekit design system without change, so that a person
who reads both sites sees one hand.

### Palette

```
--bg:     #0a0a0a   near-black
--fg:     #e7e7e7   off-white
--dim:    #888888   metadata, comments
--faint:  #555555   separators
--green:  #9fef00   code, an answered threat, the shell prompt
--red:    #ef4444   an unanswered threat, a non-zero exit code
--border: #222222
```

`--red` appears only for an unanswered threat and for a non-zero exit code.
`--green` appears for code, for the shell prompt and for an answered threat.

### Typography

- One font stack: `ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace`.
- Sizes: 11px metadata, 12px secondary, 13px body, 15px and 18px headings. The
  page holds no size above 18px.
- Line height 1.5 for prose, 1.4 for an ASCII diagram.

### Layout

- One column, `max-width: 720px`, left-aligned, centred in the page.
- The navigation bar is plain text at the top of the document, and it scrolls
  with the page.
- Below 768px the two-column comparison stacks, left column first.

### ASCII conventions

- A section header reads `// section-name`, lowercase, in `--dim`.
- A diagram uses `┌ ─ ┐ │ └ ┘ ▶ →`.
- A list uses `-` as the bullet.
- A link that replaces a button reads `[ download ]`, and the brackets turn
  `--green` on hover.
- A metadata line uses `key=value` pairs separated by two spaces.

## Files

```
docs/index.html                           the landing page, one <style> block
docs/documentation.template.html          the shell, with {{TOC}} and {{BODY}}
scripts/build-docs-page.py                renders LANGUAGE.md into the shell
.github/workflows/pages.yml               builds and deploys the site
.github/workflows/pages-requirements.txt  markdown, pinned by sha256
.github/workflows/pr-test.yml             gains one job that runs the build
```

`docs/documentation.html` is a build output. The workflow writes it into a
staging directory, and the repository never holds it. `.gitignore` names
`docs/documentation.html`, so a person who runs the script into `docs/` to look
at the result cannot commit it.

Both `docs/index.html` and `docs/documentation.template.html` hold the same
`<style>` block, pasted verbatim. The duplication keeps the deployment model at
plain GitHub Pages with no preprocessor, and the two files are the only two
copies.

## The landing page

The page holds eight sections, in this order.

### 1. Hero

```
┌───────────────────────────────────────┐
│  THREAT-MODELLER                      │
│  .arch + .controls → .md              │
└───────────────────────────────────────┘
```

Lead line: `A threat model your team writes as text files in git.`

Below it: `[ download ]  [ docs ]  [ source ]`.

### 2. Stats

One line: `sources=2  outputs=1  catalogue=v1.0.1  platforms=macos+linux  net=0`

### 3. Download

One block of `key: value` pairs: version, the `.dmg`, the macOS command line
tarball, the two Linux command line tarballs, the source repository, and the
licence.

Every asset link points at
`https://github.com/craigjbass/threat-modeller/releases/latest` in the HTML. A
script at the end of the page reads
`https://api.github.com/repos/craigjbass/threat-modeller/releases/latest` and
rewrites each link and its text with the asset that matches its pattern:

| Element id | Asset pattern |
| --- | --- |
| `dmg-link` | `\.dmg$` |
| `cli-macos-link` | `-macos\.tar\.gz$` |
| `cli-linux-x86-link` | `-linux-x86_64\.tar\.gz$` |
| `cli-linux-arm-link` | `-linux-aarch64\.tar\.gz$` |
| `version-link`, `version-link-foot` | the tag name |

The script catches every failure and changes nothing when the request fails, so
the page still shows the releases page with JavaScript off or the API
unreachable.

The latest release is a prerelease, and `releases/latest` does not return a
prerelease. The script therefore reads `/releases?per_page=1` and takes the
first element, which is the newest release of either kind.

### 4. How it works

```
┌──────────┐   compile   ┌──────────────┐   check   ┌──────────┐
│  .arch   │ ──────────▶ │  .controls   │ ────────▶ │ exit 0/1 │
└──────────┘             └──────┬───────┘           └──────────┘
                                │ report
                                ▼
                           ┌──────────┐
                           │   .md    │
                           └──────────┘
```

Four numbered lines:

1. A person writes `<name>.arch`: the technologies, the zones, the components
   and the flows.
2. `threatmodeller compile` reads the architecture, raises every threat the
   catalogue holds for it, and writes a stanza into `<name>.controls`.
3. A person fills in each stanza: the status of each control, a note, and a
   compensating control where one applies.
4. `threatmodeller check` exits `1` while a threat has no answer, so the build
   fails until somebody answers it.

### 5. The two files

The `payments.arch` sample and the `payments.controls` sample from `README.md`,
quoted without change, each under a `// name.arch` header.

### 6. Features

A bullet list. Each item is one lowercase phrase, with one or two dimmed lines
below it:

- the architecture language
- the generated controls file
- the build gate
- the macOS canvas
- shared element libraries
- fixed scoring order
- markdown reports
- your own `git`, no credential

### 7. Why text files

Two columns of text: `a diagram tool` on the left, `threat-modeller` on the
right. The rows compare where the model lives, how a change is reviewed, what
happens when the architecture changes, who owns the answer to a threat, and what
the build knows.

### 8. Install

A shell block for the application:

```
$ open threatmodeller-<version>.dmg
$ # drag threatmodeller to Applications
```

A shell block for the command line executable:

```
$ tar xzf threatmodeller-cli-<version>-macos.tar.gz
$ ln -sf "$PWD/threatmodeller-<version>/threatmodeller" ~/.local/bin/threatmodeller
$ export PATH="$HOME/.local/bin:$PATH"
```

A shell block for continuous integration:

```
$ threatmodeller library verify && threatmodeller check
```

One dimmed line states that the application installs the same executable through
*threatmodeller ▸ Install Command Line Tool…*.

### Footer

```
// license: MIT · catalogue: Threat Model Library v1.0.1 (CC BY 4.0)
   source: github.com/craigjbass/threat-modeller · version: <tag>
```

## The documentation page

`scripts/build-docs-page.py` reads `docs/LANGUAGE.md`, renders it, and writes the
result into `docs/documentation.template.html`.

Command:

```
python3 scripts/build-docs-page.py --template docs/documentation.template.html \
                                   --source docs/LANGUAGE.md \
                                   --output <staging>/documentation.html
```

Rules the script follows:

1. It renders the markdown with the `tables`, `fenced_code` and `toc`
   extensions of the `markdown` package.
2. It removes the `## Contents` section of `LANGUAGE.md` and everything up to
   the next `##` heading, so the page holds one table of contents.
3. It builds `{{TOC}}` from every `##` heading that remains. Each entry is a
   bracketed link to the heading's id. The entry text drops the leading number,
   so `## 4. The architecture language` gives `[ the architecture language ]`.
4. It rewrites every relative link that does not start with `#` to
   `https://github.com/craigjbass/threat-modeller/blob/main/<path>`. A link to
   another file under `docs/` is rewritten the same way, because the site
   publishes no rendered page for it.
5. It writes the rendered HTML into `{{BODY}}`.
6. It exits `1` and prints one line to standard error when the source file, the
   template file, or either slot is missing.

The template holds the same navigation bar, the same `<style>` block and the
same footer as the landing page. The `docs` link in the navigation bar carries
`aria-current="page"`.

## The deployment workflow

`.github/workflows/pages.yml`:

```
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
```

Steps of the one job:

1. `actions/checkout`.
2. `actions/setup-python`.
3. `pip install --require-hashes -r .github/workflows/pages-requirements.txt`.
4. `cp -R docs site` — the staging directory.
5. `rm -rf site/superpowers` — the design specs and the plans are not part of
   the site, and they stay readable in the repository.
6. `python3 scripts/build-docs-page.py … --output site/documentation.html`.
7. `rm site/documentation.template.html`.
8. `actions/configure-pages`.
9. `actions/upload-pages-artifact` with `path: site/`.
10. `actions/deploy-pages`.

Every action is pinned by commit sha, which is what `release.yml` and
`pr-test.yml` already do.

`pages-requirements.txt` pins `markdown` at one version with the `sha256` hash
of every file pip may download, in the format `pip install --require-hashes`
demands.

The workflow needs one manual step first, and a person does it once: in
Settings ▸ Pages, set Source to GitHub Actions.

## Testing

`pr-test.yml` gains a `docs-site` job:

1. Install the pinned `markdown` package.
2. Run `scripts/build-docs-page.py` into a temporary file.
3. Run `scripts/check-docs-page.py`, which fails when any of these is true:
   - the output holds `{{TOC}}` or `{{BODY}}`;
   - the output holds fewer than ten `<h2 id=` elements, which is every `##`
     heading of `LANGUAGE.md` except `## Contents`;
   - the output holds no `<table>`;
   - the output holds no `<pre>`;
   - the output holds an `href` that starts with neither `#`, `http:` nor
     `https:`;
   - the output holds a heading id that the table of contents does not link to.
4. Check that `docs/index.html` and `docs/documentation.template.html` hold the
   same `<style>` block, byte for byte, so the two copies cannot drift.

The job runs on every pull request. A change to `LANGUAGE.md` that breaks the
page fails the pull request, and not the deployment.

Manual checks before the first deployment:

- The landing page and the documentation page at 375px, 768px and 1440px.
- Every anchor link in the table of contents resolves.
- The landing page with JavaScript off: every download link points at the
  releases page.

## Repository settings

Two values a person sets by hand, once, and neither blocks the deployment:

- Description: `A threat model your team writes as text files in git.`
- Website: `https://craigjbass.github.io/threat-modeller/`
