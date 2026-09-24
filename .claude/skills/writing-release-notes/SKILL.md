---
name: writing-release-notes
description: Use when the user asks for release notes, a changelog, "what's new", or the body of a GitHub release for a threatmodeller tag (v<major>.<minor>.<n>-<hash>), or when a release body holds only the auto-generated "Full Changelog" line.
---

# Writing release notes

## Overview

The release notes use the format of the `craigjbass/clearancekit` releases: fixed sections, and one bullet for each change that a user sees. Each bullet starts with a bold lead and then says what the user saw before and what the user sees now.

WARNING: release notes are customer-facing text. Write them in plain, clear English for a user of the app and the language. Do not write the notes in the house style of `CLAUDE.md`. This skill file and your chat replies still use the house style.

## Step 1: find the commit range

The range starts at the previous full release, not at the previous beta tag.

```bash
git fetch --tags
git tag --list 'v*' --sort=-creatordate | grep -v -- '-beta-' | head -3
git log --format='===== %h %s%n%b' <previous-full-tag>..<this-tag> | grep -v 'Co-Authored-By\|Claude-Session'
```

Read every commit body. The subject line alone does not show a breaking change.

## Step 2: sort each commit into one section

| Commit shows | Section |
| --- | --- |
| The one to three changes a user will notice most | **Highlights** |
| A new control, command, language block, report section, language server feature | **Features** |
| Wrong behaviour a user could see, now correct | **Bug fixes** |
| A language attribute removed or renamed, a new error, a document format change, a status word change, report wording change | **Upgrade notes** |
| Wrong behaviour a user could see, fixed by a `feat:` commit | **Bug fixes** (the symptom decides, not the commit type) |
| Tests, CI, Linux build, refactor, docs-only, dependency bumps | **Internal** (one short list, or leave it out) |
| A change to a code comment only | No bullet |

A `feat:` commit can also add an upgrade note. A `docs:` commit that goes with a `feat:` commit adds no bullet of its own.

## Step 3: write the body in this order

```markdown
## Highlights

- **<Bold lead: the change in user words>** ([#<issue>](https://github.com/craigjbass/threat-modeller/issues/<issue>)). <What the user saw before.> <What the user sees now.>

## Features

- **<Bold lead>.** <One to three sentences.>

## Bug fixes

- **<Bold lead naming the symptom>.** <What the user saw, for example "opened with its box unticked".> <The cause in one sentence.> <What happens now.>

## Upgrade notes

- **<What changed in the files or behaviour>.** <The new error text in backticks.> <What to change, with a before/after `hcl` block when the language changed.>

## Internal

- <One line each.>

## Commits

- `<hash>` <subject>

**Full Changelog**: https://github.com/craigjbass/threat-modeller/compare/<previous-full-tag>...<this-tag>
```

Rules for the body:

- Leave out a section that has no bullets. Keep **Upgrade notes** if a single commit changes the language, a document format or a status word.
- Write **Commits** only when the range holds 30 commits or fewer.
- Link an issue when a commit body says `Closes #<n>` or `#<n>`.
- Quote identifiers, error text, commands and menu items exactly, in backticks or bold.
- Start with `## Highlights`. Do not add a title, a statistics line (commits, files, lines) or a summary paragraph.

## Step 4: publish

WARNING: `gh release edit` replaces the public release body.

1. Write the draft to the scratchpad directory, not to the repository.
2. Show the user the section list and the range. Ask before you publish.
3. After the user says yes: `gh release edit <tag> --notes-file <draft>`.
4. Check the result: `gh release view <tag> --json body --jq .body | head -3` shows `## Highlights`.

## Common mistakes

| Mistake | Correct form |
| --- | --- |
| Range starts at the last beta tag | Range starts at the previous full release |
| Headings named by theme ("The report reads more of the model") | The fixed section names above |
| A bug fix states the new code behaviour only ("the monitor reads the mode at event time") | Name the symptom the user saw, then the fix |
| Test, CI and Linux build fixes under **Bug fixes** | Put them under **Internal** |
| A removed attribute appears only as a feature | Add an **Upgrade notes** bullet with the error text and a before/after block |
| Notes written in the `CLAUDE.md` house style | Plain English for the user |
| Repository conventions or memory names in the notes ("per the comments-are-a-smell convention") | Say what changed; leave out the reason from the repository rules |
