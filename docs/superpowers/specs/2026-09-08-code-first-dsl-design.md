# Code-first threat modelling: design

Date: 2026-09-08. Status: approved in conversation, ready for an implementation
plan.

## 1. What this adds

Today a threat model is a `.threatmodel` document a person edits on a canvas.
This design adds a second way to hold the same thing: two text files a team
writes, reviews and commits, and an application that draws them.

- `payments.arch` states the architecture. A person writes it.
- `payments.controls` states the answers. A compiler generates it, and a person
  fills it in.
- `payments.md` is the report. A compiler writes it.

The application becomes the visual interface over those files. A command line
executable does the same work in continuous integration, so a pull request that
adds a database and answers nothing fails the build.

## 2. The decisions this design fixes

1. **Two formats, one at a time.** A model lives either in a project directory
   of `.arch` and `.controls` files, or in a `.threatmodel` document. The
   document format, its window and its commands do not change. *Export
   Architecture…* is how a document becomes a project.

2. **The controls file is generated, then filled in.** The compiler resolves
   every threat and writes one stanza per threat with every control listed and
   unanswered. A person commits their answers into it. A later compile keeps
   those answers, adds what is new, and marks what no longer applies as stale
   rather than deleting it.

3. **HCL-style blocks.** Both files use one grammar: blocks, attributes,
   comments. This application already writes threatcl HCL, the shape is familiar
   in this domain, and one hand-written parser serves both files.

4. **No coordinates in the source.** The application lays a diagram out from
   declaration order. The same source always draws the same picture. A layout a
   user adjusts by hand is not written back.

5. **Only a compensating control moves a number.** A control carries a status. A
   threat may carry a compensating control with a percent and a rationale, and
   that is the one thing in these files that changes a score.

6. **A rewrite keeps answers and loses comments.** Statuses, notes, rationales
   and stale markers are data the model carries, so a rewrite keeps them.
   Free-standing comments do not survive. The writer emits a stable order, so
   rewriting an unchanged model produces no diff.

7. **The project is a directory, found by convention.** The application opens a
   project root and finds `threatmodel/<name>.arch` and its neighbours. The
   executable reads the same convention, so the two cannot disagree about where
   a file lives.

8. **The language and the executable are Linux-clean.** Neither may import an
   Apple framework. A continuous integration job on Ubuntu enforces it.

## 3. The architecture language

### 3.1 Shape

```hcl
system "Payments" {
  catalogue = "v1.0.1"            # optional; the tag this was written against

  technology "our-ledger" {       # a technology the catalogue does not hold
    name     = "Our Ledger"
    category = "database"
    threats  = ["t-sql-injection", "t-data-exfiltration"]
    encrypts = true
  }

  zone "app" {
    kind            = "private"
    network         = "vpc"
    name            = "Application VPC"
    reduces_risk_by = 30

    component "api" {
      technology = "aws-ec2"
      name       = "Application Server"
      data       = "confidential"
    }

    component "ledger" {
      technology = "our-ledger"
      data       = "restricted"
      threats    = false
    }
  }

  component "attacker" {          # outside every zone
    technology = "actor-attacker"
    data       = "public"
  }

  flow api -> ledger
}
```

### 3.2 Blocks and attributes

| Block | Label | Attribute | Values | Default |
|---|---|---|---|---|
| `system` | the model's name | `catalogue` | a tag string | the catalogue in use |
| `technology` | the technology id | `name` | string | required |
| | | `category` | a category id from the taxonomy | required |
| | | `description` | string | empty |
| | | `threats` | a list of threat ids | empty |
| | | `encrypts` | `true` or `false` | `false` |
| `zone` | the zone id | `kind` | `public`, `private` | `private` |
| | | `network` | `generic`, `vpc`, `subnet`, `on-premises`, `dmz`, `management`, `data` | `generic` |
| | | `name` | string | the zone's derived display name |
| | | `reduces_risk` | `true` or `false` | `true` |
| | | `reduces_risk_by` | 0 to 100 | the application's default |
| `component` | the component id | `technology` | a technology id | required |
| | | `name` | string | the technology's name |
| | | `data` | `public`, `internal`, `confidential`, `restricted` | `internal` |
| | | `threats` | `true` or `false` | `true` |
| `flow` | none; written `flow a -> b` | | | |

A `component` block inside a `zone` block sits in that zone. A `component` block
at the top level sits outside every zone. Nested zones are not supported: this
application does not model them.

### 3.3 Identity

An id in quotes is identity. `component "api"` is `ComponentId("api")`. A zone
is its id. A flow's id is `api->ledger`, derived from its ends, so a flow needs
no id of its own.

These ids are what the controls file keys on. Renaming an id in `.arch` orphans
its answers, and the merge marks those answers stale.

### 3.4 What the parser refuses

The parser returns every fault it finds. Each carries a line, a column, a
message and a severity.

Errors, which stop an import:

- a duplicate component, zone or technology id
- a flow naming a component the file does not declare
- a flow from a component to itself
- two flows between the same pair in the same direction
- a value outside a vocabulary, named by field and value
- `reduces_risk_by` outside 0 to 100
- a required attribute that is absent
- a block or attribute the grammar does not hold

Warnings, which do not:

- a `technology` id the catalogue does not hold and the file does not declare
- a threat id in a `technology` block that the catalogue does not hold
- a zone that declares no components

## 4. The controls language

### 4.1 Shape

```hcl
controls for "Payments" {
  catalogue = "v1.0.1"

  threat "t-credential-theft" on component "api" {
    severity = "critical"        # restated from the catalogue so the file reads alone
    score    = 90

    control "Enforce MFA on all administrative access" {
      status = "implemented"
      note   = "Okta, enforced group-wide"
    }

    control "Rotate access keys every 90 days" {
      status = "not_implemented"
    }

    compensating "Break-glass account watched by the SIEM" {
      reduces_risk_by = 40
      rationale       = "Standing keys are gone; the one account left alerts on use."
    }
  }

  threat "t-lateral-movement" on zone "app" { }

  threat "t-mitm" on flow "cdn->api" { }

  stale threat "t-sql-injection" on component "cache" {
    control "Use parameterised queries" { status = "implemented" }
  }
}
```

### 4.2 Rules

- `on` names the source: `component`, `zone` or `flow`, then its id.
- `severity` and `score` are written by the compiler for the reader. A person
  editing them changes nothing: the application recomputes both.
- A `control` label is the control's description, which is what the catalogue
  gives and what the existing control key is minted from.
- `status` is one of `implemented`, `not_implemented`, `not_applicable`,
  `accepted`. `implemented` records the control, exactly as the checkbox does
  today. `not_applicable` and `accepted` count as answered.
- `note` is free text, kept through a rewrite.
- `compensating` carries a label, `reduces_risk_by` from 0 to 100, and a
  `rationale`, which is required: a reduction nobody can justify is not one.
- A `stale` block holds answers for a threat the architecture no longer raises.
  Nothing deletes it. A person deletes it.

### 4.3 The merge

`CompileControls` reads the architecture and the existing controls file, then
writes the controls file.

| Case | Result |
|---|---|
| The threat is raised and the file answers it | The answer is kept whole: statuses, notes, compensating controls |
| The threat is raised and the file does not answer it | A stanza appears with every control at `not_implemented` |
| The file answers a threat that is no longer raised | The answer moves into a `stale` block |
| A control has left the catalogue | The control is dropped from the stanza; its answer is not kept |
| A stale answer's threat is raised again | The answer moves back out of `stale`, with its statuses |

The output order is fixed: components in declaration order, then flows, then
zones; inside each, threats by id; inside each, controls by description. So a
compile of an unchanged model writes the file it read.

## 5. Scoring

The order is pinned so it cannot drift:

1. the threat's base severity
2. a severity override, if the user set one
3. the zone reduction, if the component sits in a private zone that reduces risk
4. the pathway mitigation, if one answers the threat
5. **the compensating control, applied last and multiplicatively**

Two compensating controls on one threat give the stronger, not the sum, which is
the rule the pathway mitigations already follow. The report and the threat card
show the score before and after compensation, the way they already show it
before and after a pathway mitigation.

## 6. Architecture inside the application

### 6.1 The pipeline

```
payments.arch ──▶ ArchitectureDSL ──▶ ArchitectureSource ──▶ ImportArchitecture ──▶ ThreatModel
   (text)          lexer + parser      (plain values)          (use case)            (in memory)
                        │                                            │
                        │                                            ▼
                        │                                     ThreatResolver
                        │                                            │
payments.controls ◀─────┴──── ControlsSource ◀── CompileControls ◀────┘
   (text)                     (plain values)      (merge)
                                    │
                                    ▼
                            ApplyControlAnswers ──▶ ThreatModel
                                    │
                                    ▼
                       BuildThreatModelReport ──▶ ExportModelAsMarkdown ──▶ payments.md
```

### 6.2 A new package target

`ArchitectureDSL` holds the lexer, the parser and the writer for both files: one
grammar, two vocabularies. It depends on `ThreatModelKit` for the value types it
produces, and on nothing else. Text and tokens never leave it.

### 6.3 New ports

| Port | Responsibility |
|---|---|
| `ArchitectureSourceGateway` | text to `ArchitectureSource` with diagnostics; `ArchitectureSource` to text |
| `ControlsSourceGateway` | the same pair for the controls file |
| `ProjectSourceGateway` | discover a project root; read a file; write a file; watch for changes |

`ArchitectureSource` and `ControlsSource` are plain value trees, and they are the
boundary. A `Diagnostic` carries a line, a column, a message and a severity.

### 6.4 New use cases

| Use case | What it does |
|---|---|
| `ImportArchitecture` | text in, model out; refuses on any error and returns every diagnostic |
| `ExportArchitecture` | model out to text; structure only, no coordinates |
| `LayOutModel` | positions from declaration order |
| `CompileControls` | architecture plus existing answers, merged, out to text |
| `ApplyControlAnswers` | controls text into the model, so the sidebar shows what the file says |
| `CheckControlAnswers` | what is unanswered and what is stale |
| `OpenProject` | a root to a `ProjectLayout` |
| `ListSystems` | the systems a project holds |
| `OpenSystem` | one system's architecture and answers, drawn and scored |
| `SaveSystem` | the model back to its two files |
| `CompileProjectReport` | the Markdown report for one system |

### 6.5 Changes to what exists

- `ThreatModel` gains `controlStatuses: [ControlKey: ControlStatus]` and
  `compensatingControls: [ThreatKey: [CompensatingControl]]`. A `ThreatKey` is
  `"<threatId>@<source.id>"`, which is the pair `ThreatResolver` already mints to
  raise a duplicate threat once.
  `implementedControls` stays and is derived from the statuses, so nothing that
  reads it changes.
- `ThreatResolver` applies the compensating reduction last and reports the score
  before it.
- `AssessedThreat` gains the control statuses and the compensating controls, so
  the sidebar can show them.
- `Report` gains the same, and `ExportModelAsMarkdown` gains a status column and
  a line for each compensating control. threatcl and the PDF read the same tree.
- The document format moves to version 3, carrying the two new fields, and reads
  versions 1 and 2.

## 7. Layout

Deterministic, declaration order only. No force-directed placement and no
crossing minimisation: the same source must always draw the same picture, and a
user who wants a tidier diagram reorders their declarations.

1. Components declared outside every zone go in one band across the top, left to
   right in declaration order.
2. Zones follow, in declaration order, left to right, wrapped to a new row when
   the row would pass 2400 points.
3. Inside a zone, components sit in a grid in declaration order, `ceil(sqrt(n))`
   columns wide.
4. A node is 160 by 72. Gaps are 60 across and 48 down. A zone pads its contents
   by 40, plus the 40-point header band the containment rule reserves.
5. A zone's size is what its grid needs. A zone with no components gets one
   empty cell, so it stays visible and selectable.

`LayOutModel` is a use case, not a view helper, so it is tested by asserting
coordinates.

## 8. The project

### 8.1 Convention

```
<project root>/
  threatmodel/
    payments.arch
    payments.controls
    payments.md
    internal-tools.arch
    internal-tools.controls
```

A `.arch` file names a system. Its `.controls` and its `.md` are the same stem
beside it. When `threatmodel/` is absent the application looks for `*.arch` at
the root. When that finds nothing it offers to create `threatmodel/` with a
starter system.

### 8.2 In the application

- *File ▸ Open Project…* opens a folder chooser. The grant covers the folder and
  its contents. An app-scoped bookmark keeps *Open Recent Project* working after
  a relaunch, which needs `com.apple.security.files.bookmarks.app-scope` in the
  target's entitlements.
- The window is the three columns that exist today, with a systems picker in the
  toolbar.
- ⌘S writes the architecture back to its `.arch` and merges the answers into its
  `.controls`. *Compile Report* writes the `.md`, because a report is an artefact
  and a save is not.
- The project watches its own directory. A file that changes on disk while the
  window has no unsaved change reloads silently. When there is an unsaved change
  the notice strip offers *Reload* or *Keep mine*.
- An import that fails opens a sheet listing every fault as `line:column
  message`, with the source line quoted. Warnings go in the notice strip, which
  becomes a list rather than the one drift line it carries today.
- A control row's checkbox becomes a four-way status control. A compensating
  section under a threat's controls lists what compensates it, and a small sheet
  adds or edits one.

### 8.3 What does not change

The canvas, the palette, the zone and node panels, undo, the clipboard, the
`.threatmodel` document and its window.

## 9. The executable

An executable target in the package, `threatmodeller`. No new dependency: this
repository has none beyond the vendored catalogue, and the argument handling is
four verbs and three flags: `-o <dir>`, `--catalogue <dir>` and `--quiet`.

```
threatmodeller compile [<root>]              # writes or merges every .controls
threatmodeller check   [<root>]              # exit 1 when a threat is unanswered
threatmodeller report  [<root>] [-o <dir>]   # writes every .md
threatmodeller format  [<root>]              # rewrites both files canonically
```

`<root>` defaults to the working directory, read by the same convention the
application uses.

Exit codes: `0` success; `1` `check` found an unanswered threat or a stale
answer; `2` the source did not parse; `3` a file could not be read or written.

A diagnostic prints as
`threatmodel/payments.arch:12:5: error: no technology "aws-ec3" in catalogue v1.0.1`,
which an editor and a build log both understand.

`main.swift` is a few lines over a library target holding the verbs, so tests
call the verbs in process and no test shells out.

The PNG is not in the executable. Drawing the canvas needs SwiftUI, which lives
in the application target, so `report` writes Markdown and the picture stays a
menu command.

## 10. Linux

No package source imports AppKit, CoreGraphics, SwiftUI, CoreText or PDFKit
today, and nothing in `ArchitectureDSL` or the executable may.
`platforms: [.macOS(.v26)]` states Apple minimums and does not exclude Linux.

**The catalogue is the one real problem.** `Bundle.module` works on Linux, but it
resolves to a resources directory beside the binary, so a single file to copy
does not exist by default. `LibraryResources` gains a source: a directory named
by `--catalogue <dir>` or `THREATMODELLER_CATALOGUE`, else `Bundle.module`. The
release artefact is a tarball carrying the binary and the resources directory.
Embedding the 1.2 MB catalogue as generated Swift source is the answer if one
file is ever required, and is not done now.

**Building.**

```
swift sdk install <static-linux-sdk-artifactbundle>
swift build --swift-sdk x86_64-swift-linux-musl  -c release --product threatmodeller
swift build --swift-sdk aarch64-swift-linux-musl -c release --product threatmodeller
```

The static Linux SDK links musl and the Swift runtime into the binary, so the
target machine needs no Swift installed.

**Proof.** Cross-compiling proves it links, not that it runs. A continuous
integration job on Ubuntu runs `swift build` and `swift test` for the package,
then `threatmodeller check` over the sample project and asserts the exit code.
Cross-compilation from macOS is a release step.

## 11. Testing

- **The language.** Lexer, then parser, then diagnostics: every fault case
  asserts a line, a column and a message. Two properties: parse, write, parse
  gives the same value tree; writing a canonical file reproduces it byte for
  byte. Golden files carry the three bundled samples as `.arch`.
- **The gateways.** One shared contract each for `ArchitectureSourceGateway`,
  `ControlsSourceGateway` and `ProjectSourceGateway`, run against a fake over an
  in-memory file system and against the real one over a temporary directory. The
  project contract pins "pairs by stem", "falls back to the root" and "finds
  nothing".
- **The use cases.** Import, export, compile, apply, check and layout. Layout
  asserts coordinates.
- **Acceptance.** `ModellingFromSourceTests`: write `.arch` text, import it,
  read the threats; compile the controls, answer one, apply it, see the score
  move. `KeepingAProjectInGitTests`: a temporary project directory, opened,
  changed, saved and read again from the text on disk.
- **The executable.** The verbs called in process; the exit code and the printed
  text asserted.
- **The application.** Project discovery, the notice strip and the status
  control. One interface journey opens a project through a `-project <path>`
  launch argument over a temporary project, because an open panel cannot be
  driven from an interface test.
- **Linux.** The Ubuntu job, which is what enforces the no-Apple-framework rule.

## 12. Milestones

**Milestone 10A — the architecture language.** The lexer, the parser, the
diagnostics, the writer, `LayOutModel`, `ImportArchitecture`,
`ExportArchitecture`, the project convention and `ProjectSourceGateway`, the
project window, and `format` in the executable. It ends with a user opening a
project directory and seeing the diagram and the threats.

**Milestone 10B — the controls language.** The controls grammar, the generated
stub, the merge, `ControlStatus` and `CompensatingControl` in the model and the
resolver, document format version 3, `ApplyControlAnswers`,
`CheckControlAnswers`, the sidebar status control and the compensating sheet,
the Markdown report additions, `compile`, `check` and `report` in the executable,
and the Linux job.

## 13. Risks

- **The parser is new code on a critical path.** Every fault a user meets is a
  fault the parser reports. The property tests and the golden files are what
  hold it, and they are written first.
- **The merge can lose work.** It rewrites a file a person edited. The rule that
  nothing is ever deleted — only marked stale — is what makes that safe, and the
  contract tests state it.
- **Two sources of truth already exist.** A project and a document are separate,
  and a user can hold the same system in both and let them drift. The
  application never opens both at once, and *Export Architecture…* is one-way.
- **The sandbox.** Folder access and bookmarks are the one part of this that
  cannot be proved by a unit test.
- **Corelibs Foundation.** The Linux job is the only thing that finds a
  behaviour difference, so it runs from the first task of Milestone 10A, not at
  the end.
