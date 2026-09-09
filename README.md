# threat-modeller

A macOS application and a command line executable that build a threat model from
text files a team commits to git.

A project holds two source files for each system, and the application writes a
third:

| File | Who writes it | What it holds |
| --- | --- | --- |
| `<name>.arch` | a person | the architecture: technologies, zones, components and flows |
| `<name>.controls` | the compiler writes it, then a person fills it in | the answer for every threat the architecture raises |
| `<name>.md` | the compiler | the report |
| `library/<name>.lib` | a team, and shared with other teams | technologies, threats and controls every system in the project reads |

The application draws the same files on a canvas. The executable reads them in
continuous integration, so a pull request that adds a database and answers
nothing fails the build.

**Read [the language guide](docs/LANGUAGE.md) for the syntax of all three source
files:** the lexical rules, the grammar, every block and attribute, the
diagnostics and the canonical form.

## What the two files look like

`threatmodel/payments.arch` states the architecture:

```hcl
system "Payments" {
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

  flow attacker -> api
}
```

`threatmodel/payments.controls` states the answers:

```hcl
controls for "Payments" {
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

  threat "t-mitm" on flow "attacker->api" { }
}
```

## The project layout

```
<project root>/
  threatmodel/
    library/
      acme.lib
    payments.arch
    payments.controls
    payments.md
    internal-tools.arch
    internal-tools.controls
```

The application reads `<root>/threatmodel` when that directory exists, and
`<root>` when it does not. A `.arch` file names a system. Its `.controls` file
and its `.md` file take the same stem beside it. The rule is in
[`ProjectConvention`](ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ProjectConvention.swift),
in one place, so the application and the executable cannot disagree about where
a file is.

Every `.lib` file under `threatmodel/library/` is a shared element library, and
every system in the project reads every one of them. There is nothing to
declare.

## Sharing an element library

The vendored catalogue holds the technologies every user shares. A
`CustomTechnology` holds one that belongs to a single diagram. A **library**
sits between them: a text file a team writes, commits and shares with other
teams.

```hcl
library "acme" {
  name = "Acme Platform"

  technology "cribl-stream" {
    name     = "Cribl Stream"
    category = "monitoring"
    threats  = ["pipeline-tamper"]
  }

  threat "pipeline-tamper" {
    name     = "Pipeline tampering"
    severity = "high"

    control "Sign pipeline configurations"
  }
}
```

The label is a provider, and it prefixes every id the file declares, so two
teams can both define `cribl-stream` and neither clashes. A system names it:

```hcl
component "ingest" {
  technology = "acme-cribl-stream"
}
```

From that point a library entry and a catalogue entry are the same thing: the
palette shows an `Acme Platform` group, the sidebar raises
`acme-pipeline-tamper`, and the `.controls` file holds a stanza for it.

A library that does not load stops the project opening, rather than loading the
libraries that do. [The language guide](docs/LANGUAGE.md#6-the-library-language)
states the grammar and every fault.

## Scoring

The order is fixed:

1. the threat's base severity
2. a severity override, if the user set one
3. the zone reduction, if the component sits in a private zone that reduces risk
4. the pathway mitigation, if one answers the threat
5. the compensating control, applied last and multiplicatively

Two compensating controls on one threat give the stronger of the two, not the
sum. The report and the threat card show the score before compensation and after
it.

## The command line executable

```
threatmodeller compile [<root>]              # writes or merges every .controls file
threatmodeller check   [<root>]              # says what has no answer
threatmodeller report  [<root>] [-o <dir>]   # writes every .md report
threatmodeller format  [<root>]              # rewrites every .arch file canonically
threatmodeller help                          # shows the usage text
```

Options: `-o <dir>` writes the reports into that directory. `--catalogue <dir>`
reads the threat catalogue from that directory. `-q` or `--quiet` says nothing
about a file that did not change.

`<root>` is the project root, and defaults to the working directory.

Exit codes: `0` success; `1` a threat is unanswered or a stale answer remains;
`2` a file did not parse; `3` a file could not be read or written.

A diagnostic prints as
`threatmodel/payments.arch:12:5: error: no technology "aws-ec3" in catalogue v1.0.1`,
which an editor and a build log both read.

Build the executable:

```
cd ThreatModelKit && swift build --product threatmodeller-cli
```

## The application

- *File ▸ Open Project…* opens a folder. The application finds the systems by
  the convention above, draws the first one, and lists the rest in the systems
  picker.
- *Synchronise* writes the architecture back to its `.arch` file and merges the
  answers into its `.controls` file.
- *Generate Report* writes the `.md` file. A report is an artefact, so a
  synchronise does not write it.
- *Auto Sync* keeps the files and the screen in step both ways. It writes the
  `.arch` file and the `.controls` file when the model changes, half a second
  after the changes stop, and it redraws the diagram when a file changes on
  disk. When Auto Sync is off, nothing is written until the user presses
  Synchronise, and the notice strip says the files changed on disk.
- An import that fails lists every fault as `line:column message`.

The `.threatmodel` document and its window still work. *Export Architecture…* is
how a document becomes a project. It is one way: a project does not become a
document.

## More documentation

- [The language guide](docs/LANGUAGE.md) — the syntax and the semantics of
  `.arch`, `.controls` and `.lib`.
- [The shared element library design](docs/superpowers/specs/2026-09-09-shared-element-library-design.md) —
  why a library is shaped this way, and how it is vendored.
- [The code-first design](docs/superpowers/specs/2026-09-08-code-first-dsl-design.md) —
  why the languages are shaped this way, the pipeline, the layout rules and the
  Linux build.
- [The application design](docs/superpowers/specs/2026-09-07-native-macos-threat-modeller-design.md) —
  the canvas, the sidebar, the catalogue and the scoring.
- [Running the tests](docs/TESTING.md)
- [Releasing](docs/RELEASING.md)
- [`docs/superpowers/specs/`](docs/superpowers/specs/) — every design spec, and the
  carry-forward note for each milestone.
- [`docs/superpowers/plans/`](docs/superpowers/plans/) — the implementation plans.

## The code

| Path | What it holds |
| --- | --- |
| [`ThreatModelKit/Sources/ArchitectureDSL`](ThreatModelKit/Sources/ArchitectureDSL) | the lexer, both parsers and both writers |
| [`ThreatModelKit/Sources/ThreatModelKit/architecture`](ThreatModelKit/Sources/ThreatModelKit/architecture) | the project convention and the use cases over it |
| [`ThreatModelKit/Sources/CommandLineApplication`](ThreatModelKit/Sources/CommandLineApplication) | the four verbs and their exit codes |
| [`threatmodeller/project`](threatmodeller/project) | the project window, the workflow bar and the notice strip |
| [`scripts/update-catalogue.sh`](scripts/update-catalogue.sh) | refreshes the vendored threat catalogue |
