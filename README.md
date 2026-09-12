# Craig's Threat Modeller

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

## Modelling a host

A system is not only a network of services. It can also be a single host: the
processes on it, the privilege each one runs at, and the calls between them.

- A flow states its `kind`: `network`, `ipc`, `file`, `syscall`, and more. A
  local call raises no network-only threat, such as a man-in-the-middle attack.
- A zone states its `boundary`: `network` (the default) or `privilege`. A
  privilege zone raises the threats a library marks for that boundary.
- A component states the privilege it `runs_as`: `user`, `admin`, `root`,
  `system` or `kernel`.
- One component may mitigate a named threat on another, with the `mitigates`
  block. A security product lowers the score of the threat it answers,
  wherever that threat is raised. This is a separate scoring stage from the
  Pathway Mitigations panel below: a `mitigates` edge names one specific
  protector and one specific threat, and it states its own `status`, either
  `adopted` (the team has it, so it lowers the real score) or `assumed` (the
  team plans it or believes it, so it only lowers the target score — see
  "Scoring" below).

Read [the language guide](docs/LANGUAGE.md) for the full grammar of `flow`,
`zone`, `runs_as` and `mitigates`. Read
[`libraries/endpoint.lib`](libraries/endpoint.lib) for the technologies an
endpoint model draws from: the operating system, its shells, its security
products.

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

### Vendoring a library

A library repository holds one or more `.lib` files at its root. Nothing else in
it is read, and nothing in it is ever run.

```
threatmodeller library add <repository> <tag> [<root>]  # fetch and pin a library
threatmodeller library update [<label>] [<root>]        # fetch again at the recorded tag
threatmodeller library remove <label> [<root>]          # delete a library and its lock entry
threatmodeller library list [<root>]                    # say what this project holds
threatmodeller library verify [<root>]                  # check the files against the lock file
threatmodeller library outdated [<root>]                # say which libraries have a newer tag
```

`add` writes the files into `threatmodel/library/` and writes
`library.lock.json`, which records the repository, the tag and the `sha256` of
each file. A team commits both, so a pull request shows what changed.

```json
{
  "libraries" : {
    "acme" : {
      "files" : { "acme.lib" : "9f2c0b1e…" },
      "repository" : "git@github.com:acme/threat-elements.git",
      "tag" : "v2.1.0"
    }
  }
}
```

`add`, `update` and `outdated` run `git` as a child process, so a team keeps the
access it already has: an `ssh-agent` key, a `~/.ssh/config`, a credential
helper, a self-hosted server, a private repository. **This application holds no
credential.** It reads none, stores none and prompts for none, and a repository
the user's own `git` cannot read is one it cannot read either. The message it
shows is `git`'s own.

`verify` runs no child process and reaches no server, so it is the command a
continuous integration job runs:

```
threatmodeller library verify && threatmodeller check
```

`remove` refuses while a system names one of the library's technologies, and
says which systems. `--force` removes it anyway.

`update` fetches again at the tag the lock file already records and changes no
tag. To move version, run `add` with the new tag.

## Scoring

Every threat carries two numbers. The **residual score** is the real state of
the system today. The **target score** — "if the assumptions hold" in the
report — is the residual score recalculated as though every `assumed`
`mitigates` edge were `adopted`. The two numbers differ only when a model
carries an assumed edge; the report prints the target score only then.

The resolver runs seven stages, in this fixed order, to reach the residual
score:

1. **Base score.** The threat's severity rank, multiplied by the component's
   data sensitivity. The severity is the threat's own, unless a
   `severity_override` block in the `.controls` file names this one threat on
   this one source, or, failing that, a technology-wide override set from the
   sidebar names it. A pathway threat uses the highest sensitivity among the
   components it feeds directly, when that is higher than its own.
2. **Zone.** The zone's `reduces_risk_by` percent, when the component sits in
   a private zone.
3. **Controls.** The implemented controls, by their share of the applicable
   controls.
4. **Pathway mitigation.** The strongest mitigation in the Pathway
   Mitigations panel that is upstream of the component, switched on, and
   provided by an upstream technology.
5. **`mitigates` edges.** The strongest `mitigates` edge that targets this
   component and names this threat, counting only edges whose `status` is
   `adopted`. An edge whose `status` is `assumed` is skipped at this stage, so
   it never lowers the residual score; it lowers only the target score, at
   the same stage run a second time over both `adopted` and `assumed` edges.
6. **Likelihood.** A `.controls` file's `likelihood` block for this threat on
   this source, or, failing that, the threat's own likelihood tier, multiplies
   both the residual score and the target score. `commodity` (the default)
   leaves the score unchanged; `targeted` multiplies by 0.6; `research`
   multiplies by 0.25. A `likelihood` block can also raise a threat's tier
   back to `commodity`.
7. **Compensating control.** The strongest `compensating` block on the threat
   reduces both the residual score and the target score.

Two mitigations at the same stage — two `mitigates` edges, two pathway
mitigations, or two compensating controls — give the stronger of the two, not
the sum. The report shows the score before controls and before compensation,
alongside the residual score. The threat card shows the score before pathway
mitigation.

A threat raised by a flow runs stages 1 to 4 and 6 to 7: it takes the source
component's upstream pathway mitigations, but no `mitigates` edge targets a
flow. A threat raised by a zone runs stages 1, 2, 3, 6 and 7 only: a zone
sits outside the connection graph, so nothing is upstream of it and no
`mitigates` edge targets it.

### Risk tolerance and likelihood findings

A `likelihood` block is evidence a person found, not a control a team built.
`threatmodeller check` uses it to close a threat when the evidence says the
threat is unlikely enough: a threat counts as answered when it has an
implemented control, a `compensating` block, **or** a `likelihood` block whose
current residual risk level (`Low`, `Medium`, `High` or `Critical`) ranks at
or below the project's risk tolerance.

The risk tolerance is a `RiskLevel`, read in this order: the `--tolerance`
flag, then the system's own `risk_tolerance` attribute in the `.arch` file,
then `Low` when neither is set. `Low` is strict: a `likelihood` block closes
only a threat whose residual score is already `Low`; it never closes a
`Medium`, `High` or `Critical` threat until the team raises the tolerance. A
`severity_override` block records an assessor's own severity decision for one
threat on one source, with a rationale and, optionally, sources; it wins over
a technology-wide override in stage 1 above.

Read [the language guide](docs/LANGUAGE.md) for the full grammar of
`severity_override`, `likelihood`, `risk_tolerance`, `assumption` and
`recommendation`.

## The report

`threatmodeller report` and *Generate Report* write the same `.md` file, in
this order:

1. **Summary** — the threat count, the controls recorded, one line per control
   status, and a count by risk level.
2. **Where the risk sits** — a count by source kind: component, connection
   or zone.
3. **By zone** — one row per zone: its components, its worst residual score,
   its worst target score (only when a model carries an assumed
   `mitigates` edge), and a count by risk level.
4. **Top residual risk** — the worst-scoring threats, residual score first,
   with the score before controls and, when a model carries an assumed
   edge, the target score.
5. **Components**, **Connections**, **Zones** — what the architecture holds.
6. **Attack paths** — a walk from components without inbound flow or in public
   zones to restricted components they can reach, worst score first, with each
   hop's threat and score and what reduced it. The walk is bounded, and the
   section says how many further paths it left out.
7. **Protection dependencies** — for a component other components rely on:
   what it protects, and, when a threat on the protector itself has no
   answer, that the reduction it grants rests on an unanswered threat.
8. **Recommendations** — every `recommendation` block from the `.controls`
   file, grouped by the source that raised the threat, worst source first.
   A recommendation records what to do; it never answers a threat, so
   `check` still fails while one stands with no other answer.
9. **Assumptions** — every `assumption` block from the `.arch` file, then,
   under "Assumed mitigations", every `mitigates` edge whose `status` is
   `assumed`.
10. **Threats** — one entry per threat: its severity, its residual score, the
    likelihood block or tier applied, a severity decision, the target score
    when it differs from the residual, STRIDE and MITRE ATT&CK labels, what
    compensated it, what mitigated it upstream or through a `mitigates`
    edge, and its controls.

A section a model gives nothing to write about is left out, rather than
printed empty.

## The command line executable

```
threatmodeller compile [<root>]              # writes or merges every .controls file
threatmodeller check   [<root>]              # says what has no answer
threatmodeller report  [<root>] [-o <dir>]   # writes every .md report
threatmodeller draw    [<root>] [-o <dir>]   # writes every diagram as SVG or PNG
threatmodeller format  [<root>]              # rewrites every .arch file canonically
threatmodeller library <operation> …         # manages the shared element libraries
threatmodeller help                          # shows the usage text
```

`draw` writes SVG by default. `--svg` and `--png` say which to write, and both
may be given. SVG is written by the package itself, so every build writes it,
including the static Linux one. PNG needs a drawing engine, which only a macOS
build has; a Linux build says so rather than writing a broken file.

Options: `-o <dir>` writes the reports into that directory. `--catalogue <dir>`
reads the threat catalogue from that directory. `--tolerance <level>` sets the
risk tolerance `check` uses for a likelihood finding (see "Risk tolerance and
likelihood findings" above); `<level>` is `low`, `medium`, `high` or
`critical`. `-q` or `--quiet` says nothing about a file that did not change.
`-f` or `--force` removes a library a system still names.

`<root>` is the project root, and defaults to the working directory.

Exit codes: `0` success; `1` a threat is unanswered, a stale answer remains, a
library file does not match the lock file, a library a system names was not
removed, or a library has a newer tag; `2` a file did not parse; `3` a file
could not be read or written; `4` a library could not be fetched.

A diagnostic prints as
`threatmodel/payments.arch:12:5: error: no technology "aws-ec3" in catalogue v1.0.1`,
which an editor and a build log both read.

### Getting the command

Three ways, in the order most people want them.

**From the application.** *threatmodeller ▸ Install Command Line Tool…* writes a
link in `~/.local/bin`, which is your own directory, so it asks for no password
and touches nothing outside your home. The window says whether that directory is
on your `PATH` and, when it is not, gives you the one line to add to `~/.zshrc`.
The same window uninstalls it, and says so when the link points at a copy of the
application you have moved.

**From a release.** The tarball holds the executable with the catalogue beside
it, and needs no flag:

```
tar xzf threatmodeller-cli-<version>-macos.tar.gz
cd threatmodeller-<version>
./threatmodeller check /path/to/your/project
ln -sf "$PWD/threatmodeller" ~/.local/bin/threatmodeller
```

**From this repository.** A link to the build output keeps working after every
rebuild:

```
cd ThreatModelKit
swift build -c release --product threatmodeller-cli
mkdir -p ~/.local/bin
ln -sf "$(swift build -c release --product threatmodeller-cli --show-bin-path)/threatmodeller-cli" \
       ~/.local/bin/threatmodeller
```

If `~/.local/bin` is not on your `PATH`, add this to `~/.zshrc` and open a new
terminal:

```
export PATH="$HOME/.local/bin:$PATH"
```

The executable finds its catalogue in the directory it sits in, and resolves its
own path through a symbolic link first, which is why a link from `PATH` works
from anywhere.

## The application

- *File ▸ Open Project…* opens a folder. The application finds the systems by
  the convention above, draws the first one, and lists the rest in the systems
  picker.
- *Synchronise* writes the architecture back to its `.arch` file and merges the
  answers into its `.controls` file.
- *Generate Report* writes the `.md` file described in "The report" above. A
  report is an artefact, so a synchronise does not write it.
- The document window's *File* menu also exports one system: *Export as
  Markdown…* writes the same `.md` report, and *Export as threatcl…*, *Export
  as PDF…* and *Export as Image…* write the architecture or the canvas in
  those formats. Only the Markdown export is the project's report; the other
  three exist only from this menu.
- The **Pathway Mitigations panel**, in the sidebar, is where a user turns
  stage 4 of "Scoring" on: a master toggle, then, per mitigation, an enable
  switch, a mode (lower the score, or remove the threat outright) and, in
  "lower the score" mode, a percent slider.
- A threat's severity in the sidebar is a menu: choosing an entry sets a
  technology-wide override, and, once one is set, the menu offers "Use the
  catalogue's severity" to clear it. The sidebar disables the menu rather
  than let a choice from it change nothing.
- A user creates, edits and deletes a custom technology from the canvas: its
  name, category and description, which catalogue threats it carries, and
  whether it encrypts what crosses it. See "Sharing an element library" below
  for what a custom technology is and how it differs from a library entry.
- *Libraries* opens a sheet listing the shared element libraries the project
  holds, with their repository, version and whether the files match the lock
  file. *Add…* takes a repository and a version and fetches it; a private
  repository works, because the application runs the user's own `git` and
  inherits their `ssh-agent`. *Update* and *Remove* act on the selected row, and
  *Remove* asks again when a system still names the library. *Check for updates*
  is the one control that reaches a server without being asked for a change, and
  a person presses it: nothing checks on its own.
- *Auto Sync* keeps the files and the screen in step both ways. It writes the
  `.arch` file and the `.controls` file when the model changes, half a second
  after the changes stop, and it redraws the diagram when a file changes on
  disk. When Auto Sync is off, nothing is written until the user presses
  Synchronise, and the notice strip says the files changed on disk.
- An import that fails lists every fault as `line:column message`.

The `.threatmodel` document and its window still work. *Export Architecture…* is
how a document becomes a project. It is one way: a project does not become a
document. *File ▸ Open Example…* (`Cmd+Shift+O`) opens the sample browser for
this document window; opening an example replaces the model on the canvas,
and undo takes it back.

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
| [`ThreatModelKit/Sources/CommandLineApplication`](ThreatModelKit/Sources/CommandLineApplication) | the verbs and their exit codes |
| [`GitLibraryFetcher.swift`](ThreatModelKit/Sources/FileGateways/GitLibraryFetcher.swift) | the one place this application runs `git` |
| [`CommandLineTool.swift`](threatmodeller/CommandLineTool.swift) | putting `threatmodeller` on the user's `PATH` |
| [`scripts/embed-cli.sh`](scripts/embed-cli.sh) | putting the executable inside the application bundle |
| [`threatmodeller/project`](threatmodeller/project) | the project window, the workflow bar, the notice strip and the Libraries sheet |
| [`scripts/update-catalogue.sh`](scripts/update-catalogue.sh) | refreshes the vendored threat catalogue |
