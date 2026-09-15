# Craig's Threat Modeller

A macOS application and a command line executable that build a threat model from
text files a team commits to git.

A project holds four source files for each system, and the application writes
a fifth:

| File | Who writes it | What it holds |
| --- | --- | --- |
| `<name>.arch` | a person | the architecture: technologies, zones, components and flows |
| `<name>.controls` | the compiler writes it, then a person fills it in | the answer for every threat the architecture raises |
| `<name>.attacktree` | a person | the routes through several components, and what each route raises |
| `<name>.governance` | the compiler writes it, then a person fills it in | who carries each accepted risk, and who does each piece of planned work |
| `<name>.md` | the compiler | the report |
| `library/<name>.lib` | a team, and shared with other teams | technologies, threats and controls every system in the project reads |

The application draws the same files on a canvas. The executable reads them in
continuous integration, so a pull request that adds a database and answers
nothing fails the build.

**Read [the language guide](docs/LANGUAGE.md) for the syntax of all five source
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

The resolver runs eight stages, in this fixed order, to reach the residual
score:

1. **Base score.** The threat's severity rank, multiplied by the component's
   data sensitivity. The severity is the threat's own, unless a
   `severity_override` block in the `.controls` file names this one threat on
   this one source, or, failing that, an override set from the sidebar names
   this threat on this element. A pathway threat uses the highest sensitivity among the
   components it feeds directly, when that is higher than its own.
2. **Zone.** The zone's `reduces_risk_by` percent, when the component sits in
   a private zone.
3. **Controls.** The implemented controls, by their share of the applicable
   controls.
4. **Pathway mitigation.** Every mitigation in the Pathway Mitigations panel
   that is switched on and provided by an upstream technology. Two mitigations
   answering one threat compound: each acts on the risk the one before it
   left. A zone threat reads the mitigations the components inside that zone
   provide, because nothing is upstream of a zone.
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
8. **Attack tree.** An open tree in the `.attacktree` file raises the score of
   the threat it names as its goal, by `raises_risk_by` scaled by the chain
   factor. The chain takes the **weakest** open step, because a route is as
   likely as its least likely step, and the goal's own likelihood is not in
   the chain. A step is closed by an `implemented` control or a `compensating`
   block and by nothing else. The stage raises the target score by the same
   boost, and neither score passes the top of the scale. The design is
   [`docs/superpowers/specs/2026-09-14-attack-trees-design.md`](docs/superpowers/specs/2026-09-14-attack-trees-design.md).

Two answers at the same stage — two `mitigates` edges or two compensating
controls — give the stronger of the two, not
the sum. The report shows the score before controls and before compensation,
alongside the residual score. The threat card shows the score before pathway
mitigation.

A threat raised by a flow runs stages 1 to 4 and 6 to 8: it takes the source
component's upstream pathway mitigations, but no `mitigates` edge targets a
flow. A threat raised by a zone runs stages 1, 2, 3, 4, 6, 7 and 8: a zone
sits outside the connection graph, so it reads the mitigations inside itself
rather than upstream ones, and no `mitigates` edge targets it.

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

1. **Executive summary** — a verdict sentence, then a numbered **Highest
   residual risk** list of the three worst-scoring threats by residual score,
   then a numbered **Do first** list of the three actions to take next: when
   the model declares `recommendation` blocks on `mitigates` edges, the three
   that remove the most risk; otherwise the three `recommendation` blocks
   from the `.controls` file that answer the worst-scoring threats. The **Do
   first** list is left out when the model holds neither. The section closes
   with a count of the threats nobody has answered.
2. **Where the risk sits** — a bullet list counting threats by source kind:
   component, connection or zone.
3. **By zone** — a table showing each zone, its components, its worst residual
   score, its worst target score (only when a model carries an assumed
   `mitigates` edge), and a count by risk level.
4. **Top residual risk** — a table of the worst-scoring threats, residual
   score first, with the score before controls and, when a model carries an
   assumed edge, the target score.
5. **Top residual risk in detail** — a picture and description of each threat
   in the top-scoring table, showing the element the threat is raised on,
   everything one hop from it, and the zones those sit in. For each threat,
   the section lists the controls that do not answer it and the components
   that reduce its score.
6. **Methodology** — how the scoring stages run, and what risk tolerance means.
   A `### Diagram legend` subsection shows what each mark in the pictures means.
7. **Findings** — every threat above the project's risk tolerance.
8. **What removes the most risk** — a table of every action named by a
   `recommendation` block on an assumed `mitigates` edge, worst-removing
   first: what it removes, how many threats it moves, the worst score before
   and after, and what blocks it. Each action is measured alone against
   today's posture; two actions that answer one threat do not remove the sum
   of their leverage, so the numbers in the table do not add.
9. **Attack paths** — a walk from components without inbound flow or in public
   zones to restricted components they can reach, worst score first, with each
   hop's threat and score and what reduced it. The walk is bounded, and the
   section says how many further paths it left out.
10. **Protection dependencies** — for a component other components rely on:
    what it protects, and, when a threat on the protector itself has no
    answer, that the reduction it grants rests on an unanswered threat.
11. **Recommendations** — every `recommendation` block from the `.controls`
    file, worst risk first, with the element the threat was raised on named on
    each entry's risk line. A recommendation records what to do; it never
    answers a threat, so `check` still fails while one stands with no other
    answer.
12. **Assumptions** — every `assumption` block from the `.arch` file, then a
    `### Assumed mitigations` subsection listing every `mitigates` edge whose
    `status` is `assumed`.
13. **Glossary** — a table of terms the report uses and what they mean.
14. **Appendix A — Full threat register** — bullet counts of the threats, the
    controls recorded of offered, per-control-status counts, and per-risk-level
    counts. Then one entry per threat: its severity, its residual score, the
    likelihood block or tier applied, a severity decision, the target score
    when it differs from the residual, STRIDE and MITRE ATT&CK labels, what
    compensated it, what mitigated it upstream or through a `mitigates` edge,
    and its controls.
15. **Appendix B — Model inventory** — what the architecture holds: a table
    listing every component, its technology, sensitivity, privilege, zone and
    assets; a bullet list of every connection, showing its source, target,
    kind and description; a `#### <zone name>` subsection for each zone,
    listing the network zone, network type, boundary, risk reduction, and
    components.
16. **Appendix C — Attack paths not listed** — the count of attack paths the
    walk did not print because the walk is bounded.

The report opens with an executive summary, states the scale it scored
against, and lists every threat above the project's risk tolerance before it
lists anything else. The full threat register and the model inventory are
appendices.

A section a model gives nothing to write about is left out, rather than
printed empty.

## The command line executable

```
threatmodeller compile [<root>]              # writes or merges every .controls file
threatmodeller check   [<root>]              # says what has no answer
threatmodeller history [<root>]              # says what the model scored at each commit
threatmodeller report  [<root>] [-o <dir>]   # writes every .md report and its diagrams
threatmodeller draw    [<root>] [-o <dir>]   # writes every diagram as SVG or PNG
threatmodeller format  [<root>]                # rewrites every .arch, .attacktree and .lib file
threatmodeller library <operation> …         # manages the shared element libraries
threatmodeller help                          # shows the usage text
```

`report` also writes one SVG for each threat in **Top residual risk**, beside
the report, and a *Top residual risk in detail* section that shows each one
with what has not answered it. A picture holds the element the threat is
raised on, everything one hop from it, and the zones those sit in, each zone
cut to what the picture still shows.

`draw` writes SVG by default. `--svg` and `--png` say which to write, and both
may be given. SVG is written by the package itself, so every build writes it,
including the static Linux one. PNG needs a drawing engine, which only a macOS
build has; a Linux build says so rather than writing a broken file.

Options: `-o <dir>` writes the reports into that directory. `--catalogue <dir>`
reads the threat catalogue from that directory. `--tolerance <level>` sets the
risk tolerance `check` uses for a likelihood finding (see "Risk tolerance and
likelihood findings" above); `<level>` is `low`, `medium`, `high` or
`critical`. `-q` or `--quiet` says nothing about a file that did not change.
`-f` or `--force` removes a library a system still names. `--format <name>`
picks the shape `check`, `compile` and `format` write; see below.

### Governance: who carries an accepted risk

A `.controls` file lets a person write `status = "accepted"` and move on. That
records that somebody accepted the risk, and nobody's name and no date. The
`.governance` file beside it is where the decision lives: who carries the risk,
when they took it, and when they read it again. It also states who does each
recommendation and each action, how big the work is and when it is due.

`threatmodeller compile` writes the file and every stanza in it. A person fills
in the fields and commits it. `threatmodeller check` exits 1 for an accepted
risk with no governance entry, with no owner, with no review date, or with a
review date that has passed. Planned work fails nothing: a plan with no owner
is a gap in a plan, and the report prints it.

WARNING: a project that accepts a risk today and holds no `.governance` file
fails `check` the first time it runs after this change. The fix is two steps:

1. Run `threatmodeller compile`, which writes the file and a stanza for every
   accepted control.
2. Fill in `owner` and `review_by` in each stanza, and commit the file.

The report writes `## Accepted risks` after `## Recommendations`, one row per
accepted control, governed or not, and the executive summary states how many
are past their review date.

### Risk over time

A report states the posture of one day. `threatmodeller history` states the
direction:

```
2026-09-14  a1b2c3d  Craig  total 184  worst 12  critical 2  high 5  accepted 1  trees 1  v1.0.1
2026-09-07  9f8e7d6  Craig  did not parse
```

The history is your git history. Every commit that touched a threat model file
holds the files of that day, the compile is deterministic, so the score at that
commit is recoverable by reading them. Nothing is stored, nothing is checked
out, and neither the working tree nor the index is touched.

`--commits <n>` bounds the sample, newest first, and defaults to 50. A commit
whose files do not parse keeps its row and says so, because a zero would read
as "no risk".

`report` writes `## Risk over time` with a graph beside it, and `## What
changed` between the previous sampled commit and the working tree: threats
raised and gone, controls whose status moved, risks newly accepted, review
dates moved, and the score of each element. The executive summary states the
direction in one sentence. `--commits 0` turns all of it off. The application
reads the same rows from the History button, at your request and never on open.
What reading it costs is measured in [docs/TESTING.md](docs/TESTING.md).

### Policy: the rules a project sets for itself

`threatmodeller check` fails a build for an unanswered threat, a stale answer,
a stale tree and an accepted risk nobody governs. `threatmodel/policy.hcl` is
where a project states the rest:

```hcl
policy {
  max_open_at_level                         = "high"
  accepted_requires_owner                   = true
  accepted_requires_review_by               = true
  implemented_requires_evidence_above       = "high"
  restricted_data_stays_out_of_public_zones = true
  assumptions_require_owner                 = true
  system_requires_owner                     = true
}
```

| Rule | What it asks |
| --- | --- |
| `max_open_at_level` | no threat at that level or worse is unanswered |
| `accepted_requires_owner` | every accepted risk names an owner |
| `accepted_requires_review_by` | every accepted risk names a review date |
| `implemented_requires_evidence_above` | every implemented control on a threat at that level or worse, before its controls, states an evidence tier |
| `restricted_data_stays_out_of_public_zones` | no component holding restricted data sits in a public zone, or outside every zone |
| `assumptions_require_owner` | every assumption names an owner |
| `system_requires_owner` | the `.arch` file states `owner` |

The set is fixed names rather than an expression language, so a rule is one a
team cannot mistype, the report can explain it, and it survives a change to the
model. A breach prints one line naming the rule and exits 1. A project with no
policy file checks exactly as it did. The report writes `## Policy` after the
executive summary, listing every rule and whether the system keeps it.

### Evidence: what proves a control is in place

A `control` block takes `status = "implemented"`, and four teams write that
word and mean four things. `evidence` says which: `asserted`, `documented`,
`configured`, `tested` or `audited`, weakest first, which is the order of what
a reader can check for themselves. `reference` says where the proof is and
`verified_on` says when somebody last checked. A `compensating` block takes the
same three.

A tier moves no score. The control is either in place or it is not; the tier
says how well a reader can check that claim. The report names the tier beside
each implemented control and the executive summary counts the ones that state
none.

A project that wants more states it in its `.arch` file:

```hcl
system "Payments" {
  requires_evidence_above = "high"
}
```

`threatmodeller check` then exits 1 for an implemented control on a threat
whose risk level **before its controls** is that level or worse and that states
no tier. The level is read before the controls, because reading it after would
let the controls lower the score far enough to exempt themselves. A project
that states nothing fails nothing.

### What check writes, and for whom

`--format <plain|github|json>` says which shape `check`, `compile` and `format`
write. It defaults to `plain`, which is the lines a person reads in a terminal.
The exit codes are the same whichever shape is asked for.

`--format github` writes GitHub Actions workflow commands, so a pull request
shows the failure beside the line it names rather than a red check with no word
on it:

```
::error file=threatmodel/payments.controls,line=14,col=1::dos-attack on component "api" (Low) has no answer
::warning file=threatmodel/payments.controls,line=1,col=1::a severity_override names a severity the catalogue does not hold
```

An unanswered threat names the line of its `threat` stanza when the `.controls`
file holds one, and line 1 when it does not.

`--format json` writes one object, and nothing else, so any other tool reads
one document:

```json
{
  "messages" : [],
  "systems" : [
    {
      "diagnostics" : [],
      "name" : "payments",
      "stale" : ["sql-injection@component:gone"],
      "staleTrees" : [],
      "tolerance" : "low",
      "unanswered" : [
        {
          "file" : "threatmodel/payments.controls",
          "line" : 14,
          "riskLevel" : "Low",
          "sourceId" : "api",
          "sourceKind" : "component",
          "threatId" : "dos-attack"
        }
      ]
    }
  ]
}
```

`messages` holds what the run said about the project rather than about one
system: a catalogue that would not load, a library warning, a directory that
holds no `.arch` file.

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
- The stage picker, *Synchronise* and *Generate Report* float over the diagram
  in one panel at the bottom middle of the canvas column. When a selection
  panel is shown the floating panel moves above it. *Auto Sync* is a setting,
  not a verb, so it sits in the toolbar beside *Libraries*.
- The report message carries *Open* and *Reveal in Finder*, and *File ▸ Open
  Last Report* opens the same file. A report written by
  `threatmodeller compile` outside the application is not known to the window,
  so the item stays off until the window writes one.
- A row in the diagnostics sheet opens the file it belongs to, and *Copy*
  writes every row as `<path>:<line>:<column>: <message>`, the shape the
  command line prints.
- A save message and a report message show in the toolbar, where the load stage
  shows, and clear themselves after four seconds.
- The View menu holds *Zoom In* (`Cmd+=`), *Zoom Out* (`Cmd+-`), *Actual Size*
  (`Cmd+0`), *Zoom to Fit* (`Cmd+9`), *Zoom to Selection*, and the three stages
  (`Cmd+1`, `Cmd+2`, `Cmd+3`). The floating panel states the zoom, and a click
  on it opens the same items.
- The palette has a search field. Typed words narrow the technologies by name
  and by description, and every category with a match opens. The arrow keys
  move the selection and Return places it.
- Hovering states what a thing is: a palette row states its description and how
  many threats it raises, a node states its technology, its zone and how much
  is open on it, and a badge names the three worst open threats.
- The examples browser draws the diagram of the example a person picks, from
  that example's own document.
- A MITRE technique on a threat card is a link, and the card's menu holds
  *Copy Threat Id*. The report writes the same link.
- *View ▸ Lay Out Diagram* (`Shift+Cmd+L`) lays the drawn model out again and
  moves every component and every zone to the result, as one undoable change.
  *Lay Out Selection* (`Cmd+Option+L`) does the same for what is selected and
  moves nothing else. The layout runs off the main actor, and the toolbar says
  what it is doing while it runs.
- A secondary click opens a menu on the thing under the pointer: a component,
  a zone, a flow, or open canvas. *Rename…* and *Label…* open the field on the
  element itself; *Show Threats* and *Show Controls* change the stage and
  narrow the threat list to that element, which *Show Everything* clears. Cut,
  Copy, Duplicate and Delete act on the whole selection; every other item acts
  on the element clicked.
- *File ▸ Open Recent* lists the last ten projects, newest first, each with
  its name and its path, and dims one whose folder is gone. *Clear Menu*
  empties it. The welcome window holds *Reopen the last project at launch*,
  which is off until a person turns it on; a path on the command line opens
  that project whatever the setting says.
- *Edit ▸ Copy as Image* (`Shift+Cmd+C`) puts the diagram on the clipboard as
  PNG and as PDF. With elements selected it copies those elements and the
  flows between them, cropped to their bounds.
- A component's technology is changed in the component bar. The component
  keeps its id, its name, its place, its zone and its flows. An answer on a
  threat the new technology no longer raises goes with it, and the diagnostics
  strip names each one.
- A plain drag on empty canvas moves the diagram, a two finger scroll moves it
  as well, shift-drag draws a selection rectangle, and a pinch zooms. The
  pointer shows an open hand over open canvas and a closed hand while the
  diagram moves.
- Several zones are worked on at once. A shift-click adds a zone to the
  selection and a marquee takes every zone it covers whole, so a drag on any
  selected zone's header moves the group, and one undo takes the whole move
  back. Two zones that overlap need an order: *Edit ▸ Bring Zone to Front*
  (`Cmd+Option+]`) and *Send Zone to Back* (`Cmd+Option+[`) set it, and the
  `.arch` file writes the zones in that order.
- A name field and a percent slider write one change when the edit ends, not
  one per keystroke and not one per slider step, so one undo takes back the
  whole edit.
- The **Pathway Mitigations panel**, in the sidebar, is where a user turns
  stage 4 of "Scoring" on: a master toggle, then, per mitigation, an enable
  switch, a mode (lower the score, or remove the threat outright) and, in
  "lower the score" mode, a percent slider.
- A threat's severity in the sidebar is a menu: choosing an entry sets a
  technology-wide override, and, once one is set, the menu offers "Use the
  catalogue's severity" to clear it. The sidebar disables the menu rather
  than let a choice from it change nothing.
- *Move to Library…* on a palette row moves a technology this model defines
  into `<directory>/library/<name>.lib`. Every system in the project then reads
  it, and another project vendors it with `threatmodeller library add`. The
  technology takes the identifier the library mints, and every component that
  named the old one names the new one.
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
  `.arch`, `.controls`, `.lib`, `.attacktree`, `.governance` and
  `policy.hcl`.
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
