# Shared element libraries: design

Date: 2026-09-09. Status: approved in conversation, ready for an implementation
plan.

## 1. What this adds

Today a technology comes from one of two places. The vendored catalogue holds
the technologies every user shares, and a `CustomTechnology` holds one that
belongs to a single diagram. Nothing sits between them, so a team that runs
Cribl defines it again in every model, and a threat the catalogue has never
heard of cannot be defined at all.

This design adds the middle: a **library**, which is a text file a team writes,
commits, and shares with other teams. A library defines technologies, threats
and the controls those threats offer. A project reads every library beside its
systems, and from that point a library entry and a catalogue entry are the same
thing to the rest of the application.

- `threatmodel/library/acme.lib` is a library. A person writes it.
- `threatmodel/library/library.lock.json` says which repository and tag each
  library came from, and the checksum of each file.
- `threatmodeller library verify` says the two agree, and needs no network.

## 2. The decisions this design fixes

1. **A library defines technologies, threats and controls.** A team can say
   their pipeline carries a threat no catalogue holds, and can say what
   answers it.

2. **A library is vendored and pinned, not fetched at run time.** A verb copies
   the files into the project and writes a lock file. The application and the
   reading verbs never reach the network, a pull request shows what changed,
   and a build repeats offline.

3. **A library is written in the grammar this application already reads.** A
   `.lib` file uses the lexer and the block syntax that `.arch` and `.controls`
   use, so a fault reports a line and a column, and a rewrite has a canonical
   form.

4. **The library's label is a provider, and prefixes every id it defines.**
   `library "acme"` mints `acme-cribl-stream`. Two teams can both define
   `cribl-stream` and neither clashes. The palette already groups by provider,
   so a library appears as its own group.

5. **A project reads every library beside its systems.** There is nothing to
   declare. The rule matches how a project already finds its `.arch` files.

6. **A library reaches the application as a catalogue.** `MergedCatalogue`
   implements the `TechnologyCatalogue` port over a base catalogue and a list
   of libraries, so the resolver, the palette, the compiler and the report do
   not change and cannot tell the two apart.

7. **A library never changes a catalogue entry.** There is no override. A team
   that wants a different severity for one model uses the severity override the
   model already carries.

## 3. The library language

### 3.1 Shape

```hcl
library "acme" {
  name      = "Acme Platform"       # the palette group's title
  catalogue = "v1.0.1"              # the catalogue tag this was written against

  technology "cribl-stream" {
    name        = "Cribl Stream"
    category    = "monitoring"
    description = "Observability pipeline"
    threats     = ["pipeline-tamper", "credential-theft"]
    encrypts    = true
  }

  threat "pipeline-tamper" {
    name         = "Pipeline tampering"
    description  = "An attacker changes a pipeline so data is dropped or rewritten."
    severity     = "high"
    stride       = ["tampering"]
    connection   = false
    zone         = false
    zone_context = "A pipeline in a private zone is reachable only from the VPC."

    mitre "T1565" {
      name   = "Data Manipulation"
      tactic = "impact"
    }

    control "Sign pipeline configurations"
    control "Review every pipeline change in a pull request"
  }
}
```

### 3.2 Grammar

```
LibraryFile  = LibraryBlock ;
LibraryBlock = "library" String "{" { LibraryEntry } "}" ;
LibraryEntry = "name"      "=" String
             | "catalogue" "=" String
             | TechnologyBlock
             | ThreatBlock ;

TechnologyBlock = "technology" String "{" { TechnologyAttr } "}" ;
TechnologyAttr  = "name"        "=" String
                | "category"    "=" String
                | "description" "=" String
                | "threats"     "=" StringList
                | "encrypts"    "=" Boolean ;

ThreatBlock = "threat" String "{" { ThreatEntry } "}" ;
ThreatEntry = "name"         "=" String
            | "description"  "=" String
            | "severity"     "=" String
            | "stride"       "=" StringList
            | "connection"   "=" Boolean
            | "zone"         "=" Boolean
            | "zone_context" "=" String
            | MitreBlock
            | ControlStatement ;

MitreBlock = "mitre" String "{" { MitreAttr } "}" ;
MitreAttr  = "name"   "=" String
           | "tactic" "=" String ;

ControlStatement = "control" String ;
```

`TechnologyBlock` is the block the architecture language already holds, so one
piece of parser code serves both. `String`, `StringList`, `Boolean` and the
comment rules are the ones `docs/LANGUAGE.md` states.

### 3.3 The blocks and the attributes

| Block | Label | Attribute | Values | Default |
|---|---|---|---|---|
| `library` | the provider id | `name` | string | the label |
| | | `catalogue` | a tag string | none |
| `technology` | the technology id | `name` | string | required |
| | | `category` | a category id from the taxonomy | required |
| | | `description` | string | empty |
| | | `threats` | a list of threat ids | empty |
| | | `encrypts` | `true` or `false` | `false` |
| `threat` | the threat id | `name` | string | required |
| | | `description` | string | empty |
| | | `severity` | `low`, `medium`, `high`, `critical` | required |
| | | `stride` | a list of stride ids | empty |
| | | `connection` | `true` or `false` | `false` |
| | | `zone` | `true` or `false` | `false` |
| | | `zone_context` | string | none |
| `mitre` | the technique id | `name` | string | required |
| | | `tactic` | string | required |
| `control` | the control's description | none | | |

`connection = true` puts the threat in `connectionThreats()`, and `zone = true`
puts it in `zoneThreats()`. A library cannot define a pathway mitigation, and
cannot mark a threat as a pathway threat.

A `control` is a statement with a label and no body, because a library states
what a control is and a `.controls` file states its status. Its key is minted
from its description, which is the rule the vendored catalogue already follows.

### 3.4 Identity

The label of the `library` block is a `ProviderId`. Every technology id and
every threat id the file defines is minted `<label>-<id>`. So `library "acme"`
holding `technology "cribl-stream"` defines `acme-cribl-stream`, and a `.arch`
file names it:

```hcl
component "ingest" {
  technology = "acme-cribl-stream"
}
```

Inside a library, a threat id in a `threats` list resolves against the library
first and the vendored catalogue second. So `["pipeline-tamper",
"credential-theft"]` takes the first from the library and the second from the
catalogue.

### 3.5 What the parser refuses

Errors, which stop the load:

- a duplicate technology id or threat id inside one library
- a `severity` outside the taxonomy's four
- a `stride` id outside the taxonomy's six
- a `category` outside the taxonomy's fourteen
- a `technology` with no `name` or no `category`
- a `threat` with no `name` or no `severity`
- a `mitre` block with no `name` or no `tactic`
- a block or an attribute the grammar does not hold

Warnings, which do not:

- a `threats` entry that neither the library nor the catalogue holds; the
  technology raises the threats that do resolve
- a threat no technology in the library names, and which is neither a
  connection threat nor a zone threat, because nothing can raise it

Two libraries that carry the same label is an error as well, and section 5
states it, because it is a fault of the project rather than of one file.

## 4. The merge

`MergedCatalogue` implements `TechnologyCatalogue` over one base catalogue and
a list of libraries. Its rules:

| Method | Result |
|---|---|
| `all()` | the base's technologies, then each library's, libraries by label |
| `findById` | the base first, then the libraries in label order |
| `threatsFor(technologyId:)` | the owning source's threats, in the order the technology declares them |
| `connectionThreats()`, `zoneThreats()` | the base's, then each library's |
| `pathwayMitigations()` | the base's only |
| `version()` | the base's; a library's tag is in the lock file |
| `taxonomy()` | the base's; a library adds no category, severity or stride |
| `providers()` | the base's, then one for each library, by label |

It is pure value code in `ThreatModelKit/catalogue/domain`, so it imports no
Apple framework and runs on Linux.

The existing `TechnologyCatalogue` contract runs against `MergedCatalogue` with
no libraries, which is what proves the merge is transparent, and again with one.

## 5. What a project holds

```
<project root>/
  threatmodel/
    library/
      acme.lib
      platform.lib
      library.lock.json
    payments.arch
    payments.controls
    payments.md
```

`ProjectConvention` gains the `library` directory name and the `lib` extension,
so the application and the executable cannot disagree about where a library is.
`ProjectLayout` gains `libraryPaths: [String]`, sorted, so two reads list the
same files.

Every library loads for every system in the project.

Two libraries that carry the same label is an error naming both files, because
the label is identity and a project cannot hold two providers called `acme`.

## 6. Architecture inside the application

### 6.1 The pipeline

```
acme.lib ──▶ LibraryParser ──▶ LibrarySource ──▶ LoadLibraries ──▶ [Library]
  (text)     (ArchitectureDSL)   (plain values)     (use case)          │
                                                                        ▼
                                     BundledTechnologyCatalogue ──▶ MergedCatalogue
                                                                        │
                                                                        ▼
                                                                 ThreatResolver
                                                                 the palette
                                                                 CompileControls
                                                                 the report
```

### 6.2 The parts

| Part | Where | What it does |
|---|---|---|
| `LibraryParser`, `LibraryWriter` | `ArchitectureDSL` | text to `LibrarySource` with diagnostics, and back in a canonical shape |
| `LibrarySource` | `ThreatModelKit/architecture/domain` | the plain value tree, and the boundary |
| `LibrarySourceGateway` | `ThreatModelKit/architecture/gateway` | the port, with `HclLibrarySource` behind it |
| `Library` | `ThreatModelKit/catalogue/domain` | one library as a `Provider`, `[Technology]` and `[Threat]`, ids already prefixed |
| `MergedCatalogue` | `ThreatModelKit/catalogue/domain` | `TechnologyCatalogue` over a base and `[Library]` |
| `LoadLibraries` | `ThreatModelKit/architecture/usecase` | a project root to `[Library]` and diagnostics |

### 6.3 Changes to what exists

- `ProjectConvention` and `ProjectLayout` gain the library directory and the
  library paths.
- `OpenProject`, `OpenSystem`, `CompileControls`, `CheckControlAnswers`,
  `CompileSystemReport` and the executable's verbs build their catalogue as
  `MergedCatalogue(base:libraries:)` rather than the bundled one alone.
- A `.lib` file that does not parse stops the project opening. The diagnostics
  sheet names the file and lists every fault, which is what it already does for
  a `.arch` file.
- The palette shows one group for each library, using the grouping by provider
  it already does.

### 6.4 What does not change

The `.threatmodel` document is not a project, so it reads no library and keeps
`CustomTechnology` for a technology that belongs to one diagram. `ThreatResolver`,
the scoring order, the `.arch` grammar and the `.controls` grammar are untouched:
a library threat is a threat, and its key is `acme-pipeline-tamper@component:ingest`
like any other.

A `.arch` file that declares a `technology` block whose id a library also
defines is a warning, and the file's declaration is used, because a file is
more local than a library.

## 7. Vendoring

### 7.1 The verbs

```
threatmodeller library add    <repository> <tag> [<root>]   # fetch, copy, write the lock file
threatmodeller library update [<root>]                      # re-fetch every library at its recorded tag
threatmodeller library verify [<root>]                      # re-checksum against the lock file
```

`add` writes the entry for that repository, and replaces it when the project
already holds it, so `add` with a new tag is how a team moves to a new version.
`update` re-fetches every library at the tag the lock file already records, and
changes no tag.

`add` and `update` run `git` as a child process:
`git clone --depth 1 --branch <tag> <repository> <temporary directory>`. That
is the one place this application starts a child process and the one place it
reaches the network. It adds no library dependency, and `git` is on every
machine that holds this repository.

`add` and `update` copy every `*.lib` file at the repository root into
`<root>/threatmodel/library/`, then write the lock file.

`verify` reads the lock file, re-checksums each file, and prints what differs.
It needs no network, and it is the verb a continuous integration job runs.

### 7.2 The lock file

```json
{
  "libraries": {
    "acme": {
      "repository": "github.com/acme/threat-elements",
      "tag": "v2.1.0",
      "files": {
        "acme.lib": "9f2c…"
      }
    }
  }
}
```

The key is the library's label, which is its provider id.

### 7.3 Exit codes

The four the executable already holds, and one more:

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | `check` found an unanswered threat, or `library verify` found a file the lock file does not match |
| 2 | a file did not parse |
| 3 | a file could not be read or written |
| 4 | a library could not be fetched |

## 8. Testing

- **The language.** Lexer, then parser, then diagnostics: every fault case
  asserts a line, a column and a message. The two properties the other
  languages hold: parse, write, parse gives the same value tree, and writing a
  canonical file reproduces it byte for byte.
- **The gateway.** One shared contract for `LibrarySourceGateway`, run against
  a fake over an in-memory file system and against the real one over a
  temporary directory.
- **The merge.** The existing `TechnologyCatalogue` contract run against
  `MergedCatalogue` with no libraries, which proves the merge is transparent,
  and again with one library. Then the merge's own rules: order, `findById`
  precedence, and the provider list.
- **The use case.** `LoadLibraries` over a project holding two libraries, one
  that parses and one that does not.
- **Acceptance.** A project holding `acme.lib` and a `payments.arch` naming
  `acme-cribl-stream`: compile the controls, and read `acme-pipeline-tamper`
  in the file; answer it, apply it, and see the score move.
- **The executable.** `library verify` against a lock file that agrees and one
  that does not, with the exit code asserted. `add` and `update` are tested
  against a fake fetcher, so no test reaches the network.
- **The application.** The palette shows the library's group; a `.lib` that
  does not parse opens the diagnostics sheet.
- **Linux.** The Ubuntu job, which is what holds the no-Apple-framework rule.

The fetch is one port, `LibraryFetching`, with the `git` child process behind
it, so every test above runs offline.

## 9. Milestones

**Milestone 11A — the language and the merge.** The `.lib` lexer rules, the
parser, the diagnostics, the writer, `LibrarySource` and its gateway, `Library`,
`MergedCatalogue`, `LoadLibraries`, the project convention, and the wiring of
every use case and verb onto the merged catalogue. It ends with a user opening a
project that holds `acme.lib` and seeing Cribl in the palette and its threat in
the sidebar.

**Milestone 11B — vendoring.** `LibraryFetching`, the `git` child process, the
three `library` verbs, the lock file, exit code 4, a section for the library
language in `docs/LANGUAGE.md`, and the README.

## 10. What this design does not do

- **A library cannot define a category, a severity or a stride.** The taxonomy
  stays the vendored one, so a technology picks from its fourteen categories.
  Cribl is `monitoring`.
- **A library cannot define a pathway mitigation.**
- **A library cannot override a catalogue entry.** Decision 7.
- **The application does not author or fetch a library.** The window reads what
  is vendored, and the verbs write it. A user who wants to write a library
  writes the text file.
- **The About window does not list the libraries and their tags.** The lock
  file says it, and this is worth adding later.
- **The OWASP threat model library is a separate design.** It holds whole
  threat models against `threat-model.schema.json`, not a catalogue of
  technologies, so reading and writing it is interchange, not a library. It
  needs its own spec.

## 11. Risks

- **A third language is a third parser on a critical path.** The mitigation is
  the one the other two use: the property tests and the fault tests are written
  first, and the technology block is shared code rather than a second copy.
- **The merge is where a wrong answer is silent.** A library that fails to load
  does not raise an error a user notices unless the application says so, which
  is why a `.lib` that does not parse stops the project opening rather than
  loading half of it.
- **The child process is new.** The executable has started no child process
  before. It sits behind `LibraryFetching`, so nothing but that one
  implementation knows about `git`, and no test runs it.
- **A team can vendor a library and never update it.** `library verify` says
  the files match the lock file, and says nothing about the tag being old.
  Reporting a newer tag needs the network, so it is not in this design.
