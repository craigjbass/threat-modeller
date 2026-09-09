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

A library is also something a person manages. The window holds a Libraries
sheet that adds, updates and removes one, and the executable holds the same
operations as verbs, over the same use cases, so the two cannot disagree.

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

8. **Both interfaces manage libraries.** The window holds a Libraries sheet
   that adds, updates and removes a library, and the executable holds the same
   operations as verbs. Neither is a read-only view of the other's work.

9. **A library is fetched by running `git`.** One `LibraryFetching` port with
   `git` behind it serves both interfaces. A team keeps the access it already
   has: a private repository, a self-hosted server, an `ssh-agent` key, a
   credential helper and a `~/.gitconfig` all work because this application
   runs the tool that already reads them, and re-implements none of it.

10. **The application is no longer sandboxed.** A child process inherits its
    parent's container, which redirects `~` and denies the `ssh-agent` socket,
    so `git` inside the sandbox cannot read the user's keys. Developer ID
    signing, the Hardened Runtime and notarization stay. Section 12 states what
    this costs.

11. **A library repository provides every `.lib` file at its root.** After a
    clone there is a directory to read, so nothing declares a file list.

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
| `LibraryFetching` | `ThreatModelKit/architecture/gateway` | a repository and a tag to the files it provides, and a repository to its tags, with `GitLibraryFetcher` in `FileGateways` behind it |
| `AddLibrary`, `UpdateLibrary`, `RemoveLibrary`, `VerifyLibraries`, `ListOutdatedLibraries` | `ThreatModelKit/architecture/usecase` | what both the sheet and the verbs call. Section 7 states each rule |

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

## 7. Managing a library

### 7.1 What a library repository holds

```
acme/threat-elements @ v2.1.0
  acme.lib
  README.md
```

Every `*.lib` file at the repository root is what the repository provides.
Nothing else is read and nothing else is copied. A repository holding no `.lib`
file at its root cannot be added, and the message says so.

### 7.2 The fetch

`LibraryFetching` is one port:

```
fetch(repository: String, tag: String) throws -> [fileName: String]
tags(repository: String) throws -> [String]
```

`GitLibraryFetcher` sits behind it, in `FileGateways`, and runs `git` as a
child process:

| Operation | Command |
|---|---|
| `fetch` | `git clone --depth 1 --no-tags --recurse-submodules=no --branch <tag> -- <repository> <temporary directory>` |
| `tags` | `git ls-remote --tags -- <repository>` |

`fetch` then reads every `*.lib` file at the top of the clone, and deletes the
temporary directory whether it succeeded or not.

**Why `git` and not HTTPS.** A team already has access to its own repositories:
an `ssh-agent` key, a `~/.ssh/config` naming a jump host, a credential helper, a
self-hosted server, an `insteadOf` rule. Running `git` inherits every one of
them. Re-implementing them is a security surface this application does not need
to own. It also makes `tags` work everywhere, so `outdated` is not tied to one
host's API.

**What the fetcher does not do.** It never runs a script from the repository,
and never copies a file that is not `*.lib`. `--recurse-submodules=no` keeps a
submodule from being fetched.

**How it is run, and why:**

| Rule | Reason |
|---|---|
| `git` is taken from `PATH` | macOS and Linux both find it; when it is absent the message says `git` is not installed |
| a repository that starts with `-` is refused, and `--` precedes it | a repository is user input, and without this it could read as a flag |
| `GIT_TERMINAL_PROMPT=0` in the child's environment | a repository the user cannot read fails and says so, rather than waiting for a password nobody can type |
| the child is killed after 60 seconds | a fetch that never answers does not stop the window |
| the child's output is read and reported | `git`'s own message is what a user needs to fix an access fault |

The user's `~/.gitconfig` applies, because that is the point. This application
therefore runs configuration it did not write, and section 12 says so.

### 7.3 The verbs

```
threatmodeller library add    <repository> <tag> [<root>]  # clone, write the files and the lock entry
threatmodeller library update [<label>] [<root>]           # re-clone at the recorded tag
threatmodeller library remove <label> [<root>]             # delete the files and the lock entry
threatmodeller library list   [<root>]                     # what this project holds
threatmodeller library verify [<root>]                     # re-checksum against the lock file, offline
threatmodeller library outdated [<root>]                   # say which libraries have a newer tag
```

- `add` writes the entry for that repository, and replaces it when the project
  already holds it, so `add` with a new tag is how a team moves version.
- `update` with no label re-fetches every library at the tag the lock file
  records, and changes no tag.
- `remove` refuses while a system names one of the library's technologies, and
  names those systems. `--force` removes it anyway, and the systems then hold a
  technology nothing defines, which the import already reports as a warning.
- `list` prints the label, the name, the repository, the tag, and whether the
  files match the lock file.
- `verify` reads the lock file, re-checksums each file, and prints what
  differs. It runs no child process, needs no network, and is the verb a
  continuous integration job runs.
- `outdated` reads each library's tags and prints the recorded tag and the
  newest one.

### 7.4 The lock file

```json
{
  "libraries": {
    "acme": {
      "repository": "git@github.com:acme/threat-elements.git",
      "tag": "v2.1.0",
      "files": {
        "acme.lib": "9f2c0b1e…"
      }
    }
  }
}
```

The key is the library's label, which is its provider id. The checksum is
`sha256` of the file as written. The repository is recorded exactly as the user
gave it, so a team that reaches a server one way keeps reaching it that way.

### 7.5 Exit codes

The four the executable already holds, and one more:

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | `check` found an unanswered threat; `verify` found a file the lock file does not match; `outdated` found a newer tag |
| 2 | a file did not parse |
| 3 | a file could not be read or written |
| 4 | `git` failed, is absent, or the clone timed out. The message carries `git`'s own output |

## 8. The Libraries sheet

The project window's toolbar gains a Libraries button, which opens a sheet over
the project.

```
Libraries — /work

  Acme Platform       acme       git@github.com:acme/threat-elements   v2.1.0   matches
  Platform Elements   platform   github.com/acme/platform              v1.4.2   v1.5.0 is newer

  [ Add… ]   [ Update ]   [ Remove ]        [ Check for updates ]   [ Done ]
```

- The list reads the lock file and the files on disk, so it opens without
  running `git` and says `matches` or `does not match the lock file`.
- **Add…** asks for a repository and a tag, clones, writes, and reloads the
  project so the palette shows the new group. A private repository works here,
  because `git` inherits the user's `ssh-agent` and configuration.
- **Check for updates** is the one control that reaches a server without being
  asked for a change, and a person presses it. Nothing checks on its own.
- **Update** and **Remove** act on the selected row. Remove says which systems
  name the library's technologies and asks again before removing one in use.
- A fetch that fails leaves the project as it was, and the sheet shows `git`'s
  own message, because that is what tells a user their key is not loaded.
- The window stays usable while a fetch runs, and the fetch can be cancelled,
  which kills the child process.

Every one of those actions calls the use case the matching verb calls, so the
two interfaces cannot disagree about what `add` means.

### 8.1 The entitlements

```diff
- com.apple.security.app-sandbox
- com.apple.security.files.bookmarks.app-scope
  com.apple.security.files.user-selected.read-write
```

The Hardened Runtime, the Developer ID signature and notarization do not
change. Without the sandbox a security-scoped bookmark is not needed, so
*Open Recent Project* stores plain paths, and `RecentProjects` loses its
bookmark handling.

`docs/RELEASING.md` states what the release carries, and gains a line saying
the application is not sandboxed and why.

## 9. Testing

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
- **The use cases.** `LoadLibraries` over a project holding two libraries, one
  that parses and one that does not. `AddLibrary`, `UpdateLibrary`,
  `RemoveLibrary`, `VerifyLibraries` and `ListOutdatedLibraries`, each against
  a fake `LibraryFetching`. `RemoveLibrary` asserts the refusal while a system
  names the library, and the removal with `--force`.
- **The fetcher.** One shared `LibraryFetching` contract, run against the fake
  and against `GitLibraryFetcher` over **a real repository the test builds**:
  `git init` in a temporary directory, write `acme.lib`, commit, tag `v1.0.0`,
  then clone it by path. That runs the real `git` and reaches no network, so
  the contract proves the two agree. The contract also pins the faults: an
  unknown tag, a repository holding no `.lib` file, and a repository argument
  that starts with `-`.
- **Acceptance.** A project holding `acme.lib` and a `payments.arch` naming
  `acme-cribl-stream`: compile the controls, and read `acme-pipeline-tamper` in
  the file; answer it, apply it, and see the score move. Then add a second
  library through the use case, and see its group in the palette.
- **The executable.** Every verb's exit code and printed text, called in
  process, over the fake fetcher.
- **The application.** The Libraries sheet lists what the project holds; Add
  writes and reloads; Remove asks again while a system names the library.
- **Linux.** The Ubuntu job, which is what holds the no-Apple-framework rule.
  `Process` is Foundation, so the fetcher builds and its contract runs there.

## 10. Milestones

**Milestone 11A — the language and the merge.** The `.lib` parser, the
diagnostics, the writer, `LibrarySource` and its gateway, `Library`,
`MergedCatalogue`, `LoadLibraries`, the project convention, and the wiring of
every use case and verb onto the merged catalogue. It ends with a user opening a
project that holds `acme.lib` and seeing Cribl in the palette and its threat in
the sidebar.

**Milestone 11B — managing a library from the command line.**
`LibraryFetching`, `GitLibraryFetcher` and its contract, the five use cases,
the lock file, the six verbs and exit code 4.

**Milestone 11C — the Libraries sheet.** Removing the sandbox and the bookmark
handling, the toolbar button, the sheet, the cancellable fetch, and the reload
after a change.

## 11. What this design does not do

- **A library cannot define a category, a severity or a stride.** The taxonomy
  stays the vendored one, so a technology picks from its fourteen categories.
  Cribl is `monitoring`.
- **A library cannot define a pathway mitigation.**
- **A library cannot override a catalogue entry.** Decision 7.
- **There is no index, so there is no browsing and no search.** A user adds a
  library by naming its repository and its tag. An index that lists the
  libraries a user has never named is a separate design: it needs a host, a
  format and a rule about who may publish.
- **This application holds no credential.** It reads none, stores none and
  prompts for none. A repository the user's own `git` cannot read is a
  repository this application cannot read, and the message it shows is `git`'s.
- **`git` must be installed.** Nothing is bundled, and a machine without it can
  still read a library that is already vendored.
- **The About window does not list the libraries and their tags.** The
  Libraries sheet says it.
- **The OWASP threat model library is a separate design.** It holds whole
  threat models against `threat-model.schema.json`, not a catalogue of
  technologies, so reading and writing it is interchange, not a library. It
  needs its own spec.

## 12. Risks

- **Removing the sandbox widens what a fault in this application can reach.**
  Inside the container a fault reached one directory; outside it, it reaches
  what the user can reach. This is the price of the window using the user's own
  `git` access, and it is the one decision in this design a reader should
  weigh again before Milestone 11C. The Hardened Runtime, the Developer ID
  signature and notarization all stay, and nothing else about the release
  changes.
- **Running `git` runs configuration this application did not write.** A
  `~/.gitconfig` can name a credential helper, an `insteadOf` rule or an SSH
  command. Reusing it is the point, and it means the fetch does what the user's
  own shell would do, no more and no less. The fetcher adds only what stops a
  fetch waiting forever or reading a repository argument as a flag.
- **A third language is a third parser on a critical path.** The mitigation is
  the one the other two use: the property tests and the fault tests are written
  first, and the technology block is shared code rather than a second copy.
- **The merge is where a wrong answer is silent.** A library that fails to load
  does not raise an error a user notices unless the application says so, which
  is why a `.lib` that does not parse stops the project opening rather than
  loading half of it.
- **A team can vendor a library and never update it.** `verify` says the files
  match the lock file. `outdated` says a newer tag exists, and it reaches a
  server, so a job that runs offline cannot tell.
