# The language of Craig's Threat Modeller

A reference for the six source languages this application reads: the
architecture language, written in a `.arch` file; the controls language, written
in a `.controls` file; the library language, written in a `.lib` file; the
attack tree language, written in a `.attacktree` file; the governance
language, written in a `.governance` file; and the policy language, written in
`threatmodel/policy.hcl`.

The six languages share one lexical structure and one block syntax. They
differ only in their keywords and in what a block means. Sections 2 and 3 hold
what is common. Section 4 holds the architecture language, section 5 the
controls language, section 6 the library language, section 7 the attack tree
language, section 8 the governance language, and section 9 the policy
language.

## Contents

1. [Notation](#1-notation)
2. [Lexical structure](#2-lexical-structure)
3. [Block syntax](#3-block-syntax)
4. [The architecture language](#4-the-architecture-language)
5. [The controls language](#5-the-controls-language)
6. [The library language](#6-the-library-language)
7. [The attack tree language](#7-the-attack-tree-language)
8. [The governance language](#8-the-governance-language)
9. [The policy language](#9-the-policy-language)
10. [Diagnostics](#10-diagnostics)
11. [Canonical form](#11-canonical-form)
12. [A worked example](#12-a-worked-example)
13. [The grammar in full](#13-the-grammar-in-full)
14. [Where the code is](#14-where-the-code-is)

## 1. Notation

The grammar is EBNF:

| Form | Meaning |
| --- | --- |
| `"text"` | the literal text |
| `A B` | `A`, then `B` |
| `A \| B` | `A` or `B` |
| `{ A }` | `A` zero or more times |
| `[ A ]` | `A` zero or one time |
| `( A )` | grouping |
| `Name` | a rule defined elsewhere |

A rule name in `UpperCamelCase` is a rule of the grammar. A word in quotation
marks that reads as a name, such as `"system"`, is a keyword token.

## 2. Lexical structure

The lexer reads the source text and produces a list of tokens. It never stops at
the first fault: an unknown character is one diagnostic and one skipped
character, so a file with two such faults reports two.

### 2.1 Source text

A source file is Unicode text. The lexer reads it as a sequence of characters
and counts lines from 1 and columns from 1. A line ends at `\n`. Every token
carries the line and the column it starts at, and every diagnostic reports them.

### 2.2 Whitespace

The space, the tab, the carriage return and the line feed separate tokens and
carry no other meaning. A newline does not end a statement. Indentation carries
no meaning.

### 2.3 Comments

A comment starts with `#` or with `//` and runs to the end of the line.

```hcl
# this is a comment
// so is this
component "api" { }   # and so is this
```

WARNING: a comment is read and dropped. The writer does not put comments back,
so a synchronise or a `threatmodeller format` removes every comment from the
file. Statuses, notes, rationales and stale markers survive a rewrite because
they are data the model carries. A comment is not.

### 2.4 The tokens

| Kind | What it is |
| --- | --- |
| `identifier` | a bare word, such as `system` or `api` |
| `string` | text in quotation marks |
| `number` | a whole number |
| `boolean` | `true` or `false` |
| `leftBrace`, `rightBrace` | `{` and `}` |
| `leftBracket`, `rightBracket` | `[` and `]` |
| `equals` | `=` |
| `arrow` | `->` |
| `comma` | `,` |
| `endOfFile` | the end of the text |

### 2.5 Identifiers

```
Identifier = ( Letter | "_" ) { Letter | Digit | "_" | "-" } ;
```

An identifier starts with a letter or an underscore. After the first character
it may also hold a digit or a hyphen. `on-premises`, `aws_ec2` and `api2` are
identifiers.

The lexer reads `true` and `false` as boolean tokens, not as identifiers.

### 2.6 Keywords

The languages have no reserved words. A keyword is a bare identifier the parser
recognises by its position, so a keyword used anywhere else is an ordinary
identifier, and a quoted string that reads as a keyword is a string.

The architecture language reads these keywords: `system`, `catalogue`,
`risk_tolerance`, `assumption`, `text`, `owner`, `technology`, `name`,
`category`, `description`, `threats`, `encrypts`, `zone`, `kind`, `network`,
`boundary`, `reduces_risk`, `reduces_risk_by`, `component`, `data`, `runs_as`,
`shape`, `asset`, `holds`, `carries`, `tags`, `classification`, `third_party`,
`provided_by`, `paying_customer`, `uptime`, `uptime_notes`, `kind`, `link`,
`diagram`, `text`, `flow`, `mitigates`,
`status`, `recommendation`, `note`,
`blocked_by`, `sources`, `faces`, `threat_actor`, `aliases`, `capability`,
`intent`, `performs`, `techniques`, `performs_catalogue_tier`,
`requires_evidence_above`.

The controls language reads these keywords: `controls`, `for`, `catalogue`,
`tolerance`, `stale`, `threat`, `on`, `severity`, `score`, `likelihood`,
`tier`, `prior`, `rationale`, `sources`, `impacts`, `severity_override`, `control`,
`status`, `note`, `compensating`, `reduces_risk_by`, `recommendation`,
`evidence`, `reference`, `verified_on`, `tree`, `goal`, `chain`, `score_before`,
`step`, `by`.

The policy language reads these keywords: `policy`, `max_open_at_level`,
`accepted_requires_owner`, `accepted_requires_review_by`,
`implemented_requires_evidence_above`,
`restricted_data_stays_out_of_public_zones`, `assumptions_require_owner`,
`system_requires_owner`, `template`.

The governance language reads these keywords: `governance`, `for`, `threat`,
`on`, `stale`, `accepted`, `work`, `action`, `owner`, `accepted_on`,
`review_by`, `due_by`, `rationale`, `acceptance`, `note`, `effort`, `status`,
`sources`.

The library language reads these keywords: `library`, `name`, `catalogue`,
`technology`, `category`, `description`, `threats`, `encrypts`, `threat`,
`severity`, `stride`, `impacts`, `connection`, `zone`, `zone_context`, `applies_to`,
`boundary`, `runs_as`, `pathway`, `likelihood`, `mitre`, `tactic`, `control`,
`mitigation`, `mitigates`, `provided_by`, `reduces_risk_by`, `mode`,
`threat_actor`, `aliases`, `capability`, `intent`, `performs`, `techniques`,
`performs_catalogue_tier`.

### 2.7 String literals

```
String = '"' { Character | Escape } '"' ;
Escape = "\" AnyCharacter ;
```

A string is text between two quotation marks on one line. The value a token
carries is the text with the quotation marks and the escapes taken off.

| Escape | Value |
| --- | --- |
| `\n` | a newline |
| `\t` | a tab |
| `\"` | a quotation mark |
| `\\` | a backslash |
| `\` and any other character | that character |

A string that meets the end of the line or the end of the file before its
closing quotation mark is the error `this text has no closing quotation mark`,
and the lexer produces no token for it.

### 2.8 Number literals

```
Number = [ "-" ] Digit { Digit } ;
```

A number is a whole number. There are no fractions, no exponents and no
separators. A `-` followed by `>` is the arrow token, not a number.

### 2.9 Boolean literals

```
Boolean = "true" | "false" ;
```

### 2.10 Punctuation

`{` `}` `[` `]` `=` `,` and `->`.

Any other character is the error `this file cannot hold the character "<c>"`.
The lexer skips that character and reads on.

## 3. Block syntax

The three languages are built from three forms: a block, an attribute, and a
statement.

```
Block      = Keyword { Label } "{" { BlockEntry } "}" ;
Attribute  = Keyword "=" Value ;
Statement  = Keyword Label ;
Value      = String | Number | Boolean | StringList ;
StringList = "[" [ String { [ "," ] String } ] "]" ;
```

- A **block** takes a keyword, zero or more labels, and a body in braces. A
  label is usually a string: `component "api" { … }` is a block with the
  keyword `component` and the label `api`. A flow header and a mitigates
  header take two bare identifiers instead of a string label, joined by
  `->`: `flow api -> ledger` is a block whose keyword is `flow` and whose two
  labels are the identifiers `api` and `ledger`. A block's body is optional
  when the block defines no required attribute: `flow api -> ledger` with no
  braces is that same block with an empty body (`ArchitectureParser.swift:305-311`).
- An **attribute** takes a keyword, an equals sign and one value. Each attribute
  is written on one line by convention; the grammar does not require it.
- A **statement** takes a keyword and one label, and no body. The library
  language's `control "<description>"` is a statement: it names a control
  with no status, because a library states what a control is and a
  `.controls` file states its status (`LibraryParser.swift:308-311`).
- A block body holds attributes, nested blocks and statements in any order.

Two further rules:

- **An attribute written twice keeps the last value.** The parser reports no
  fault for this.
- **A comma in a string list is optional.** The parser reads `["a" "b"]` and
  `["a", "b"]` as the same list. The writer always writes the commas.

## 3.1 The project layout

A project is a directory. `threatmodel/` holds the systems, or the project root
does when there is no `threatmodel` directory.

A system takes one of two shapes.

**A flat system is one file of each kind**, paired by stem:

```
threatmodel/
  payments.arch
  payments.controls
  payments.attacktree
  payments.governance
  payments.md
```

**A split system is a directory**, named after the system, holding one
directory per kind. The directory name states the extension it holds:

```
threatmodel/
  payments/
    arch/payments.arch        the header file
    arch/edge.arch            a part file
    arch/ledger.arch          a part file
    controls/payments.controls
    controls/edge.controls
    attacktree/edge.attacktree
    payments.md               the report
```

A project holds both shapes at once. `library/` is the shared library
directory, so no system takes that name.

**The header file** holds the `system "<name>" { … }` block, and states
`catalogue`, `risk_tolerance`, `owner`, `faces`, `requires_evidence_above` and
every `assumption`, because those are facts of the system and not of a file.

**A part file** holds `technology`, `zone`, `component`, `flow` and `mitigates`
blocks at the top level and no `system` block.

| Fault | Message |
| --- | --- |
| no file holds a `system` block | `the system "<name>" holds no file with a system block` |
| two files hold one | `the system "<name>" states a system block twice: <first> and <second>` |
| the label and the directory differ | a warning: `the directory is "<directory>" and the system block says "<label>"`, and the label wins |

**The merge.** The `.arch` files read in file-name order, and the blocks of the
first file come first. A system holds one namespace across every one of its
files: a flow in one file may name a component another file declares, and an
identifier declared twice is a fault naming both files.

| Check | Message |
| --- | --- |
| a technology or a zone declared twice | `"<id>" is declared twice: <first> and <second>` |
| a component declared twice | `the component "<id>" is declared twice: <first> and <second>` |
| an assumption declared twice | `the assumption "<label>" is declared twice: <first> and <second>` |
| a flow that names nothing | `the flow starts at "<id>", which this system does not declare` |

Every fault names the file it is in, so a build log reads
`arch/edge.arch:12:5: error: …`.

**The answers mirror the architecture by stem.** `arch/edge.arch` pairs with
`controls/edge.controls`, and an answer goes to the file that mirrors the
architecture file the element it answers came from. An answer whose element
nothing declares any more stays where it is, as a `stale` block.
`.attacktree` files mirror the same way.

**Writing back.** A save reads the files as they are on disk, takes which file
each block came from, and writes each file whose text changed. A block a person
adds in the application goes into the header file.

`threatmodeller split <system>` moves a flat system into the directory form. It
moves files and writes no new content, so a person reads the diff and sees
moves. It divides no file: a person divides a file by cutting blocks into a new
`.arch` file, and the merge joins them again.

**What the layout refuses.** Nested subprojects: `payments/cards/arch/` is not a
system, and a person who wants a tree writes `payments-cards`. A flow that names
a component another system declares: a system is the unit of scoring, of the
diagram and of the report. A `.lib` file inside a subproject: libraries stay
project-wide.

## 4. The architecture language

A `.arch` file states the architecture: the technologies, the zones, the
components and the flows between the components. A person writes it.

### 4.1 Grammar

```
ArchitectureFile = SystemBlock ;

SystemBlock  = "system" String "{" { SystemEntry } "}" ;
SystemEntry  = CatalogueAttr
             | RiskToleranceAttr
             | RequiresEvidenceAboveAttr
             | FacesAttr
             | TechnologyBlock
             | ZoneBlock
             | ComponentBlock
             | FlowStatement
             | MitigatesBlock
             | AssumptionBlock
             | UseCaseBlock
             | ExclusionBlock
             | SystemAssetBlock
             | ThirdPartyBlock
             | DiagramBlock
             | ThreatActorBlock ;

UseCaseBlock   = "use_case" String "{" "text" "=" String "}" ;
ExclusionBlock = "exclusion" String "{" "text" "=" String "rationale" "=" String "}" ;

CatalogueAttr     = "catalogue" "=" String ;
RiskToleranceAttr = "risk_tolerance" "=" String ;
RequiresEvidenceAboveAttr = "requires_evidence_above" "=" String ;
FacesAttr         = "faces" "=" StringList ;

ThreatActorBlock = "threat_actor" String "{" { ThreatActorAttr } "}" ;
ThreatActorAttr  = "name"                    "=" String
                 | "description"             "=" String
                 | "aliases"                 "=" StringList
                 | "capability"              "=" String
                 | "intent"                  "=" String
                 | "performs"                "=" StringList
                 | "techniques"              "=" StringList
                 | "performs_catalogue_tier" "=" String ;

AssumptionBlock = "assumption" String "{" { AssumptionAttr } "}" ;
AssumptionAttr  = "text"  "=" String
                | "owner" "=" String ;

TechnologyBlock = "technology" String "{" { TechnologyAttr } "}" ;
TechnologyAttr  = "name"        "=" String
                | "category"    "=" String
                | "description" "=" String
                | "threats"     "=" StringList
                | "encrypts"    "=" Boolean ;

ZoneBlock = "zone" String "{" { ZoneEntry } "}" ;
ZoneEntry = "kind"            "=" String
          | "network"         "=" String
          | "boundary"        "=" String
          | "name"            "=" String
          | "description"     "=" String
          | "reduces_risk"    "=" Boolean
          | "reduces_risk_by" "=" Number
          | "tags"            "=" StringList
          | ComponentBlock ;

ComponentBlock = "component" String "{" { ComponentEntry } "}" ;
ComponentEntry = "technology"  "=" String
               | "name"        "=" String
               | "data"        "=" String
               | "holds"       "=" StringList
               | "provided_by" "=" String
               | "source"      "=" String
               | "runs_as"     "=" String
               | "shape"       "=" String
               | "threats"     "=" Boolean
               | "tags"        "=" StringList
               | AssetBlock ;

AssetBlock = "asset" String "{" [ "data" "=" String ] "}" ;

SystemAssetBlock = "asset" String "{" { SystemAssetEntry } "}" ;

DiagramBlock = "diagram" String "{" { DiagramEntry } "}" ;
DiagramEntry = "kind" "=" String
             | "text" "=" ( String | Heredoc ) ;

Heredoc = "<<" Identifier Newline { AnyLine } Identifier ;

ThirdPartyBlock = "third_party" String "{" { ThirdPartyEntry } "}" ;
ThirdPartyEntry = "name"            "=" String
                | "description"     "=" String
                | "kind"            "=" String
                | "paying_customer" "=" Boolean
                | "uptime"          "=" String
                | "uptime_notes"    "=" String
                | "owner"           "=" String
                | "link"            "=" String ;
SystemAssetEntry = "name"           "=" String
                 | "classification" "=" String
                 | "description"    "=" String
                 | "owner"          "=" String ;

FlowStatement = "flow" Identifier "->" Identifier [ "{" { FlowEntry } "}" ] ;
FlowEntry     = "kind"        "=" String
              | "description" "=" String
              | "carries"     "=" StringList
              | "tags"        "=" StringList ;

MitigatesBlock = "mitigates" Identifier "->" Identifier "{" { MitigatesEntry } "}" ;
MitigatesEntry = "threats"         "=" StringList
               | "reduces_risk_by" "=" Number
               | "status"          "=" String
               | ActionBlock ;

ActionBlock = "recommendation" String "{" { ActionAttr } "}" ;
ActionAttr  = "text"       "=" String
            | "note"       "=" String
            | "blocked_by" "=" String
            | "sources"    "=" StringList ;
```

A file holds exactly one `system` block. A file that starts with any other word
is the error `this file starts with system, not "<word>"`, and nothing is read.
Text after the closing brace of the `system` block is not read.

### 4.2 `system`

```hcl
system "Payments" {
  catalogue = "v1.0.1"
  …
}
```

The label is the system's name, which the report and the window title show.

| Attribute | Type | Default | Meaning |
| --- | --- | --- | --- |
| `catalogue` | string | the catalogue in use | the catalogue tag this file was written against |
| `risk_tolerance` | string | `low` | the risk level a likelihood finding may answer up to |
| `owner` | string | empty | who owns this system |
| `faces` | list of strings | empty | the threat actor ids this system faces |
| `requires_evidence_above` | string | none | the risk level at and above which an implemented control must state evidence |
| `description` | string | none | what this system is, in the team's own words |
| `authors` | list of strings | empty | who wrote the model |
| `version` | string | none | what the team calls this version of the model |
| `created` | string | none | when the model was written, `YYYY-MM-DD` |
| `reviewed` | string | none | when the model was last read again, `YYYY-MM-DD` |
| `links` | list of strings | empty | where the design, the ticket or the runbook is |
| `repositories` | list of strings | empty | where this system's code is |

**Document control.** Those seven, with `owner` and the catalogue tag, are what
the report's opening table states. A system that states none of them writes no
table: an empty table says nothing and takes a page.

A date is `YYYY-MM-DD` and names a day of the calendar: `2026-02-30` is the
error `created is "2026-02-30", which is not a date`, and `4 January 2026` is
`created is "4 January 2026"; a date is written YYYY-MM-DD`. A link and a
repository each start `https://` or `http://`; anything else is the error
`links holds "<value>", which is not an address; an address starts https:// or
http://`.

A model nobody has read again for **180 days** — `DocumentControl.reviewIntervalDays`,
one constant — is marked in the executive summary. A model that states no
`reviewed` date is not marked: nobody said it ever was read. `check` fails for
none of this; a system with no owner is not a failing system unless the
project's policy asks for one.

```hcl
attribute "data-controller" {
  value = "Acme Payments Limited"
}
```

An `attribute` block states what the language does not name. The label is the
name a reader sees in the document control table, and a name declared twice is
the error `the attribute "<name>" is declared twice`.


`requires_evidence_above` takes `low`, `medium`, `high` or `critical`. A
project that states it fails `threatmodeller check` for an implemented control
on a threat whose risk level **before its controls** is that level or worse and
that states no `evidence` tier. The level is read before the controls, because
reading it after would let the controls lower the score far enough to exempt
themselves from proving they are in place. A project that states nothing fails
nothing. A value outside the four is the error `requires_evidence_above is
"<value>"; this application holds "low", "medium", "high", "critical"`.

`faces` names the adversaries this system is assessed against. An entry naming
an actor no library, no catalogue and no `threat_actor` block in this file
holds is the error `this project holds no threat actor called "<id>"`. A system
that states `faces` twice keeps the last list.

**`threat_actor`.** A system may declare its own actors, the way it declares
its own technologies. The block takes the attributes of section 6.3, and its id
is the label with no provider prefix. A local block whose label matches a
library actor id overrides that actor whole: the local block's attributes are
the actor, and the library's are not merged in.

```hcl
system "Payments" {
  faces = ["commodity-crimeware", "acme-insider"]

  threat_actor "contractor" {
    name       = "Third-party contractor"
    capability = "targeted"
    intent     = "financial"
    performs   = ["supply-chain-compromise"]
  }
}
```

`risk_tolerance` takes `low`, `medium`, `high` or `critical`. A system that
states none reads as `low`. `threatmodeller check --tolerance <level>`
overrides this for one run, without changing the file. A value outside the
four levels is the error `risk_tolerance is "<value>"; this application holds
"low", "medium", "high", "critical"`.

**`assumption`.** A system may hold one or more `assumption` blocks. An
assumption is a fact the team accepts without proof, written down so a
reviewer can see it and challenge it.

```hcl
system "Payments" {
  assumption "network-segmented" {
    text  = "The VPC has no route to the internet."
    owner = "Platform team"
  }
}
```

The label names the assumption.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `text` | string | any, and not empty | **required** |
| `owner` | string | any | none |

A block with no `text`, or an empty one, is the error `the assumption "<label>"
has no text`, and the block is dropped.

The report's `## Assumptions` section lists every assumption, by label, text
and owner, in the order the `.arch` file declares them. The same section also
lists every assumed `mitigates` edge, under an `### Assumed mitigations`
subheading, because an edge names no assumption of its own. `BuildThreatModelReport`
fills both lists from the model, `MarkdownAssumptions` writes the section, and
`ExportModelAsMarkdown` places it after the recommendations. A model that
states no assumption and assumes no mitigation writes no `## Assumptions`
section at all.

**`use_case` and `exclusion`.** A system states what a person does with it and
what this model leaves out. A reader of the report can then tell a flow that
was modelled and found safe from a flow nobody modelled.

```hcl
system "Payments" {
  use_case "take-a-payment" {
    text = "A customer pays for a basket."
  }

  exclusion "the card network" {
    text      = "This model does not cover the card network."
    rationale = "Another team owns it and models it."
  }
}
```

The label names the use case or the exclusion.

| Block | Attribute | Type | Values | Default |
| --- | --- | --- | --- | --- |
| `use_case` | `text` | string | any, and not empty | **required** |
| `exclusion` | `text` | string | any, and not empty | **required** |
| `exclusion` | `rationale` | string | any, and not empty | **required** |

A `use_case` with no `text` is the error `the use_case "<label>" has no text`,
and the block is dropped. An `exclusion` with no `text` is the error `the
exclusion "<label>" has no text`. An `exclusion` with no `rationale` is the
error `the exclusion "<label>" has no rationale; an exclusion with no reason is
a gap`: a reader cannot tell a decision from an oversight.

WARNING: an exclusion whose label names a component the same system draws is
the warning `the exclusion "<label>" names a component this system draws; a
thing both drawn and excluded is a contradiction`. The file still reads, and
the exclusion still stands.

The report's `## Scope` section reads after the executive summary, with the use
cases first and the exclusions second. The executive summary states how many
exclusions the model holds. A system that states neither writes no `## Scope`
section.

### 4.3 `technology`

A `technology` block declares a technology the vendored catalogue does not hold.
A component may name a catalogue technology or one declared here.

```hcl
technology "our-ledger" {
  name        = "Our Ledger"
  category    = "database"
  description = "The ledger we wrote ourselves"
  threats     = ["t-sql-injection", "t-data-exfiltration"]
  encrypts    = true

  control "Every write is signed by the service account"
  control "The ledger is read only outside the write path"
}
```

The label is the technology's identifier, which a component's `technology`
attribute names.

| Attribute | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | **required** | the display name |
| `category` | string | **required** | a category identifier from the taxonomy |
| `description` | string | empty | free text |
| `threats` | list of strings | empty | the threat identifiers this technology raises |
| `encrypts` | boolean | `false` | true when the technology encrypts what it holds |
| `control` | statement | none | a control this technology brings, in the team's own words |

A `control` statement states a control this technology brings. It answers every
threat the technology carries, the way a catalogue technology's own mitigation
does, so it appears on every card that technology raises and in the report. A
block may hold as many as it needs.

Two technologies this file declares cannot share a name: the palette would draw
two rows a person cannot tell apart. The application states the clash and names
the other technology before it saves.

A block with no `name` is the error `the technology "<id>" has no name`. A block
with no `category` is the error `the technology "<id>" has no category`. Either
error drops the block.

### 4.4 `zone`

A zone is a network boundary. A component inside a private zone that reduces
risk scores lower than the same component outside one.

```hcl
zone "app" {
  kind            = "private"
  network         = "vpc"
  name            = "Application VPC"
  reduces_risk_by = 30

  component "api" { technology = "aws-ec2" }
}
```

The label is the zone's identifier.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `kind` | string | `public`, `private` | `private` |
| `network` | string | `generic`, `vpc`, `subnet`, `on-premises`, `dmz`, `management`, `data` | `generic` |
| `boundary` | string | `network`, `privilege` | `network` |
| `name` | string | any | the zone's derived display name |
| `description` | string | any | none |
| `reduces_risk` | boolean | `true`, `false` | `true` |
| `reduces_risk_by` | number | 0 to 100 | the application's default |
| `tags` | string list | any | none |

A value outside a vocabulary is an error that names the field, the value and the
values the application holds. A `reduces_risk_by` outside 0 to 100 is the error
`reduces_risk_by is <n>; it runs from 0 to 100`.

`boundary` states what kind of boundary the zone is. A `privilege` zone raises
the privilege threat set: the threats a library marks `boundary = "privilege"`.
A `network` zone raises the network threat set: the threats a library marks
`zone = true` with no `boundary`, or with `boundary = "network"`. Neither zone
raises the other's threat set.

A zone body may hold `component` blocks. It may not hold another `zone` block:
this application does not model nested zones.

### 4.5 `component`

```hcl
component "api" {
  technology = "aws-ec2"
  name       = "Application Server"
  data       = "confidential"
  runs_as    = "root"
  shape      = "process"
  threats    = true
}
```

The label is the component's identifier.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `technology` | string | a technology identifier | **required** |
| `name` | string | any | the technology's name |
| `data` | string | the project's classification scheme, which is `public`, `internal`, `confidential`, `restricted` unless a library states its own (section 6) | `internal` |
| `runs_as` | string | `user`, `admin`, `root`, `system`, `kernel` | `user` |
| `shape` | string | `actor`, `process`, `store` | the derived shape |
| `threats` | boolean | `true`, `false` | `true` |
| `tags` | string list | any | none |

`threats = false` stops the component raising threats at all.

`shape` states the data flow diagram shape the canvas draws. An actor is a
rectangle, a process is a circle, and a store is two horizontal lines. A block
that states no `shape` takes the derived shape: the `actor` provider gives an
actor, the `database`, `storage` and `secrets` categories give a store, and
every other technology gives a process.

A block with no `technology` is the error
`the component "<id>" names no technology`, and the block is dropped.

**Placement.** A `component` block inside a `zone` block sits in that zone. A
`component` block at the top level of the `system` block sits outside every
zone.

**`asset` on the system.** A system names the things of value it holds. A
component then states which of them it holds, and a flow states which it
carries, so one classification is written once and read wherever the asset
goes.

```hcl
system "Payments" {
  asset "card-numbers" {
    name           = "Card numbers"
    classification = "restricted"
    description    = "The primary account numbers customers type."
    owner          = "Payments team"
  }

  component "api" {
    technology = "aws-ec2"
    holds      = ["card-numbers"]
  }

  flow api -> ledger {
    kind    = "network"
    carries = ["card-numbers"]
  }
}
```

The label is the asset's identifier, which `holds` and `carries` name.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `name` | string | any, and not empty | **required** |
| `classification` | string | the words `data` takes | `internal` |
| `description` | string | any | empty |
| `owner` | string | any | none |

A component that states `holds` and no `data` of its own takes the highest
classification it holds. A component that states both keeps its own `data`
word; a `data` word below one it holds is the warning `the component "<id>"
states data "<word>" and holds "<asset id>", which is "<word>"`, and the file
still reads.

WARNING: a `holds` or a `carries` entry naming an asset no block declares is
an error, and the file does not read. A flow carrying an asset the component
it starts at does not hold is a warning, and the file still reads.

The report writes a `## Data inventory` section after `## Scope`: one row per
asset with its classification, its owner, the components that hold it, the
flows that carry it and the worst threat nobody has answered on any of them.
Each threat stanza names the assets at risk on the element that raised it. A
system that declares no asset writes no section, and scores exactly what it
scored before.

**`tags` on an element.** A `component`, a `zone` and a `flow` each state the
words a team files them under. A model of sixty components reads as one picture
of everything; a tag names a view of it.

```hcl
zone "app" {
  kind = "private"
  tags = ["payments"]

  component "api" {
    technology = "aws-ec2"
    tags       = ["payments", "pci"]
  }
}

flow api -> ledger {
  kind = "network"
  tags = ["payments"]
}
```

A tag is any text. The language states no vocabulary, so a team names its own
tags. An element holds none, one or many, and the file keeps the order the team
wrote. An element that states no `tags` writes no line.

The canvas toolbar lists every tag the system states and draws only the
elements that hold a picked tag, with the flows between them. The filter is a
view: it writes no file and changes no score, so a tagged model scores exactly
what the same model scored before.

**`diagram`.** A team keeps pictures the data-flow diagram cannot draw: a
sequence of a login, a deployment. A `diagram` block holds one, and the report
writes it under `## Diagrams` after the model inventory.

```hcl
system "Payments" {
  diagram "The login sequence" {
    kind = "mermaid"
    text = <<EOT
sequenceDiagram
  Customer->>API: signs in
  API->>Database: reads the account
EOT
  }
}
```

The label is what the report calls the picture.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `kind` | string | `mermaid` | `mermaid` |
| `text` | string or heredoc | any, and not only whitespace | **required** |

**The heredoc rule.** `<<TAG` starts a heredoc. The body starts on the next
line and ends at the first line holding the tag alone, whatever indents that
line. Every byte between the two stays as it is: no escape is read, no indent
is taken off and none is added. `format` writes the body at the left margin
with its `EOT` line at the left margin too, so a round trip gives the file it
read. A heredoc with no closing line is the error `this heredoc has no closing
"<tag>" line`.

GitHub draws a fenced `mermaid` block. The HTML report writes the same source
in a `<pre class="mermaid">` block: the page states the picture's source
rather than shipping a renderer, and a page that loads one draws it from that
same block.

**`source`.** A `component` and a `zone` may state what wrote them.

```hcl
component "aws-instance-api" {
  technology = "aws-ec2"
  source     = "terraform"
}
```

The language reads any word. `terraform` is the one
`threatmodeller import terraform` writes, and that verb owns only what it
wrote: an element stating `source = "terraform"` that the state no longer
holds is removed on the next import, and an element stating no `source` is a
person's own and is never removed or changed. The mapping is stated in
`docs/superpowers/specs/2026-09-15-terraform-import-design.md`.

**`third_party`.** A box on the diagram states a technology. A `third_party`
block states which company, project or person runs it, what the team pays and
what happens when it stops. A component names one with `provided_by`.

```hcl
system "Payments" {
  third_party "stripe" {
    name            = "Stripe"
    description     = "The company that takes the card payment."
    kind            = "saas"
    paying_customer = true
    uptime          = "hard"
    uptime_notes    = "No payment is taken while Stripe is down."
    owner           = "Payments team"
    link            = "https://stripe.com"
  }

  component "checkout" {
    technology  = "aws-ec2"
    provided_by = "stripe"
  }
}
```

The label is the third party's identifier, which `provided_by` names.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `name` | string | any, and not empty | **required** |
| `description` | string | any | empty |
| `kind` | string | `saas`, `open_source`, `infrastructure`, `contractor` | `saas` |
| `paying_customer` | boolean | `true`, `false` | `false` |
| `uptime` | string | `none`, `degraded`, `hard`, `operational` | **required** |
| `uptime_notes` | string | any | empty |
| `owner` | string | any | none |
| `link` | string | any | none |

`uptime` states what happens to this system when the party stops. `none` means
the system runs as it always did. `degraded` means the system runs and
something a person notices stops working. `hard` means the system stops.
`operational` means the system runs and the team cannot operate it.

WARNING: a `provided_by` naming a party no block declares is an error, and the
file does not read. A `hard` dependency that no assumption names is the warning
`this system cannot run without "<name>" and no assumption names it`: a
dependency nobody has thought about is the one that fails.

The report writes a `## Third parties` section after `## Data inventory`: one
row per party with its kind, whether the team pays, its uptime dependency, the
components it provides and the assets those components hold. The executive
summary states how many parties the system cannot run without. A system that
names none writes no section.

**`asset` on a component.** A component may hold one or more `asset` blocks. An
asset here is a thing of value the component holds, named on the component
rather than on the system.

```hcl
component "workstation" {
  technology = "generic-host"

  asset "ssh-keys" {
    data = "restricted"
  }
}
```

The label is the asset's name.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `data` | string | `public`, `internal`, `confidential`, `restricted` | `internal` |

A component scores at the highest sensitivity among its own `data` value and
every asset it holds. An asset never lowers what the component states: an
asset with a lower `data` value than the component changes nothing.

### 4.6 `flow`

```hcl
flow api -> ledger
```

A flow's two ends are **bare identifiers, not strings**, and each must name a
component the file declares.

A flow is directed. `flow a -> b` and `flow b -> a` are two flows.

A flow may take a body:

```hcl
flow guard -> store {
  kind        = "ipc"
  description = "XPC call"
}
```

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `kind` | string | `network`, `ipc`, `file`, `syscall`, `human` | `network` |
| `description` | string | any | none |
| `tags` | string list | any | none |

A flow with no body is a network flow: `flow a -> b` is the same as
`flow a -> b { kind = "network" }`.

A flow whose two ends run at different `runs_as` levels raises the privilege
threat set as well as its own.

### 4.7 `mitigates`

A `mitigates` edge states that one component lowers the risk of a named threat
set on another component.

```hcl
mitigates guard -> store {
  threats         = ["credential-theft"]
  reduces_risk_by = 80
  status          = "assumed"
}
```

Its two ends are bare identifiers, the same as a flow's: the component that
provides the mitigation, then the component it protects.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `threats` | list of strings | threat identifiers | **required** |
| `reduces_risk_by` | number | 0 to 100 | **required** |
| `status` | string | `adopted`, `assumed` | `adopted` |

A block with no `threats` is the error `the mitigates edge "<id>" names no
threats`. A block with no `reduces_risk_by` is the error `the mitigates edge
"<id>" has no reduces_risk_by`. Either error drops the block. A `status`
outside `adopted` or `assumed` is the error `status is "<value>"; a mitigates
edge is "adopted" or "assumed"`.

An `assumed` edge never lowers the residual score: it states a mitigation the
team plans but has not put in place. The report shows the score both with and
without it, in an "If assumed hold" column, so a reader sees the risk today
and the risk once the assumption is true. The report's `## Assumptions`
section also lists the edge itself, under an `### Assumed mitigations`
subheading, alongside the `assumption` blocks of section 4.2.

Two `mitigates` edges that lower the same threat on the same component give
the stronger reduction, not the sum.

**`recommendation`.** An `assumed` `mitigates` edge may hold a
`recommendation` block: what a team would do to adopt it.

```hcl
mitigates guard -> store {
  threats         = ["credential-theft"]
  reduces_risk_by = 60
  status          = "assumed"

  recommendation "adopt-the-guard" {
    text       = "Adopt the guard"
    note       = "It is bought and not deployed."
    blocked_by = "guard-not-deployed"
    sources    = ["https://example.com/ticket/1"]
  }
}
```

The label names the action.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `text` | string | any, and not empty | none |
| `note` | string | any | none |
| `blocked_by` | string | an `assumption` label declared in the same system | none |
| `sources` | list of strings | any | empty |

Only an `assumed` edge carries a `recommendation`. An `adopted` edge that
states one is the warning `the mitigates edge "<id>" is adopted, so it
carries no recommendation`, and the `recommendation` block drops; the edge
itself, and its `reduces_risk_by`, stand.

Two or more `mitigates` edges may share one label: this is one action, named
once but reachable through several edges. Exactly one of the edges states the
action's `text`; the others leave `text` unset. The parser keeps the action
on every edge in the group, and the report measures the group's leverage by
adopting every edge in the group at once, not edge by edge.

A label no edge states `text` for is the warning `the action "<label>"
states no text`, and every edge under that label drops its action. A label
two edges both state `text` for is the warning `the action "<label>" states
its text twice`; the parser keeps the first edge's action and drops the
action from the edge that repeated the text.

The other two faults belong to one edge alone:

| Check | Message |
| --- | --- |
| `text` present but empty, or all whitespace | `the action "<label>" has no text` |
| `blocked_by` names a label no `assumption` in the system declares | `the action "<label>" is blocked by "<blocker>", which no assumption declares` |

Each of these five checks is a warning, not an error: the faulty
`recommendation` block drops, and the `mitigates` edge that held it survives
with its own numbers.

A warning prints when `threatmodeller format` reads the file. `compile`,
`report` and `check` read the same file and apply the same fault, but print
nothing for it today; this matches every other architecture warning, such as
a zone with no components. A `recommendation` block with a fault of its own
drops with no message under those three commands, and the report then has no
leverage section and gives no reason why. Run `threatmodeller format` to see
the warning.

### 4.8 Identity and namespaces

An identifier in quotation marks is identity, not display text. `component "api"`
is the component `api`, whatever its `name` says.

A flow takes its identifier from its two ends: `flow api -> ledger` is the flow
`api->ledger`. A flow needs no identifier of its own.

The parser checks two namespaces:

- technologies and zones share one namespace
- components have their own namespace, across every zone and the top level

So a zone and a component may both be called `app`, but a zone and a technology
may not.

WARNING: the `.controls` file keys on these identifiers. When you rename an
identifier in `.arch`, the answers held against the old identifier are orphaned,
and the next compile moves them into a `stale` block.

### 4.9 Layout

The source holds no coordinates. The application lays the diagram out from
declaration order, so the same source always draws the same picture, and a
layout a user moves by hand is not written back. To change the picture, change
the order of the declarations.

### 4.10 Static checks

The parser runs these checks after the whole file parses. Each one reports the
first line of the file, because it is a fault of the file and not of one token.

Errors, which stop the import and produce no model:

| Check | Message |
| --- | --- |
| a technology or zone identifier declared twice | `"<id>" is declared twice` |
| a component identifier declared twice | `the component "<id>" is declared twice` |
| a flow that starts at an undeclared component | `the flow starts at "<id>", which this file does not declare` |
| a flow that ends at an undeclared component | `the flow ends at "<id>", which this file does not declare` |
| a flow from a component to itself | `the flow "<id>" starts and ends at the same component` |
| the same flow declared twice | `the flow "<id>" is declared twice` |
| a mitigates edge that starts at an undeclared component | `the mitigates edge starts at "<id>", which this file does not declare` |
| a mitigates edge that ends at an undeclared component | `the mitigates edge ends at "<id>", which this file does not declare` |
| a mitigates edge from a component to itself | `the mitigates edge "<id>" starts and ends at the same component` |
| the same mitigates edge declared twice | `the mitigates edge "<id>" is declared twice` |
| an assumption label declared twice | `the assumption "<label>" is declared twice` |

Warnings, which do not stop the import:

| Check | Message |
| --- | --- |
| a zone that declares no components | `the zone "<id>" holds no components` |
| a technology neither declared nor in the catalogue | `"<id>" is neither in this file nor in the catalogue, so "<component>" raises no threats` |
| a faced actor that performs no threat this model raises | `the threat actor "<id>" performs no threat this model raises` |
| a `performs` entry naming a threat no catalogue holds | `the threat actor "<id>" performs "<threat id>", which no catalogue holds` |

The last three warnings are raised by `ImportArchitecture`, not by the parser,
because only the import knows the catalogue.

A `techniques` entry that matches no threat is neither an error nor a warning.
ATT&CK holds hundreds of live techniques and the vendored catalogue names a few
dozen, so an unmatched technique is the normal case.

## 5. The controls language

A `.controls` file states the answer for every threat the architecture raises.
The compiler writes the file, and a person fills in the answers and commits
them.

### 5.1 Grammar

```
ControlsFile = ControlsBlock ;

ControlsBlock = "controls" "for" String "{" { ControlsEntry } "}" ;
ControlsEntry = CatalogueAttr | ToleranceAttr | ThreatBlock | TreeAnswerBlock ;

CatalogueAttr = "catalogue" "=" String ;
ToleranceAttr = "tolerance" "=" String ;

TreeAnswerBlock = [ "stale" ] "tree" String "{" { TreeAnswerEntry } "}" ;
TreeAnswerEntry = "goal"           "=" String
                | "chain"          "=" Number
                | "raises_risk_by" "=" Number
                | "score"          "=" Number
                | "score_before"   "=" Number
                | StepAnswerBlock ;

StepAnswerBlock = "step" String "{" { StepAnswerAttr } "}" ;
StepAnswerAttr  = "state" "=" String
                | "by"    "=" String ;

ThreatBlock = [ "stale" ] "threat" String "on" SourceKind String "{" { ThreatEntry } "}" ;
SourceKind  = "component" | "zone" | "flow" ;
ThreatEntry = "severity" "=" String
            | "score"    "=" Number
            | "impacts"  "=" StringList
            | LikelihoodBlock
            | SeverityOverrideBlock
            | ControlBlock
            | CompensatingBlock
            | RecommendationBlock ;

LikelihoodBlock = "likelihood" String "{" { LikelihoodAttr } "}" ;
LikelihoodAttr  = "tier"      "=" String
                | "prior"     "=" Number
                | "rationale" "=" String
                | "sources"   "=" StringList ;

SeverityOverrideBlock = "severity_override" String "{" { SeverityOverrideAttr } "}" ;
SeverityOverrideAttr  = "rationale" "=" String
                      | "sources"   "=" StringList ;

ControlBlock = "control" String "{" { ControlAttr } "}" ;
ControlAttr  = "status"      "=" String
             | "note"        "=" String
             | "evidence"    "=" String
             | "reference"   "=" String
             | "verified_on" "=" String ;

CompensatingBlock = "compensating" String "{" { CompensatingAttr } "}" ;
CompensatingAttr  = "reduces_risk_by" "=" Number
                  | "rationale"       "=" String
                  | "sources"         "=" StringList
                  | "evidence"        "=" String
                  | "reference"       "=" String
                  | "verified_on"     "=" String ;

RecommendationBlock = "recommendation" String "{" { RecommendationAttr } "}" ;
RecommendationAttr  = "note"    "=" String
                    | "sources" "=" StringList ;
```

A file holds exactly one `controls for` block. Text after its closing brace is
not read.

A file that does not start with `controls` is the error `expected controls,
not "<word>"`, and nothing is read. A `controls` block missing the keyword
`for` is the error `expected for, not "<word>"`. Both messages read
differently from the architecture and library files' `this file starts with
<keyword>, not "<word>"`, because the controls parser checks the two keywords
`controls` and `for` in turn, rather than one keyword.

### 5.2 `controls for`

```hcl
controls for "Payments" {
  catalogue = "v1.0.1"
  …
}
```

The label is the system's name. It matches the name in the `.arch` file.

| Attribute | Type | Default | Meaning |
| --- | --- | --- | --- |
| `catalogue` | string | the catalogue in use | the catalogue tag this file was written against |
| `tolerance` | string | `low` | the risk level a likelihood finding may answer up to |

The compiler writes `tolerance` from the `.arch` file's `risk_tolerance`, so
this file reads alone. A person editing it changes nothing: the next compile
overwrites it. `threatmodeller check --tolerance <level>` overrides the value
for one run, without changing either file. A value outside `low`, `medium`,
`high` or `critical` is the error `tolerance is "<value>"; this application
holds "low", "medium", "high", "critical"`.

### 5.3 `threat`

```hcl
threat "t-credential-theft" on component "api" {
  severity = "critical"
  score    = 90
  …
}
```

A threat block takes two labels: the threat identifier, then, after the keyword
`on`, what raised it. `on` takes a source kind — `component`, `zone` or `flow` —
and then the identifier of that component, zone or flow **in quotation marks**.

A flow identifier is `"<source>-><target>"`, which is what section 4.8 mints:

```hcl
threat "t-mitm" on flow "cdn->api" { }
```

| Attribute | Type | Meaning |
| --- | --- | --- |
| `severity` | string | the severity, restated from the catalogue so the file reads alone |
| `score` | number | the score, restated the same way |
| `impacts` | a list of `confidentiality`, `integrity`, `availability` | what this threat harms in this system |

WARNING: `severity` and `score` are written for the reader. The application
recomputes both from the catalogue and the answers, so an edit to either changes
nothing.

`impacts` is the team's answer, and the application keeps it. A threat that
states none harms what the catalogue says it harms, and the catalogue's own
answer comes from the threat's stride categories when the threat states no
impact of its own:

| Stride category | What it harms |
| --- | --- |
| `spoofing` | confidentiality |
| `information-disclosure` | confidentiality |
| `tampering` | integrity |
| `repudiation` | integrity |
| `denial-of-service` | availability |
| `elevation-of-privilege` | confidentiality, integrity, availability |

A threat that states no stride category, and one whose categories are outside
this table, harms all three. An `impacts` list holding a word outside the three
is the warning `impacts holds "<word>"; this application holds confidentiality,
integrity and availability`, and the word is dropped.

An impact labels a threat and moves no number: the score is what section 3 of
the design states, whatever the threat harms.

An empty body means the threat is raised and nothing answers it:

```hcl
threat "t-lateral-movement" on zone "app" { }
```

A threat block with no `on` keyword after the threat identifier is the error
`a threat says what raised it: on component, on zone or on flow`. A source
kind that is not `component`, `zone` or `flow` is the error `a threat is
raised by a component, a zone or a flow, not "<word>"`.

**`recommendation`.** A threat block may hold one or more `recommendation`
blocks, alongside its controls.

```hcl
threat "credential-theft" on component "c1" {
  recommendation "Protect the managed preferences plist" {
    note    = "Deny write from anything but the MDM daemon."
    sources = ["https://example.com/mdm-hardening"]
  }
}
```

The label is what a person says should be done. `note` is optional free text.
A threat may hold more than one recommendation.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `note` | string | any | none |
| `sources` | list of strings | any | empty |

`sources` is a URL, a CVE identifier, or any other text that says where the
recommendation comes from.

A compile keeps a recommendation whole, the same way it keeps a control's
status and a compensating control's rationale.

A recommendation answers nothing. It does not count toward `isAnswered`, so
`threatmodeller check` exits 1 for a threat that holds a recommendation and no
answer.

### 5.4 `stale threat`

```hcl
stale threat "t-sql-injection" on component "cache" {
  control "Use parameterised queries" { status = "implemented" }
}
```

`stale` marks an answer for a threat the architecture no longer raises. The body
is the body of a `threat` block.

Nothing deletes a stale block, and the application does not apply what it holds.
A person deletes it. When the architecture raises that threat again, the next
compile moves the answer back out of `stale` with its statuses intact.

`threatmodeller check` exits 1 while a stale block remains, and prints
`<key> is answered but no longer raised`. So a stale block is work for a person:
read the answer, then either restore what raised the threat or delete the
block.

### 5.5 `tree` and `stale tree`

The compiler writes one stanza for every tree the `.attacktree` file states, so
the controls file reads alone. Every number here is recomputed on the next
compile, the way `severity` and `score` are, so an edit changes nothing.

```hcl
tree "read-every-customer-record" {
  goal           = "data-exfiltration@component:db"
  chain          = 100
  raises_risk_by = 40
  score          = 7
  score_before   = 5

  step "ssrf-attack@component:appserver" {
    state = "open"
  }

  step "credential-theft@component:appserver" {
    state = "closed"
    by    = "Enforce IMDSv2 with a hop limit of 1"
  }
}
```

| Attribute | Meaning |
| --- | --- |
| `goal` | the threat key the boost lands on |
| `chain` | the chain factor the weakest open step gave, as a percentage |
| `raises_risk_by` | the number the `.attacktree` file states |
| `score` | the goal's score after the boost |
| `score_before` | the goal's score before it |
| `step.state` | `open` or `closed` |
| `step.by` | the control description that closed the step, when one did |

A live `tree` stanza never holds `unbound`, because one unbound step moves the
whole tree into `stale tree`:

```hcl
stale tree "read-every-customer-record" {
  step "credential-theft@component:appserver" {
    state = "unbound"
  }
}
```

A stale tree states no number: nothing recomputed them, and a number nobody can
trust is worse than no number. `threatmodeller check` exits 1 while one
remains, and prints `the tree "<id>" is written but no longer binds`.

A tree the `.attacktree` file no longer states writes no stanza at all, because
a person owns that file and deleting a tree there loses nothing.

### 5.6 `control`

```hcl
control "Enforce MFA on all administrative access" {
  status = "implemented"
  note   = "Okta, enforced group-wide"
}
```

The label is the control's **description**, which is what the catalogue gives.
The description is the identity of the control: a control whose description has
left the catalogue is dropped from the stanza at the next compile, and its
answer is not kept.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `status` | string | `implemented`, `not_implemented`, `not_applicable`, `accepted` | `not_implemented` |
| `note` | string | any | none |

| Status | Counts as an answer | Lowers the score |
| --- | --- | --- |
| `implemented` | yes | yes, by its share of the applicable controls |
| `not_applicable` | yes | no, and it leaves the share |
| `accepted` | yes | no, and it stays in the share |
| `not_implemented` | no | no |

The implemented controls lower the score together, not one at a time. The
share is `implemented / applicable`, where `applicable` is every control whose
status is not `not_applicable`. That share takes off at most 70% of the score,
and a score never falls below 1. A threat with 5 controls and 3 implemented
scores `round(12 * (1 - 0.6 * 0.70))` = 7 where it scored 12.

WARNING: `accepted` answers a threat and lowers nothing. An accepted risk is
still a risk, and the report states it at its full score.

`not_implemented` is what a control starts as, so it does not count as an
answer. `threatmodeller check` exits 1 while any threat holds no answered
control and no compensating control.

A `status` outside the four values is an error that lists the four.

`note` is free text, and a rewrite keeps it.

**Evidence.** A `control` and a `compensating` block each state what proves
the control is in place:

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `evidence` | string | `asserted`, `documented`, `configured`, `tested`, `audited` | none |
| `reference` | string | any | empty |
| `verified_on` | string | a date, `YYYY-MM-DD` | none |

```hcl
control "Enforce MFA on all administrative access" {
  status      = "implemented"
  evidence    = "tested"
  reference   = "ci/okta-mfa-enforced-test"
  verified_on = "2026-09-01"
}
```

The five tiers run weakest first, and the order is the order of what a reader
can check for themselves: somebody says so; a document says so; somebody read
the configuration; a test fails when the control is off; an audit found it. A
control that states no tier is unevidenced, which is what every control written
before these attributes existed is.

A tier moves no score. A score that moved with the tier would fall when a team
wrote down what it already knew, and rise when a document went stale; the
control is either in place or it is not, and the tier says how well a reader
can check that claim. The report names the tier beside each implemented
control, the executive summary counts the ones that state none, and
`requires_evidence_above` in the `.arch` file is what makes a missing tier fail
a build.

An `evidence` outside the five is the error `evidence is "<raw>"; this
application holds "asserted", "documented", "configured", "tested",
"audited"`. A `verified_on` that is not a date gives the two messages section
8.6 gives for a date.

### 5.7 `compensating`

```hcl
compensating "Break-glass account watched by the SIEM" {
  reduces_risk_by = 40
  rationale       = "Standing keys are gone; the one account left alerts on use."
  sources         = ["https://example.com/break-glass-runbook"]
}
```

The label is what the compensating control is called.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `reduces_risk_by` | number | 0 to 100 | `0` |
| `rationale` | string | any, and not empty | **required** |
| `sources` | list of strings | any | empty |

`sources` is a URL, a CVE identifier, or any other text that says where the
compensating control comes from.

A block with no `rationale`, or an empty one, is the error
`the compensating control "<label>" has no rationale`, and the block is dropped.
A reduction nobody can justify is not one.

A `reduces_risk_by` outside 0 to 100 is the error
`reduces_risk_by is <n>; it runs from 0 to 100`.

A compensating control makes a threat answered on its own, without any control
being `implemented`.

Two compensating controls on one threat give the stronger of the two, not the
sum.

### 5.8 `likelihood`

A `likelihood` block is a finding: what a person learned about how often an
attack of this kind happens, and why. It is evidence, not a control, and it
multiplies the score rather than answering the threat outright.

```hcl
threat "t-credential-theft" on component "api" {
  likelihood "no campaign has used this against our stack" {
    tier      = "research"
    rationale = "No public reporting names this technique against this platform."
    sources   = ["https://example.com/threat-report"]
  }
}
```

The label is what the finding says. A threat holds at most one `likelihood`
block.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `tier` | string | `commodity`, `targeted`, `research` | one of `tier` or `prior` is **required** |
| `prior` | number | 0 to 100 | one of `tier` or `prior` is **required** |
| `rationale` | string | any, and not empty | **required** |
| `sources` | list of strings | any | empty |

`sources` is a URL, a CVE identifier, or any other text that says where the
finding comes from.

A block states a tier or a prior, never both. `tier` names a band from the
library language's three tiers; `prior` is a percentage a person measured or
estimated directly.

A `tier` outside `commodity`, `targeted` or `research` is the error `tier is
"<raw>"; this application holds "commodity", "targeted", "research"`. A block
with no `rationale`, or an empty one, is the error `the likelihood "<label>"
has no rationale`, and the block is dropped. A finding nobody can justify is
not one. A block that states both a `tier` and a `prior` is the error `the
likelihood "<label>" states a tier and a prior; it states one`. A block that
states neither is the error `the likelihood "<label>" states no tier and no
prior`. A `prior` outside 0 to 100 is the error `prior is <n>; it runs from 0
to 100`. A threat that holds a second `likelihood` block is the error `this
threat holds two likelihood blocks; it holds one`.

`threatmodeller check` counts a threat as answered by its likelihood only
while the residual score sits at or below the project's risk tolerance.
Section 4.2 and section 5.2 state that tolerance; `--tolerance <level>`
overrides it for one run.

### 5.9 `severity_override`

A `severity_override` block is a person's decision to raise or lower a
threat's severity from what the catalogue states, with the reasoning kept
beside it.

```hcl
threat "t-data-exfiltration" on component "ledger" {
  severity_override "critical" {
    rationale = "This ledger holds the whole customer balance, not one row."
    sources   = ["https://example.com/data-classification-policy"]
  }
}
```

The label is the severity the assessor chose. A threat holds at most one
`severity_override` block.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `rationale` | string | any, and not empty | **required** |
| `sources` | list of strings | any | empty |

`sources` is a URL, a CVE identifier, or any other text that says where the
decision comes from.

A block with no `rationale`, or an empty one, is the error `the
severity_override "<label>" has no rationale`, and the block is dropped. A
severity decision nobody can justify is not one. A threat that holds a second
`severity_override` block is the error `this threat holds two
severity_override blocks; it holds one`.

A label naming a severity the catalogue does not hold is not a parser error:
`ApplyControlAnswers` warns `"<severity>" is not a severity this catalogue
holds, so the severity_override on "<threat id>" is not applied`, and the
catalogue's own severity stands.

### 5.10 Threat keys

Each threat block names one key. The key pairs the threat identifier with what
raised it:

```
<threat identifier>@<kind>:<identifier>
```

The kind in a key is `component`, `zone` or `connection`. The file says `flow`
and the key says `connection`; `SourceThreatAnswer.resolverKind` is the one
place that maps the two words.

So `threat "t-mitm" on flow "cdn->api"` holds the key
`t-mitm@connection:cdn->api`.

Two blocks with the same key are the error `<key> is answered twice`.

### 5.11 What the application does with the answers

`ApplyControlAnswers` reads the file against the threats the architecture
raises. It skips every `stale` block, and it warns rather than fails when a file
says something the model does not:

| Case | Warning |
| --- | --- |
| the model does not raise that threat on that source | `this model does not raise "<threat>" on <kind> "<id>", so its answers are not applied` |
| the threat no longer offers that control | `"<threat>" no longer offers the control "<description>", so its answer is not applied` |
| the `severity_override` names a severity the catalogue does not hold | `"<severity>" is not a severity this catalogue holds, so the severity_override on "<threat>" is not applied` |

### 5.12 The merge

`threatmodeller compile` reads the architecture and the existing `.controls`
file, then writes the `.controls` file back.

| Case | Result |
| --- | --- |
| the architecture raises the threat and the file answers it | the answer is kept whole: statuses, notes and compensating controls |
| the architecture raises the threat and the file does not answer it | a stanza appears with every control at `not_implemented` |
| the file answers a threat the architecture no longer raises | the answer moves into a `stale` block |
| a control has left the catalogue | the control is dropped, and its answer is not kept |
| a stale answer's threat is raised again | the answer moves back out of `stale`, with its statuses |

## 6. The library language

A `.lib` file states technologies, threats and the controls those threats offer,
so a team defines a thing once and every project reads it. A person writes it,
and `threatmodeller library add` vendors somebody else's into a project.

Every `.lib` file a project holds sits in `<directory>/library`, and every
system in the project reads every one of them. `library.lock.json` beside them
records which repository and tag each came from, and the `sha256` of each file.
The key in that file is the library's label, which is the label of the `library`
block. `threatmodeller library verify` says the files and the lock file agree,
and needs no network. The README states the six `library` operations.

### 6.1 Shape

```hcl
library "acme" {
  name      = "Acme Platform"       # the palette group's title; default is the label
  catalogue = "v1.0.1"              # the catalogue tag this was written against

  # The words this library adds to the taxonomy. A team whose domain the
  # vendored categories do not name declares it here.
  category "operational-technology" {
    name = "Operational Technology"
  }

  severity "catastrophic" {
    name = "Catastrophic"
  }

  stride "safety" {
    name = "Safety"
  }

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

**A technology that crosses systems and projects belongs in a library.** A
`technology` block in an `.arch` file belongs to the system that states it. The
application moves one into a library: *Move to Library…* on the palette row
writes it into `<directory>/library/<name>.lib`, takes it out of the `.arch`
file, and points every component at the identifier the library mints,
`<library>-<id>`. Every system in the project reads every library file, so the
technology is stated once and read by both. Another project vendors it with
`threatmodeller library add`, and `threatmodeller library verify` says when a
vendored copy and the lock file disagree.

A `classification` block states one level of a classification scheme, and the
order the blocks appear in is the scheme: the first level is the least
sensitive and the last is the most. A project whose library states a scheme
takes those words for a component's `data`, for an asset's `data` and for the
chips the palette draws.

**Scoring reads the position, not the id.**

    rank  = the level's position in the scheme, counting from 1
    score = the threat's severity rank × the data's rank

A team whose scheme is `official`, `official-sensitive`, `secret` and
`top-secret` scores `secret` at 3, because it sits third, the same as
`confidential` in the standard scheme: a critical threat (severity rank 4) on
`secret` data scores 4 × 3 = 12. A five level scheme scores its top level at 5,
so the same threat scores 4 × 5 = 20.

A word the project's scheme does not hold is a warning naming the words it
does hold, and it ranks 1: an unknown word never inflates a score. Two
libraries that state a scheme give a warning naming both, and the first one
read stands. A project that reads no such library keeps `public`, `internal`,
`confidential` and `restricted`, and scores as it always has.

An `override` block changes what the catalogue says about a threat the
catalogue already holds: its severity, its likelihood, its description or its
controls. A block states what it changes and nothing else, and a control list
with entries replaces the catalogue's controls, because a team that words its
own controls means those and not those plus the catalogue's. An override of a
threat the catalogue does not hold refuses the library and names the id.

**The merge order** is the catalogue first, then each library in the order the
project reads them, which is its `.lib` files by name, then the per-model
severity override. A later library's override wins over an earlier one's, and
the per-model override wins over both: the resolver applies it after the
catalogue has answered. The report writes
`- Changed by the library: <library>` on a threat a library changed, so a
reader can tell an overridden value from the catalogue's own.

A `mitigation` block states a pathway mitigation the library brings: what
provides it, which threats it answers, the percentage it lowers a score by and
the mode it starts in. A threat the library marks `pathway = true` is a pathway
threat. The Pathway Mitigations panel lists the vendored mitigations and every
library's together, and names the library each library one came from.

A library's own words are known to that library: a technology names a category
it declares, and a threat names a severity or a stride category it declares. A
word the vendored taxonomy already holds stands as the vendored catalogue
states it: a library adds to the taxonomy and never changes what a word means.
Two libraries that declare one id give a warning naming both, and the one read
first stands. A library severity ranks above every vendored severity, because a
team that words its own severity means something the vendored scale does not
hold.

### 6.2 Grammar

```
LibraryFile  = LibraryBlock ;
LibraryBlock = "library" String "{" { LibraryEntry } "}" ;
LibraryEntry = "name"      "=" String
             | "catalogue" "=" String
             | ClassificationBlock
             | TaxonomyBlock
             | TechnologyBlock
             | ThreatBlock
             | MitigationBlock
             | ThreatActorBlock ;

TaxonomyBlock = ( "category" | "severity" | "stride" ) String "{" "name" "=" String "}" ;

ClassificationBlock = "classification" String "{" "name" "=" String
                      [ "colour" "=" String ] "}" ;

ThreatBlock = "threat" String "{" { ThreatEntry } "}" ;
ThreatEntry = "name"         "=" String
            | "description"  "=" String
            | "severity"     "=" String
            | "stride"       "=" StringList
            | "impacts"      "=" StringList
            | "connection"   "=" Boolean
            | "zone"         "=" Boolean
            | "zone_context" "=" String
            | "applies_to"   "=" StringList
            | "boundary"     "=" String
            | "runs_as"      "=" StringList
            | "pathway"      "=" Boolean
            | "likelihood"   "=" ( String | Number )
            | MitreBlock
            | ControlStatement ;

MitreBlock = "mitre" String "{" { MitreAttr } "}" ;
MitreAttr  = "name"   "=" String
           | "tactic" "=" String ;

ControlStatement = "control" String ;

MitigationBlock = "mitigation" String "{" { MitigationAttr } "}" ;
MitigationAttr  = "name"            "=" String
                | "description"     "=" String
                | "mitigates"       "=" StringList
                | "provided_by"     "=" StringList
                | "reduces_risk_by" "=" Number
                | "mode"            "=" String ;
```

`TechnologyBlock` is the block section 4.5's `.arch` file holds, read by the
same code, so a technology reads the same in both files.

A file holds exactly one `library` block. Text after its closing brace is not
read.

### 6.3 The blocks and the attributes

| Block | Label | Attribute | Values | Default |
| --- | --- | --- | --- | --- |
| `library` | the provider id | `name` | string | the label |
| | | `catalogue` | a tag string | none |
| `technology` | the technology id | `name` | string | **required** |
| | | `category` | a category id from the taxonomy | **required** |
| | | `description` | string | empty |
| | | `threats` | a list of threat ids | empty |
| | | `encrypts` | `true` or `false` | `false` |
| `threat` | the threat id | `name` | string | **required** |
| | | `description` | string | empty |
| | | `severity` | a severity id from the taxonomy | **required** |
| | | `stride` | a list of stride ids | empty |
| | | `impacts` | a list of `confidentiality`, `integrity`, `availability` | what the stride categories decide |
| | | `connection` | `true` or `false` | `false` |
| | | `zone` | `true` or `false` | `false` |
| | | `zone_context` | string | none |
| | | `applies_to` | a list of flow kinds: `network`, `ipc`, `file`, `syscall`, `human` | empty |
| | | `boundary` | `network`, `privilege` | none |
| | | `runs_as` | a list of privilege levels: `user`, `admin`, `root`, `system`, `kernel` | empty |
| | | `pathway` | `true` or `false` | `false` |
| | | `likelihood` | a tier — `commodity`, `targeted`, `research` — or a whole number 0 to 100 | `commodity` |
| `mitre` | the technique id | `name` | string | **required** |
| | | `tactic` | string | **required** |
| `control` | the control's description | none | | |
| `mitigation` | the mitigation id | `name` | string | **required** |
| | | `description` | string | empty |
| | | `mitigates` | a list of threat ids | **required** |
| | | `provided_by` | a list of technology ids | **required** |
| | | `reduces_risk_by` | number, 0 to 100 | `0` |
| | | `mode` | `remove`, `reduce` | `reduce` |

`connection = true` makes the threat one a link between two components raises.
`zone = true` makes it one a network zone raises. `applies_to` narrows a
connection threat to the flow kinds named; `boundary` narrows a zone threat to
the zone boundary named. `runs_as` names the privilege levels the threat runs
at. `pathway = true` marks the threat as one a pathway mitigation can lower.

`likelihood` states how often an attack of this kind happens: how many
attackers actually use it, not how bad it is when they do. It takes one of the
three tier words, or a whole number from 0 to 100 that a person measured
directly. A threat that states none is `commodity`, the busiest tier, so a
model that says nothing about likelihood keeps the score it always had.

```hcl
threat "credential-theft" {
  name       = "Credential theft"
  severity   = "high"
  likelihood = "targeted"
}

threat "supply-chain-compromise" {
  name       = "Supply-chain compromise"
  severity   = "critical"
  likelihood = 15
}
```

A tier word outside the three is the error `likelihood is "<word>"; this
application holds "commodity", "targeted", "research", or a whole number from
0 to 100`. A number outside 0 to 100 is the error `likelihood is <n>; a whole
number runs from 0 to 100`.

A `mitigation` block declares a pathway mitigation: a control a technology
provides that lowers named threats. `reduces_risk_by` is the percentage the
mitigation starts at and `mode` is what it does to a threat it answers;
a project's settings may change either. A block with no
`name` is the error `the mitigation "<id>" has no name`. A block with no
`mitigates` is the error `the mitigation "<id>" names no threats`. A block
with no `provided_by` is the error `the mitigation "<id>" names no
technologies`. A `mode` outside the two words is the error `mode is "<word>";
this application holds "remove" and "reduce"`.

The library states the mode and the percentage; the application states neither.
A mitigation whose block leaves one out takes the application's own default for
that one alone: mode `reduce` at 50 per cent.

**Two mitigations answering one threat compound.** Each one acts on the risk
the one before it left, so two mitigations always lower a score further than
the stronger of the two alone:

```
score = score × (1 − p1/100) × (1 − p2/100) × …
```

The result is floored, and never falls below 1: a control that lowers a risk
has not removed it. One mitigation in `remove` mode drops the threat, whatever
the others say. Multiplication does not care about order, and the floor runs
once at the end, so the same set of mitigations always gives the same score.

Worked number. Credential theft is critical (4) on confidential data (3), so
it scores 12. A WAF reduces it by 50 per cent and secret rotation reduces it by
25 per cent:

```
12 × (1 − 50/100) = 6
 6 × (1 − 25/100) = 4.5
floor(4.5)        = 4
```

The threat scores 4. The stronger mitigation alone would leave 6.

A zone threat reads the mitigations the components **inside that zone**
provide. A zone sits nowhere in the connection graph, so nothing is upstream of
it; a firewall in the zone answers the threats about moving inside it.

A `threat_actor` block declares an adversary a system can face. `capability`
carries the factor a likelihood tier carries: `commodity` 1.0, `targeted` 0.6,
`research` 0.25. A capability says how many attackers of this kind there are,
not how skilled one of them is.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `name` | string | any | **required** |
| `description` | string | any | empty |
| `aliases` | list of strings | any | empty |
| `capability` | string | `commodity`, `targeted`, `research` | `targeted` |
| `intent` | string | any | empty |
| `performs` | list of strings | threat ids | empty |
| `techniques` | list of strings | MITRE technique ids | empty |
| `performs_catalogue_tier` | string | `commodity`, `targeted`, `research` | none |

```hcl
threat_actor "insider" {
  name        = "Disgruntled operator"
  description = "A person with production access who has resigned."
  aliases     = ["leaver"]
  capability  = "commodity"
  intent      = "sabotage"
  performs    = ["data-exfiltration", "credential-theft"]
  techniques  = ["T1078", "T1530"]
}
```

An actor performs a threat when any one of three tests passes: `performs` holds
the threat's id; `techniques` holds a technique whose parent matches the parent
of one of the threat's own techniques, so `T1550.001` matches `T1550`; or
`performs_catalogue_tier` equals the threat's catalogue likelihood.

A threat's likelihood is then the highest capability among the actors the
system faces that perform it. A threat no faced actor performs keeps the
catalogue's own likelihood, so a short or wrong actor list never lowers a
score. A `likelihood` block in a `.controls` file beats both.

A `control` is a statement with a label and no body, because a library states
what a control is and a `.controls` file states its status. Its key is minted
from its description, which is the rule the vendored catalogue follows.

### 6.4 Identity

The label of the `library` block is a provider id. Every technology id, every
threat id and every threat actor id the file declares is minted `<label>-<id>`, so two teams can both
define `cribl-stream` and neither clashes:

```hcl
component "ingest" {
  technology = "acme-cribl-stream"
}
```

Inside a library, a threat id in a `threats` list resolves against the library
first and the vendored catalogue second. So `["pipeline-tamper",
"credential-theft"]` takes the first from the library and the second from the
catalogue.

The palette shows one group for each library, beside AWS, Azure and SaaS.

### 6.5 The canonical form

`threatmodeller format` rewrites every `.lib` file the project holds, the way
it rewrites every `.arch` and `.attacktree` file. The canonical form is the
architecture file's:

- two-space indentation,
- the equals signs of one block lined up,
- one blank line between blocks,
- an attribute holding its default not written,
- the taxonomy a library adds first, then the technologies, then the threats,
  then the mitigations, then the threat actors.

A rewrite of a file already in this shape writes nothing and says
`unchanged <path>`. A file that does not parse is left as it is, its faults are
printed as `<path>:<line>:<column>: <message>`, and the verb exits 2.

### 6.6 What the parser refuses

Errors, which stop the project opening:

| Check | Message |
| --- | --- |
| a file that does not start with `library` | `this file starts with library, not "<word>"` |
| a duplicate technology id | `the technology "<id>" is declared twice` |
| a duplicate threat id | `the threat "<id>" is declared twice` |
| a technology with no `name` | `the technology "<id>" has no name` |
| a technology with no `category` | `the technology "<id>" has no category` |
| a threat with no `name` | `the threat "<id>" has no name` |
| a threat with no `severity` | `the threat "<id>" has no severity` |
| a duplicate threat actor id | `the threat actor "<id>" is declared twice` |
| a threat actor with no `name` | `the threat actor "<id>" has no name` |
| a `capability` outside the three tiers | `capability is "<word>"; this application holds "commodity", "targeted", "research"` |
| a `performs_catalogue_tier` outside the three tiers | `performs_catalogue_tier is "<word>"; this application holds "commodity", "targeted", "research"` |
| a `mitre` block with no `name` | `the technique "<id>" has no name` |
| a `mitre` block with no `tactic` | `the technique "<id>" has no tactic` |
| a block or an attribute the grammar does not hold | `a library holds name, catalogue, technology, threat and mitigation, not "<word>"` |

Warnings, which do not:

| Check | Message |
| --- | --- |
| a threat with no `control` | `the threat "<id>" offers no control, so nothing can answer it` |
| a threat no technology names, that is neither a connection nor a zone threat | `no technology in this library names "<id>", so nothing raises it` |

`severity`, `stride` and `category` are taxonomy data rather than grammar, so
the parser accepts any string and the **load** refuses a value the taxonomy does
not hold:

```
the technology "cribl-stream" is in the category "observability", which the taxonomy does not hold
```

Two libraries in one project that carry the same label is an error as well:

```
this project already holds a library called "acme"
```

A library that does not load stops the project opening, rather than loading the
libraries that do, because half a catalogue draws a diagram nobody can trust.

## 7. The attack tree language

A `.attacktree` file sits beside the `.arch` file it belongs to and takes the
same stem: `threatmodel/payments.arch` pairs with
`threatmodel/payments.attacktree`. A person writes it. It states the routes
through a system that a person confirmed, and how much each route raises the
threat it ends on.

### 7.1 Grammar

```
AttackTreeFile = AttackTreesBlock ;

AttackTreesBlock = "attack_trees" "for" String "{" { AttackTreesEntry } "}" ;
AttackTreesEntry = CatalogueAttr | TreeBlock ;

CatalogueAttr = "catalogue" "=" String ;

TreeBlock = "tree" String "{" { TreeEntry } "}" ;
TreeEntry = "name"           "=" String
          | "description"    "=" String
          | "raises_risk_by" "=" Number
          | GoalStatement
          | NodeBlock
          | StepBlock ;

GoalStatement = "goal" String "on" SourceKind String ;
SourceKind    = "component" | "zone" | "flow" ;

NodeBlock = ( "all_of" | "any_of" ) "{" { NodeEntry } "}" ;
NodeEntry = StepBlock | NodeBlock ;

StepBlock = "step" String "on" SourceKind String [ "{" { StepEntry } "}" ] ;
StepEntry = "note" "=" String ;
```

A file holds exactly one `attack_trees for` block. Text after its closing brace
is not read.

### 7.2 The blocks and the attributes

| Block | Label | Attribute | Values | Default |
| --- | --- | --- | --- | --- |
| `attack_trees for` | the system name | `catalogue` | a tag string | the catalogue in use |
| `tree` | the tree id | `name` | string | the label |
| | | `description` | string | none |
| | | `raises_risk_by` | number, 0 to 100 | `0` |
| `goal` | the threat id, then the source | | | **required** |
| `step` | the threat id, then the source | `note` | string | none |

`raises_risk_by = 0` is a tree that narrates and scores nothing. The report
prints it, `check` gates on it, and no number moves.

A tree body holds exactly one root, which is one `all_of`, one `any_of` or one
`step`.

```hcl
attack_trees for "Two-Tier Web Application" {
  catalogue = "v1.0.1"

  tree "read-every-customer-record" {
    name           = "Read every customer record"
    description    = "An unauthenticated caller reaches the customer table."
    raises_risk_by = 40

    goal "data-exfiltration" on component "db"

    all_of {
      step "ssrf-attack" on component "appserver" {
        note = "The avatar import fetches a URL the user gives it."
      }

      any_of {
        step "credential-theft" on component "appserver"

        all_of {
          step "excessive-permissions" on component "secrets"
          step "privilege-escalation" on component "secrets"
        }
      }
    }
  }
}
```

### 7.3 `goal` and `step`

Both take the two-label shape the controls language uses in section 5.3:
`"<threat id>" on component "<id>"`, and `zone` and `flow` in place of
`component`. One shape, read by one rule, in three languages.

A `step` with no body is that same step with an empty body, which is the rule
`flow a -> b` already sets in section 4.6.

### 7.4 `all_of` and `any_of`

| Node | Open while | Factor |
| --- | --- | --- |
| `step` | nothing has closed it | the threat's own likelihood factor |
| `any_of` | any child is open | the **strongest** open child |
| `all_of` | every child is open | the **weakest** child |

`any_of` takes the strongest child because an attacker picks the easiest
branch. `all_of` takes the weakest because the chain needs every one of them.
A tree whose root is closed gives no boost.

### 7.5 What binds, and what closes

A step **binds** when the resolved model raises that threat on that source. A
bound step is **closed** when its threat holds at least one `implemented`
control or a `compensating` block, and **open** otherwise.

`not_applicable` and `accepted` answer a threat and close no step: the control
does not apply, or the team lives with it, and an attacker still walks the
step. A `likelihood` finding closes no step either; it lowers the step's
factor.

One step that does not bind, or a goal that does not bind, makes the whole tree
**stale**. A stale tree moves no score, the compile writes it as a
`stale tree` stanza, and `threatmodeller check` exits 1 while one remains.

A step naming a component the `.arch` file does not declare is not a parser
fault: the parser reads one file and the architecture is another, the way
section 4.10 states for the catalogue warning.

### 7.6 What the parser refuses

Errors, which stop the read and produce no source:

| Check | Message |
| --- | --- |
| a file that does not start with `attack_trees` | `expected attack_trees, not "<word>"` |
| a block missing `for` | `expected for, not "<word>"` |
| a tree id declared twice | `the tree "<id>" is declared twice` |
| a tree with no `goal` | `the tree "<id>" states no goal` |
| a tree with two `goal` statements | `the tree "<id>" states two goals; it states one` |
| a tree with no root node | `the tree "<id>" holds no steps` |
| a tree with two root nodes | `the tree "<id>" holds two roots; it holds one` |
| an `all_of` or `any_of` with no entries | `the <word> in the tree "<id>" holds nothing` |
| a source kind that is not `component`, `zone` or `flow` | `a step is raised by a component, a zone or a flow, not "<word>"` |
| a `goal` or `step` with no `on` | `a step says what raises it: on component, on zone or on flow` |
| `raises_risk_by` outside 0 to 100 | `raises_risk_by is <n>; it runs from 0 to 100` |
| an entry the grammar does not hold | `a tree holds name, description, raises_risk_by, goal, all_of, any_of and step, not "<word>"` |

## 8. The governance language

A `.governance` file sits beside the `.arch` and `.controls` files of one
system and takes the same stem. `threatmodeller compile` writes it; a person
fills it in and commits it. A system that accepts no control, holds no
recommendation and declares no action gets no file: nothing writes an empty
one.

A `.controls` file lets a person write `status = "accepted"` and move on. That
records that somebody accepted the risk, and nobody's name, no date and no date
to read it again. An accepted risk with no owner and no review date is not a
decision; it is a threat somebody stopped reading. This file is where the
decision lives.

### 8.1 Grammar

```
GovernanceFile  = GovernanceBlock ;

GovernanceBlock = "governance" "for" String "{" { GovernanceEntry } "}" ;
GovernanceEntry = GovernedThreatBlock | ActionBlock ;

GovernedThreatBlock = [ "stale" ] "threat" String "on" SourceKind String
                      "{" { GovernedThreatEntry } "}" ;
GovernedThreatEntry = AcceptedBlock | WorkBlock ;

AcceptedBlock = [ "stale" ] "accepted" String "{" { AcceptedAttr } "}" ;
AcceptedAttr  = "owner"       "=" String
              | "accepted_on" "=" String
              | "review_by"   "=" String
              | "rationale"   "=" String
              | "sources"     "=" StringList ;

WorkBlock   = [ "stale" ] "work" String "{" { WorkAttr } "}" ;
ActionBlock = [ "stale" ] "action" String "{" { WorkAttr } "}" ;
WorkAttr    = "owner"      "=" String
            | "effort"     "=" String
            | "due_by"     "=" String
            | "status"     "=" String
            | "acceptance" "=" String
            | "note"       "=" String
            | "sources"    "=" StringList ;
```

A file holds exactly one `governance for` block. Text after its closing brace
is not read. A file that does not start with `governance` is the error
`expected governance, not "<word>"`, and a block missing `for` is the error
`expected for, not "<word>"`.

### 8.2 The blocks and the attributes

| Block | Label | Keyed by |
| --- | --- | --- |
| `threat` | the threat id, then what raised it | `<threat id>@<kind>:<source id>`, the key section 5.10 gives |
| `accepted` | the control's description | the threat key and the description |
| `work` | the recommendation's text | the threat key and the text |
| `action` | the action's label | the label, which the `.arch` file declares |

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `owner` | string | any | empty |
| `accepted_on` | string | a date, `YYYY-MM-DD` | none |
| `review_by` | string | a date, `YYYY-MM-DD` | none |
| `due_by` | string | a date, `YYYY-MM-DD` | none |
| `rationale` | string | any | empty |
| `acceptance` | string | any | empty |
| `note` | string | any | empty |
| `effort` | string | `small`, `medium`, `large` | none |
| `status` | string | `planned`, `in_progress`, `done`, `dropped` | `planned` |
| `sources` | list of strings | any | empty |

```hcl
governance for "Payments" {
  threat "credential-theft" on component "api" {
    accepted "Enforce MFA on all administrative access" {
      owner       = "Head of Platform"
      accepted_on = "2026-09-01"
      review_by   = "2027-03-01"
      rationale   = "The MFA rollout waits on the SSO migration."
      sources     = ["https://example.com/risk-register/RSK-412"]
    }

    work "Protect the managed preferences plist" {
      owner      = "Platform team"
      effort     = "medium"
      due_by     = "2026-11-30"
      acceptance = "The plist is writable only by the MDM daemon."
    }
  }

  action "reenable-devtool-rules" {
    owner      = "Endpoint team"
    effort     = "small"
    due_by     = "2026-10-15"
    status     = "in_progress"
    acceptance = "The read rules are on, and the audit log shows no bypass."
  }
}
```

A date is a calendar date written `YYYY-MM-DD`. Nothing in this file moves a
score: an accepted risk still counts at its full score.

### 8.3 `stale`

`stale` marks a stanza whose control is no longer accepted, whose
recommendation or action is gone, or whose threat the architecture no longer
raises. The rule is the rule section 5.4 gives: nothing deletes a stale block,
the application applies nothing it holds, and a person deletes it.

A stale stanza fails no check. The `.controls` file already fails the build for
a stale answer, and failing twice for one cause tells a person nothing new.

### 8.4 What the compile writes

| Case | Result |
| --- | --- |
| a control is `accepted` and the file governs it | the stanza is kept whole |
| a control is `accepted` and the file does not govern it | a stanza appears with every field empty |
| a recommendation exists and the file does not govern it | a `work` stanza appears with every field empty |
| an `.arch` action exists and the file does not govern it | an `action` stanza appears with every field empty |
| a control is no longer `accepted` | the stanza is marked `stale` |
| a recommendation or an action is gone | the stanza is marked `stale` |
| a threat is no longer raised | its whole block is marked `stale` |

Two compiles of one project write the same bytes.

### 8.5 What the check fails

`threatmodeller check` exits 1 for each of these, which is the code an
unanswered threat already exits:

| Failure | Printed |
| --- | --- |
| a control is `accepted` and no stanza governs it | `<key> is accepted and has no governance entry; run threatmodeller compile` |
| an `accepted` stanza has no `owner` | `<key> is accepted by nobody; the accepted risk needs an owner` |
| an `accepted` stanza has no `review_by` | `<key> is accepted with no review date` |
| an `accepted` stanza's `review_by` has passed | `<key> was accepted for review by <date>, which has passed` |

A `work` stanza and an `action` stanza fail nothing. Planned work with no owner
is a gap in a plan; an accepted risk with no owner is a decision nobody made.
The report prints both.

### 8.6 What the parser refuses

| Check | Message |
| --- | --- |
| a date that is not `YYYY-MM-DD` | `<attribute> is "<raw>"; a date is written YYYY-MM-DD` |
| a date that is not a calendar date | `<attribute> is "<raw>", which is not a date` |
| an `effort` outside the three | `effort is "<raw>"; this application holds "small", "medium", "large"` |
| a `status` outside the four | `status is "<raw>"; this application holds "planned", "in_progress", "done", "dropped"` |
| a threat block with no `on` | `a threat says what raised it: on component, on zone or on flow` |
| two blocks with one key | `<key> is governed twice` |

## 9. The policy language

One `threatmodel/policy.hcl` for the whole project, beside the systems it
governs. Every system is checked against it, and a project with no such file
checks exactly as it does without one.

The rules are a fixed set of names, not an expression language: a rule a team
cannot mistype, that the report can explain, and that survives a change to the
value tree.

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

### 9.1 Grammar

```
PolicyFile  = PolicyBlock ;

PolicyBlock = "policy" "{" { PolicyEntry } "}" ;
PolicyEntry = "max_open_at_level"                         "=" String
            | "accepted_requires_owner"                   "=" Boolean
            | "accepted_requires_review_by"               "=" Boolean
            | "implemented_requires_evidence_above"       "=" String
            | "restricted_data_stays_out_of_public_zones" "=" Boolean
            | "assumptions_require_owner"                 "=" Boolean
            | "system_requires_owner"                     "=" Boolean
            | "template"                                  "=" String ;
```

A file holds exactly one `policy` block. Text after its closing brace is not
read. A file that does not start with `policy` is the error `expected policy,
not "<word>"`.

### 9.2 The rules

| Rule | Type | What it asks |
| --- | --- | --- |
| `max_open_at_level` | a risk level | no threat at that level or worse is unanswered |
| `accepted_requires_owner` | boolean | every accepted risk names an owner |
| `accepted_requires_review_by` | boolean | every accepted risk names a review date |
| `implemented_requires_evidence_above` | a risk level | every implemented control on a threat at that level or worse, before its controls, states an evidence tier |
| `restricted_data_stays_out_of_public_zones` | boolean | no component holding restricted data sits in a public zone, or outside every zone |
| `assumptions_require_owner` | boolean | every assumption names an owner |
| `system_requires_owner` | boolean | the `.arch` file states `owner` |
| `template` | string | the report template this project renders through, as a path from the project root. It asks nothing and breaches nothing |

A rule the file does not state is not in force, and `false` is the same as not
stating it, so a team turns one off without deleting the line.

`template` is not a rule and breaches nothing. It names the report template
this project renders through, as a path from the project root:

```hcl
policy {
  template = "docs/board-report.md"
}
```

`threatmodeller report --template <file>` states one for a single run and wins
over the file. The template language is stated in
`docs/superpowers/specs/2026-09-15-report-template-design.md`.

A risk level is `low`, `medium`, `high` or `critical`. A value outside the four
is the error `<rule> is "<raw>"; this application holds "low", "medium",
"high", "critical"`. A name outside the set is the error `a policy holds
max_open_at_level, accepted_requires_owner, accepted_requires_review_by,
implemented_requires_evidence_above,
restricted_data_stays_out_of_public_zones, assumptions_require_owner,
system_requires_owner, template, not "<word>"`.

### 9.3 What a breach prints

`threatmodeller check` prints one line per breach, naming the rule first,
because a person reading a build log is looking for which rule they broke:

```
threatmodel/payments.governance: system_requires_owner: this system states no owner
```

Any breach exits 1, which is the code every other `check` failure exits. Two
rules restate a check that always runs — `accepted_requires_owner` and
`accepted_requires_review_by` — and a breach either check finds is printed
once.

The report writes `## Policy` after the executive summary, listing every rule
in force and whether this system keeps it, so a reader sees what the team
enforces and not only what it failed.

## 10. Diagnostics

### 10.1 The shape

A diagnostic carries a severity, a line, a column and a message, and prints as:

```
threatmodel/payments.arch:12:5: error: no technology "aws-ec3" in catalogue v1.0.1
```

An editor and a build log both read that shape.

### 10.2 The severities

| Severity | Effect |
| --- | --- |
| `error` | the read produces **no** source, so nothing is imported |
| `warning` | the read produces a source, and the application shows the warning |

One error anywhere in a file stops the whole file. Warnings alone do not.

### 10.3 Recovery

Neither the lexer nor the parser stops at the first fault, so a file with four
faults reports four rather than one.

| Where the fault is | What the parser does next |
| --- | --- |
| an unknown entry in a `system` or `controls for` body | records one diagnostic, then skips forward to the end of the current block |
| an unknown attribute inside a block | records one diagnostic, then skips that attribute, including a whole list or a whole nested block |
| a missing required attribute | records one diagnostic and drops the block |
| an unknown character | records one diagnostic and skips that one character |

### 10.4 What each block holds

An entry that is not one of a block's own attributes or nested blocks is the
message below. The parser then does what section 10.3 states for "an unknown
entry" or "an unknown attribute".

| Language | Block | Message |
| --- | --- | --- |
| architecture | `system` | `a system holds catalogue, technology, zone, component, flow, mitigates, risk_tolerance, requires_evidence_above, assumption, faces and threat_actor, not "<word>"` |
| architecture | `assumption` | `an assumption holds text and owner, not "<word>"` |
| architecture | `technology` | `a technology holds name, category, description, threats and encrypts, not "<word>"` |
| architecture | `zone` | `a zone holds kind, network, name, reduces_risk, reduces_risk_by, component, boundary and description, not "<word>"` |
| architecture | `component` | `a component holds technology, name, data, holds, provided_by, source, threats, runs_as, shape and asset, not "<word>"` |
| architecture | `third_party` | `a third_party holds name, description, kind, paying_customer, uptime, uptime_notes, owner and link, not "<word>"` |
| architecture | `third_party` | `the third party "<id>" has no name` |
| architecture | `third_party` | `the third party "<id>" states no uptime; state "none", "degraded", "hard" or "operational"` |
| architecture | `component` | `the component "<id>" is provided by "<id>", which no third_party declares` |
| architecture | `third_party` | `this system cannot run without "<name>" and no assumption names it` |
| architecture | `diagram` | `a diagram holds kind and text, not "<word>"` |
| architecture | `diagram` | `the diagram "<label>" has no text` |
| architecture | heredoc | `a heredoc starts "<<" and a tag, as in "<<EOT"` |
| architecture | heredoc | `this heredoc has no closing "<tag>" line` |
| architecture | `asset` | `an asset holds data, not "<word>"` |
| architecture | `asset` | `an asset holds name, classification, description and owner, not "<word>"` |
| architecture | `asset` | `the asset "<id>" has no name` |
| architecture | `component` | `the component "<id>" holds "<asset id>", which no asset declares` |
| architecture | `flow` | `the flow "<id>" carries "<asset id>", which no asset declares` |
| architecture | `flow` | `the flow "<id>" carries "<asset id>", which the component "<id>" does not hold` |
| architecture | `component` | `the component "<id>" states data "<word>" and holds "<asset id>", which is "<word>"` |
| architecture | `flow` | `a flow holds kind and description, not "<word>"` |
| architecture | `mitigates` | `a mitigates edge holds threats, reduces_risk_by, status and recommendation, not "<word>"` |
| architecture | `recommendation` (on a `mitigates` edge) | `a recommendation holds text, note, blocked_by and sources, not "<word>"` |
| controls | `controls for` | `a controls file holds catalogue, tolerance, threat, tree, stale threat and stale tree, not "<word>"` |
| controls | `threat` | `a threat holds severity, score, impacts, likelihood, severity_override, control, compensating and recommendation, not "<word>"` |
| controls | `threat` | `impacts holds "<word>"; this application holds confidentiality, integrity and availability` |
| controls | `likelihood` | `a likelihood holds tier, prior, rationale and sources, not "<word>"` |
| controls | `severity_override` | `a severity_override holds rationale and sources, not "<word>"` |
| controls | `control` | `a control holds status, note, evidence, reference and verified_on, not "<word>"` |
| controls | `compensating` | `a compensating control holds reduces_risk_by, rationale, sources, evidence, reference and verified_on, not "<word>"` |
| controls | `recommendation` | `a recommendation holds note and sources, not "<word>"` |
| controls | `tree` | `a tree holds goal, chain, raises_risk_by, score, score_before and step, not "<word>"` |
| controls | `step` (in a `tree`) | `a step holds state and by, not "<word>"` |
| attack tree | `tree` | `a tree holds name, description, raises_risk_by, goal, all_of, any_of and step, not "<word>"` |
| policy | `policy` | `a policy holds max_open_at_level, accepted_requires_owner, accepted_requires_review_by, implemented_requires_evidence_above, restricted_data_stays_out_of_public_zones, assumptions_require_owner, system_requires_owner, not "<word>"` |
| governance | `governance for` | `a governance file holds threat, action, stale threat and stale action, not "<word>"` |
| governance | `threat` | `a governed threat holds accepted, work, stale accepted and stale work, not "<word>"` |
| governance | `accepted` | `an accepted risk holds owner, accepted_on, review_by, rationale and sources, not "<word>"` |
| governance | `work` and `action` | `planned work holds owner, effort, due_by, status, acceptance, note and sources, not "<word>"` |
| library | `library` | `a library holds name, catalogue, technology, threat, mitigation and threat_actor, not "<word>"` |
| library | `technology` | `a technology holds name, category, description, threats and encrypts, not "<word>"` |
| library | `threat` | `a threat holds name, description, severity, stride, impacts, connection, zone, zone_context, mitre, control, applies_to, boundary, runs_as, pathway and likelihood, not "<word>"` |
| library | `threat` | `impacts holds "<word>"; this application holds confidentiality, integrity and availability` |
| library | `mitre` | `a mitre technique holds name and tactic, not "<word>"` |
| library | `mitigation` | `a mitigation holds name, description, mitigates, provided_by, reduces_risk_by and mode, not "<word>"` |

## 11. Canonical form

The writer emits one shape, so a rewrite of an unchanged source produces no
diff. `threatmodeller format` rewrites every `.arch` file in this shape.

Both writers share these rules:

- two spaces of indentation for each level
- the equals signs of one run of attributes line up, so a diff of one changed
  value is one changed line
- a blank line between blocks, and none before the closing brace
- one newline at the end of the file
- a string is written with `"` as `\"`, `\` as `\\`, a newline as `\n` and a tab
  as `\t`
- an attribute holding its default value is not written
- comments are not written

The architecture writer writes, in this order: `risk_tolerance`, then every
`assumption` block, then `catalogue`, then `faces`, then the `threat_actor`
blocks, then the technologies, then the zones
with their components nested in declaration order, then the top-level
components, then the flows, then the `mitigates` edges. Inside a block the
attribute order is fixed, and it is the order of the tables in section 4.

The controls writer writes the live answers before the stale ones. Inside each
group it writes the components, then the flows, then the zones; inside each, by
source identifier; inside each, by threat identifier. Inside a threat block it
writes `severity` and `score`, then the `likelihood` block, then the controls
sorted by description, then the `severity_override` block, then the
compensating controls, then the recommendations.

## 12. A worked example

`threatmodel/payments.arch`:

```hcl
system "Payments" {
  catalogue = "v1.0.1"

  technology "our-ledger" {
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
    }
  }

  component "attacker" {
    technology = "actor-attacker"
    data       = "public"
  }

  flow attacker -> api
  flow api -> ledger
}
```

`threatmodeller compile` then writes `threatmodel/payments.controls`, and a
person fills the answers in:

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

    control "Rotate access keys every 90 days" {
      status = "not_implemented"
    }

    compensating "Break-glass account watched by the SIEM" {
      reduces_risk_by = 40
      rationale       = "Standing keys are gone; the one account left alerts on use."
    }
  }

  threat "t-mitm" on flow "attacker->api" { }

  threat "t-lateral-movement" on zone "app" { }
}
```

`threatmodeller check` exits 1 while `t-mitm` and `t-lateral-movement` hold no
answer. `threatmodeller report` writes `threatmodel/payments.md`.

## 13. The grammar in full

```
(* common *)

Identifier = ( Letter | "_" ) { Letter | Digit | "_" | "-" } ;
String     = '"' { Character | "\" AnyCharacter } '"' ;
Number     = [ "-" ] Digit { Digit } ;
Boolean    = "true" | "false" ;
StringList = "[" [ String { [ "," ] String } ] "]" ;
Comment    = ( "#" | "//" ) { AnyCharacter } LineEnd ;

(* the architecture language *)

ArchitectureFile = SystemBlock ;

SystemBlock  = "system" String "{" { SystemEntry } "}" ;
SystemEntry  = CatalogueAttr
             | RiskToleranceAttr
             | RequiresEvidenceAboveAttr
             | FacesAttr
             | TechnologyBlock
             | ZoneBlock
             | ComponentBlock
             | FlowStatement
             | MitigatesBlock
             | AssumptionBlock
             | UseCaseBlock
             | ExclusionBlock
             | SystemAssetBlock
             | ThirdPartyBlock
             | DiagramBlock
             | ThreatActorBlock ;

UseCaseBlock   = "use_case" String "{" "text" "=" String "}" ;
ExclusionBlock = "exclusion" String "{" "text" "=" String "rationale" "=" String "}" ;

CatalogueAttr     = "catalogue" "=" String ;
RiskToleranceAttr = "risk_tolerance" "=" String ;
RequiresEvidenceAboveAttr = "requires_evidence_above" "=" String ;
FacesAttr         = "faces" "=" StringList ;

ThreatActorBlock = "threat_actor" String "{" { ThreatActorAttr } "}" ;
ThreatActorAttr  = "name"                    "=" String
                 | "description"             "=" String
                 | "aliases"                 "=" StringList
                 | "capability"              "=" String
                 | "intent"                  "=" String
                 | "performs"                "=" StringList
                 | "techniques"              "=" StringList
                 | "performs_catalogue_tier" "=" String ;

AssumptionBlock = "assumption" String "{" { AssumptionAttr } "}" ;
AssumptionAttr  = "text"  "=" String
                | "owner" "=" String ;

TechnologyBlock = "technology" String "{" { TechnologyAttr } "}" ;
TechnologyAttr  = "name"        "=" String
                | "category"    "=" String
                | "description" "=" String
                | "threats"     "=" StringList
                | "encrypts"    "=" Boolean ;

ZoneBlock = "zone" String "{" { ZoneEntry } "}" ;
ZoneEntry = "kind"            "=" String
          | "network"         "=" String
          | "boundary"        "=" String
          | "name"            "=" String
          | "description"     "=" String
          | "reduces_risk"    "=" Boolean
          | "reduces_risk_by" "=" Number
          | ComponentBlock ;

ComponentBlock = "component" String "{" { ComponentEntry } "}" ;
ComponentEntry = "technology"  "=" String
               | "name"        "=" String
               | "data"        "=" String
               | "holds"       "=" StringList
               | "provided_by" "=" String
               | "source"      "=" String
               | "runs_as"     "=" String
               | "shape"       "=" String
               | "threats"     "=" Boolean
               | AssetBlock ;

AssetBlock = "asset" String "{" [ "data" "=" String ] "}" ;

SystemAssetBlock = "asset" String "{" { SystemAssetEntry } "}" ;

DiagramBlock = "diagram" String "{" { DiagramEntry } "}" ;
DiagramEntry = "kind" "=" String
             | "text" "=" ( String | Heredoc ) ;

Heredoc = "<<" Identifier Newline { AnyLine } Identifier ;

ThirdPartyBlock = "third_party" String "{" { ThirdPartyEntry } "}" ;
ThirdPartyEntry = "name"            "=" String
                | "description"     "=" String
                | "kind"            "=" String
                | "paying_customer" "=" Boolean
                | "uptime"          "=" String
                | "uptime_notes"    "=" String
                | "owner"           "=" String
                | "link"            "=" String ;
SystemAssetEntry = "name"           "=" String
                 | "classification" "=" String
                 | "description"    "=" String
                 | "owner"          "=" String ;

FlowStatement = "flow" Identifier "->" Identifier [ "{" { FlowEntry } "}" ] ;
FlowEntry     = "kind"        "=" String
              | "description" "=" String
              | "carries"     "=" StringList ;

MitigatesBlock = "mitigates" Identifier "->" Identifier "{" { MitigatesEntry } "}" ;
MitigatesEntry = "threats"         "=" StringList
               | "reduces_risk_by" "=" Number
               | "status"          "=" String
               | ActionBlock ;

ActionBlock = "recommendation" String "{" { ActionAttr } "}" ;
ActionAttr  = "text"       "=" String
            | "note"       "=" String
            | "blocked_by" "=" String
            | "sources"    "=" StringList ;

(* the controls language *)

ControlsFile = ControlsBlock ;

ControlsBlock = "controls" "for" String "{" { ControlsEntry } "}" ;
ControlsEntry = CatalogueAttr | ToleranceAttr | ThreatBlock | TreeAnswerBlock ;

ToleranceAttr = "tolerance" "=" String ;

TreeAnswerBlock = [ "stale" ] "tree" String "{" { TreeAnswerEntry } "}" ;
TreeAnswerEntry = "goal"           "=" String
                | "chain"          "=" Number
                | "raises_risk_by" "=" Number
                | "score"          "=" Number
                | "score_before"   "=" Number
                | StepAnswerBlock ;

StepAnswerBlock = "step" String "{" { StepAnswerAttr } "}" ;
StepAnswerAttr  = "state" "=" String
                | "by"    "=" String ;

ThreatBlock = [ "stale" ] "threat" String "on" SourceKind String
              "{" { ThreatEntry } "}" ;
SourceKind  = "component" | "zone" | "flow" ;
ThreatEntry = "severity" "=" String
            | "score"    "=" Number
            | "impacts"  "=" StringList
            | LikelihoodBlock
            | SeverityOverrideBlock
            | ControlBlock
            | CompensatingBlock
            | RecommendationBlock ;

LikelihoodBlock = "likelihood" String "{" { LikelihoodAttr } "}" ;
LikelihoodAttr  = "tier"      "=" String
                | "prior"     "=" Number
                | "rationale" "=" String
                | "sources"   "=" StringList ;

SeverityOverrideBlock = "severity_override" String "{" { SeverityOverrideAttr } "}" ;
SeverityOverrideAttr  = "rationale" "=" String
                      | "sources"   "=" StringList ;

ControlBlock = "control" String "{" { ControlAttr } "}" ;
ControlAttr  = "status"      "=" String
             | "note"        "=" String
             | "evidence"    "=" String
             | "reference"   "=" String
             | "verified_on" "=" String ;

CompensatingBlock = "compensating" String "{" { CompensatingAttr } "}" ;
CompensatingAttr  = "reduces_risk_by" "=" Number
                  | "rationale"       "=" String
                  | "sources"         "=" StringList
                  | "evidence"        "=" String
                  | "reference"       "=" String
                  | "verified_on"     "=" String ;

RecommendationBlock = "recommendation" String "{" { RecommendationAttr } "}" ;
RecommendationAttr  = "note"    "=" String
                    | "sources" "=" StringList ;

(* the library language *)

LibraryFile  = LibraryBlock ;
LibraryBlock = "library" String "{" { LibraryEntry } "}" ;
LibraryEntry = "name"      "=" String
             | "catalogue" "=" String
             | TechnologyBlock
             | ThreatBlock
             | MitigationBlock
             | ThreatActorBlock ;

ThreatBlock = "threat" String "{" { ThreatEntry } "}" ;
ThreatEntry = "name"         "=" String
            | "description"  "=" String
            | "severity"     "=" String
            | "stride"       "=" StringList
            | "impacts"      "=" StringList
            | "connection"   "=" Boolean
            | "zone"         "=" Boolean
            | "zone_context" "=" String
            | "applies_to"   "=" StringList
            | "boundary"     "=" String
            | "runs_as"      "=" StringList
            | "pathway"      "=" Boolean
            | "likelihood"   "=" ( String | Number )
            | MitreBlock
            | ControlStatement ;

MitreBlock = "mitre" String "{" { MitreAttr } "}" ;
MitreAttr  = "name"   "=" String
           | "tactic" "=" String ;

ControlStatement = "control" String ;

MitigationBlock = "mitigation" String "{" { MitigationAttr } "}" ;
MitigationAttr  = "name"            "=" String
                | "description"     "=" String
                | "mitigates"       "=" StringList
                | "provided_by"     "=" StringList
                | "reduces_risk_by" "=" Number
                | "mode"            "=" String ;

(* the attack tree language *)

AttackTreeFile = AttackTreesBlock ;

AttackTreesBlock = "attack_trees" "for" String "{" { AttackTreesEntry } "}" ;
AttackTreesEntry = CatalogueAttr | TreeBlock ;

TreeBlock = "tree" String "{" { TreeEntry } "}" ;
TreeEntry = "name"           "=" String
          | "description"    "=" String
          | "raises_risk_by" "=" Number
          | GoalStatement
          | NodeBlock
          | StepBlock ;

GoalStatement = "goal" String "on" SourceKind String ;

NodeBlock = ( "all_of" | "any_of" ) "{" { NodeEntry } "}" ;
NodeEntry = StepBlock | NodeBlock ;

StepBlock = "step" String "on" SourceKind String [ "{" { StepEntry } "}" ] ;
StepEntry = "note" "=" String ;

(* the governance language *)

GovernanceFile = GovernanceBlock ;

GovernanceBlock = "governance" "for" String "{" { GovernanceEntry } "}" ;
GovernanceEntry = GovernedThreatBlock | ActionBlock ;

GovernedThreatBlock = [ "stale" ] "threat" String "on" SourceKind String
                      "{" { GovernedThreatEntry } "}" ;
GovernedThreatEntry = AcceptedBlock | WorkBlock ;

AcceptedBlock = [ "stale" ] "accepted" String "{" { AcceptedAttr } "}" ;
AcceptedAttr  = "owner"       "=" String
              | "accepted_on" "=" String
              | "review_by"   "=" String
              | "rationale"   "=" String
              | "sources"     "=" StringList ;

WorkBlock   = [ "stale" ] "work" String "{" { WorkAttr } "}" ;
ActionBlock = [ "stale" ] "action" String "{" { WorkAttr } "}" ;
WorkAttr    = "owner"      "=" String
            | "effort"     "=" String
            | "due_by"     "=" String
            | "status"     "=" String
            | "acceptance" "=" String
            | "note"       "=" String
            | "sources"    "=" StringList ;

(* the policy language *)

PolicyFile  = PolicyBlock ;

PolicyBlock = "policy" "{" { PolicyEntry } "}" ;
PolicyEntry = "max_open_at_level"                         "=" String
            | "accepted_requires_owner"                   "=" Boolean
            | "accepted_requires_review_by"               "=" Boolean
            | "implemented_requires_evidence_above"       "=" String
            | "restricted_data_stays_out_of_public_zones" "=" Boolean
            | "assumptions_require_owner"                 "=" Boolean
            | "system_requires_owner"                     "=" Boolean ;
```

## 14. Where the code is

| File | What it holds |
| --- | --- |
| [`Lexer.swift`](../ThreatModelKit/Sources/ArchitectureDSL/Lexer.swift) | section 2 |
| [`Token.swift`](../ThreatModelKit/Sources/ArchitectureDSL/Token.swift) | the token kinds |
| [`ArchitectureParser.swift`](../ThreatModelKit/Sources/ArchitectureDSL/ArchitectureParser.swift) | section 4 |
| [`ArchitectureWriter.swift`](../ThreatModelKit/Sources/ArchitectureDSL/ArchitectureWriter.swift) | the canonical form of a `.arch` file |
| [`ControlsParser.swift`](../ThreatModelKit/Sources/ArchitectureDSL/ControlsParser.swift) | section 5 |
| [`ControlsWriter.swift`](../ThreatModelKit/Sources/ArchitectureDSL/ControlsWriter.swift) | the canonical form of a `.controls` file |
| [`LibraryParser.swift`](../ThreatModelKit/Sources/ArchitectureDSL/LibraryParser.swift) | section 6 |
| [`LibraryWriter.swift`](../ThreatModelKit/Sources/ArchitectureDSL/LibraryWriter.swift) | the canonical form of a `.lib` file |
| [`AttackTreeParser.swift`](../ThreatModelKit/Sources/ArchitectureDSL/AttackTreeParser.swift) | section 7 |
| [`AttackTreeWriter.swift`](../ThreatModelKit/Sources/ArchitectureDSL/AttackTreeWriter.swift) | the canonical form of a `.attacktree` file |
| [`GovernanceParser.swift`](../ThreatModelKit/Sources/ArchitectureDSL/GovernanceParser.swift) | section 8 |
| [`GovernanceWriter.swift`](../ThreatModelKit/Sources/ArchitectureDSL/GovernanceWriter.swift) | the canonical form of a `.governance` file |
| [`PolicyParser.swift`](../ThreatModelKit/Sources/ArchitectureDSL/PolicyParser.swift) | section 9 |
| [`PolicyRules.swift`](../ThreatModelKit/Sources/ThreatModelKit/architecture/domain/PolicyRules.swift) | what each rule asks, read by the check and by the report |
| [`Library.swift`](../ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Library.swift) | the prefix rule of section 6.4, and the taxonomy check |
| [`MergedCatalogue.swift`](../ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/MergedCatalogue.swift) | how a library and the vendored catalogue read as one |
| [`Diagnostic.swift`](../ThreatModelKit/Sources/ThreatModelKit/architecture/domain/Diagnostic.swift) | section 10 |
| [`ControlsSource.swift`](../ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ControlsSource.swift) | the value tree, and the threat key of section 5.10 |
| [`ProjectConvention.swift`](../ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ProjectConvention.swift) | how a `.arch` file pairs with its `.controls` and its `.md` |

Related documents:

- [The README](../README.md) — the project, the file layout and the executable.
- [The code-first design](superpowers/specs/2026-09-08-code-first-dsl-design.md) —
  why the languages are shaped this way.
- [Running the tests](TESTING.md)
