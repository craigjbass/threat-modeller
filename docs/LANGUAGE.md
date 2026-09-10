# The language of Craig's Threat Modeller

A reference for the three source languages this application reads: the
architecture language, written in a `.arch` file; the controls language, written
in a `.controls` file; and the library language, written in a `.lib` file.

The three languages share one lexical structure and one block syntax. They
differ only in their keywords and in what a block means. Sections 2 and 3 hold
what is common. Section 4 holds the architecture language, section 5 the
controls language, and section 6 the library language.

## Contents

1. [Notation](#1-notation)
2. [Lexical structure](#2-lexical-structure)
3. [Block syntax](#3-block-syntax)
4. [The architecture language](#4-the-architecture-language)
5. [The controls language](#5-the-controls-language)
6. [The library language](#6-the-library-language)
7. [Diagnostics](#7-diagnostics)
8. [Canonical form](#8-canonical-form)
9. [A worked example](#9-a-worked-example)
10. [The grammar in full](#10-the-grammar-in-full)
11. [Where the code is](#11-where-the-code-is)

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
`asset`, `flow`, `mitigates`, `status`.

The controls language reads these keywords: `controls`, `for`, `catalogue`,
`tolerance`, `stale`, `threat`, `on`, `severity`, `score`, `likelihood`,
`tier`, `prior`, `rationale`, `sources`, `severity_override`, `control`,
`status`, `note`, `compensating`, `reduces_risk_by`, `recommendation`.

The library language reads these keywords: `library`, `name`, `catalogue`,
`technology`, `category`, `description`, `threats`, `encrypts`, `threat`,
`severity`, `stride`, `connection`, `zone`, `zone_context`, `applies_to`,
`boundary`, `runs_as`, `pathway`, `likelihood`, `mitre`, `tactic`, `control`,
`mitigation`, `mitigates`, `provided_by`, `reduces_risk_by`.

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

## 4. The architecture language

A `.arch` file states the architecture: the technologies, the zones, the
components and the flows between the components. A person writes it.

### 4.1 Grammar

```
ArchitectureFile = SystemBlock ;

SystemBlock  = "system" String "{" { SystemEntry } "}" ;
SystemEntry  = CatalogueAttr
             | RiskToleranceAttr
             | TechnologyBlock
             | ZoneBlock
             | ComponentBlock
             | FlowStatement
             | MitigatesBlock
             | AssumptionBlock ;

CatalogueAttr     = "catalogue" "=" String ;
RiskToleranceAttr = "risk_tolerance" "=" String ;

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
ComponentEntry = "technology" "=" String
               | "name"       "=" String
               | "data"       "=" String
               | "runs_as"    "=" String
               | "threats"    "=" Boolean
               | AssetBlock ;

AssetBlock = "asset" String "{" [ "data" "=" String ] "}" ;

FlowStatement = "flow" Identifier "->" Identifier [ "{" { FlowEntry } "}" ] ;
FlowEntry     = "kind"        "=" String
              | "description" "=" String ;

MitigatesBlock = "mitigates" Identifier "->" Identifier "{" { MitigatesEntry } "}" ;
MitigatesEntry = "threats"         "=" StringList
               | "reduces_risk_by" "=" Number
               | "status"          "=" String ;
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
  threats    = true
}
```

The label is the component's identifier.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `technology` | string | a technology identifier | **required** |
| `name` | string | any | the technology's name |
| `data` | string | `public`, `internal`, `confidential`, `restricted` | `internal` |
| `runs_as` | string | `user`, `admin`, `root`, `system`, `kernel` | `user` |
| `threats` | boolean | `true`, `false` | `true` |

`threats = false` stops the component raising threats at all.

A block with no `technology` is the error
`the component "<id>" names no technology`, and the block is dropped.

**Placement.** A `component` block inside a `zone` block sits in that zone. A
`component` block at the top level of the `system` block sits outside every
zone.

**`asset`.** A component may hold one or more `asset` blocks. An asset is a
thing of value the component holds, separate from the component itself.

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

The second warning is raised by `ImportArchitecture`, not by the parser, because
only the import knows the catalogue.

## 5. The controls language

A `.controls` file states the answer for every threat the architecture raises.
The compiler writes the file, and a person fills in the answers and commits
them.

### 5.1 Grammar

```
ControlsFile = ControlsBlock ;

ControlsBlock = "controls" "for" String "{" { ControlsEntry } "}" ;
ControlsEntry = CatalogueAttr | ToleranceAttr | ThreatBlock ;

CatalogueAttr = "catalogue" "=" String ;
ToleranceAttr = "tolerance" "=" String ;

ThreatBlock = [ "stale" ] "threat" String "on" SourceKind String "{" { ThreatEntry } "}" ;
SourceKind  = "component" | "zone" | "flow" ;
ThreatEntry = "severity" "=" String
            | "score"    "=" Number
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
ControlAttr  = "status" "=" String
             | "note"   "=" String ;

CompensatingBlock = "compensating" String "{" { CompensatingAttr } "}" ;
CompensatingAttr  = "reduces_risk_by" "=" Number
                  | "rationale"       "=" String
                  | "sources"         "=" StringList ;

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

WARNING: `severity` and `score` are written for the reader. The application
recomputes both from the catalogue and the answers, so an edit to either changes
nothing.

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

### 5.5 `control`

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

### 5.6 `compensating`

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

### 5.7 `likelihood`

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

### 5.8 `severity_override`

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

### 5.9 Threat keys

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

### 5.10 What the application does with the answers

`ApplyControlAnswers` reads the file against the threats the architecture
raises. It skips every `stale` block, and it warns rather than fails when a file
says something the model does not:

| Case | Warning |
| --- | --- |
| the model does not raise that threat on that source | `this model does not raise "<threat>" on <kind> "<id>", so its answers are not applied` |
| the threat no longer offers that control | `"<threat>" no longer offers the control "<description>", so its answer is not applied` |
| the `severity_override` names a severity the catalogue does not hold | `"<severity>" is not a severity this catalogue holds, so the severity_override on "<threat>" is not applied` |

### 5.11 The merge

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

### 6.2 Grammar

```
LibraryFile  = LibraryBlock ;
LibraryBlock = "library" String "{" { LibraryEntry } "}" ;
LibraryEntry = "name"      "=" String
             | "catalogue" "=" String
             | TechnologyBlock
             | ThreatBlock
             | MitigationBlock ;

ThreatBlock = "threat" String "{" { ThreatEntry } "}" ;
ThreatEntry = "name"         "=" String
            | "description"  "=" String
            | "severity"     "=" String
            | "stride"       "=" StringList
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
                | "reduces_risk_by" "=" Number ;
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
mitigation starts at; a project's settings may change it. A block with no
`name` is the error `the mitigation "<id>" has no name`. A block with no
`mitigates` is the error `the mitigation "<id>" names no threats`. A block
with no `provided_by` is the error `the mitigation "<id>" names no
technologies`.

A `control` is a statement with a label and no body, because a library states
what a control is and a `.controls` file states its status. Its key is minted
from its description, which is the rule the vendored catalogue follows.

### 6.4 Identity

The label of the `library` block is a provider id. Every technology id and every
threat id the file declares is minted `<label>-<id>`, so two teams can both
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

### 6.5 What the parser refuses

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

## 7. Diagnostics

### 7.1 The shape

A diagnostic carries a severity, a line, a column and a message, and prints as:

```
threatmodel/payments.arch:12:5: error: no technology "aws-ec3" in catalogue v1.0.1
```

An editor and a build log both read that shape.

### 7.2 The severities

| Severity | Effect |
| --- | --- |
| `error` | the read produces **no** source, so nothing is imported |
| `warning` | the read produces a source, and the application shows the warning |

One error anywhere in a file stops the whole file. Warnings alone do not.

### 7.3 Recovery

Neither the lexer nor the parser stops at the first fault, so a file with four
faults reports four rather than one.

| Where the fault is | What the parser does next |
| --- | --- |
| an unknown entry in a `system` or `controls for` body | records one diagnostic, then skips forward to the end of the current block |
| an unknown attribute inside a block | records one diagnostic, then skips that attribute, including a whole list or a whole nested block |
| a missing required attribute | records one diagnostic and drops the block |
| an unknown character | records one diagnostic and skips that one character |

### 7.4 What each block holds

An entry that is not one of a block's own attributes or nested blocks is the
message below. The parser then does what section 7.3 states for "an unknown
entry" or "an unknown attribute".

| Language | Block | Message |
| --- | --- | --- |
| architecture | `system` | `a system holds catalogue, technology, zone, component, flow, mitigates, risk_tolerance and assumption, not "<word>"` |
| architecture | `assumption` | `an assumption holds text and owner, not "<word>"` |
| architecture | `technology` | `a technology holds name, category, description, threats and encrypts, not "<word>"` |
| architecture | `zone` | `a zone holds kind, network, name, reduces_risk, reduces_risk_by, component, boundary and description, not "<word>"` |
| architecture | `component` | `a component holds technology, name, data, threats, runs_as and asset, not "<word>"` |
| architecture | `asset` | `an asset holds data, not "<word>"` |
| architecture | `flow` | `a flow holds kind and description, not "<word>"` |
| architecture | `mitigates` | `a mitigates edge holds threats, reduces_risk_by and status, not "<word>"` |
| controls | `controls for` | `a controls file holds catalogue, tolerance, threat and stale threat, not "<word>"` |
| controls | `threat` | `a threat holds severity, score, likelihood, severity_override, control, compensating and recommendation, not "<word>"` |
| controls | `likelihood` | `a likelihood holds tier, prior, rationale and sources, not "<word>"` |
| controls | `severity_override` | `a severity_override holds rationale and sources, not "<word>"` |
| controls | `control` | `a control holds status and note, not "<word>"` |
| controls | `compensating` | `a compensating control holds reduces_risk_by, rationale and sources, not "<word>"` |
| controls | `recommendation` | `a recommendation holds note and sources, not "<word>"` |
| library | `library` | `a library holds name, catalogue, technology, threat and mitigation, not "<word>"` |
| library | `technology` | `a technology holds name, category, description, threats and encrypts, not "<word>"` |
| library | `threat` | `a threat holds name, description, severity, stride, connection, zone, zone_context, mitre, control, applies_to, boundary, runs_as, pathway and likelihood, not "<word>"` |
| library | `mitre` | `a mitre technique holds name and tactic, not "<word>"` |
| library | `mitigation` | `a mitigation holds name, description, mitigates, provided_by and reduces_risk_by, not "<word>"` |

## 8. Canonical form

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
`assumption` block, then `catalogue`, then the technologies, then the zones
with their components nested in declaration order, then the top-level
components, then the flows, then the `mitigates` edges. Inside a block the
attribute order is fixed, and it is the order of the tables in section 4.

The controls writer writes the live answers before the stale ones. Inside each
group it writes the components, then the flows, then the zones; inside each, by
source identifier; inside each, by threat identifier. Inside a threat block it
writes `severity` and `score`, then the `likelihood` block, then the controls
sorted by description, then the `severity_override` block, then the
compensating controls, then the recommendations.

## 9. A worked example

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

## 10. The grammar in full

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
             | TechnologyBlock
             | ZoneBlock
             | ComponentBlock
             | FlowStatement
             | MitigatesBlock
             | AssumptionBlock ;

CatalogueAttr     = "catalogue" "=" String ;
RiskToleranceAttr = "risk_tolerance" "=" String ;

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
ComponentEntry = "technology" "=" String
               | "name"       "=" String
               | "data"       "=" String
               | "runs_as"    "=" String
               | "threats"    "=" Boolean
               | AssetBlock ;

AssetBlock = "asset" String "{" [ "data" "=" String ] "}" ;

FlowStatement = "flow" Identifier "->" Identifier [ "{" { FlowEntry } "}" ] ;
FlowEntry     = "kind"        "=" String
              | "description" "=" String ;

MitigatesBlock = "mitigates" Identifier "->" Identifier "{" { MitigatesEntry } "}" ;
MitigatesEntry = "threats"         "=" StringList
               | "reduces_risk_by" "=" Number
               | "status"          "=" String ;

(* the controls language *)

ControlsFile = ControlsBlock ;

ControlsBlock = "controls" "for" String "{" { ControlsEntry } "}" ;
ControlsEntry = CatalogueAttr | ToleranceAttr | ThreatBlock ;

ToleranceAttr = "tolerance" "=" String ;

ThreatBlock = [ "stale" ] "threat" String "on" SourceKind String
              "{" { ThreatEntry } "}" ;
SourceKind  = "component" | "zone" | "flow" ;
ThreatEntry = "severity" "=" String
            | "score"    "=" Number
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
ControlAttr  = "status" "=" String
             | "note"   "=" String ;

CompensatingBlock = "compensating" String "{" { CompensatingAttr } "}" ;
CompensatingAttr  = "reduces_risk_by" "=" Number
                  | "rationale"       "=" String
                  | "sources"         "=" StringList ;

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
             | MitigationBlock ;

ThreatBlock = "threat" String "{" { ThreatEntry } "}" ;
ThreatEntry = "name"         "=" String
            | "description"  "=" String
            | "severity"     "=" String
            | "stride"       "=" StringList
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
                | "reduces_risk_by" "=" Number ;
```

## 11. Where the code is

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
| [`Library.swift`](../ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Library.swift) | the prefix rule of section 6.4, and the taxonomy check |
| [`MergedCatalogue.swift`](../ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/MergedCatalogue.swift) | how a library and the vendored catalogue read as one |
| [`Diagnostic.swift`](../ThreatModelKit/Sources/ThreatModelKit/architecture/domain/Diagnostic.swift) | section 7 |
| [`ControlsSource.swift`](../ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ControlsSource.swift) | the value tree, and the threat key of section 5.9 |
| [`ProjectConvention.swift`](../ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ProjectConvention.swift) | how a `.arch` file pairs with its `.controls` and its `.md` |

Related documents:

- [The README](../README.md) — the project, the file layout and the executable.
- [The code-first design](superpowers/specs/2026-09-08-code-first-dsl-design.md) —
  why the languages are shaped this way.
- [Running the tests](TESTING.md)
