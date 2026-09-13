# The governance file — design

Date: 2026-09-13
Status: approved for planning

## 1. Why

A `.controls` file lets a person write `status = "accepted"` against a control
and move on. The file records that somebody accepted the risk. It records
nobody's name, no date, and no date to look at it again. The application then
prints the threat at its full score and says nothing about who owns it.

A `recommendation` has the same hole in the other direction. It states what
should be done. It states nobody who will do it, no size, and no date.

`2026-09-13-report-professional-structure-design.md` section 11 names both:

- "Governance on an accepted risk: who accepted it, when, and when it is
  reviewed again."
- "Governance on a recommendation: owner, effort, acceptance criteria."

An accepted risk with no owner and no review date is not a decision. It is a
threat somebody stopped reading.

## 2. Scope

**In scope.** A fourth source language in a `.governance` file; the compiler
that writes its stanzas; four new failures in `threatmodeller check`; two
report sections; read-only lines on the threat card.

**Out of scope.** Document control — the report's version, author,
classification and scope statement. That is report metadata, not a decision
about a threat, and it belongs in a later design.

**Out of scope.** Evidence tiers on a control note. A later design.

**Out of scope.** Any change to how a score is computed. An accepted risk still
counts at its full score, which is what `ControlStatus.accepted` already does.

**Out of scope.** Any editor in the application.

## 3. The file

One `.governance` file per system, beside its `.arch` and `.controls` files,
under the same stem. `threatmodeller compile` writes it. A person fills it in
and commits it.

A system with no accepted control and no recommendation gets no file. Nothing
writes an empty one.

### 3.1 Shape

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
      status     = "planned"
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

### 3.2 Grammar

```
GovernanceFile  = GovernanceBlock ;

GovernanceBlock = "governance" "for" String "{" { GovernanceEntry } "}" ;
GovernanceEntry = ThreatBlock | ActionBlock ;

ThreatBlock = [ "stale" ] "threat" String "on" SourceKind String "{" { ThreatEntry } "}" ;
SourceKind  = "component" | "zone" | "flow" ;
ThreatEntry = AcceptedBlock | WorkBlock ;

AcceptedBlock = [ "stale" ] "accepted" String "{" { AcceptedAttr } "}" ;
AcceptedAttr  = "owner"       "=" String
              | "accepted_on" "=" String
              | "review_by"   "=" String
              | "rationale"   "=" String
              | "sources"     "=" StringList ;

WorkBlock = [ "stale" ] "work" String "{" { WorkAttr } "}" ;
ActionBlock = [ "stale" ] "action" String "{" { WorkAttr } "}" ;
WorkAttr    = "owner"      "=" String
            | "effort"     "=" String
            | "due_by"     "=" String
            | "status"     "=" String
            | "acceptance" "=" String
            | "note"       "=" String
            | "sources"    "=" StringList ;
```

The file uses the lexer and the block syntax of sections 2 and 3 of
`LANGUAGE.md`, unchanged. The `threat … on …` header is the header the controls
language already parses, and the two parsers share the code that reads it.

A file holds exactly one `governance for` block. Text after its closing brace
is not read. A file that does not start with `governance` is the error
`expected governance, not "<word>"`. A block missing the keyword `for` is the
error `expected for, not "<word>"`, which is the wording the controls parser
already gives.

### 3.3 Identity

| Block | Label | Keyed by |
| --- | --- | --- |
| `threat` | the threat id, then what raised it | `<threat id>@<kind>:<source id>`, the key section 5.9 of `LANGUAGE.md` gives |
| `accepted` | the control's description | the threat key and the description |
| `work` | the recommendation's text | the threat key and the text |
| `action` | the action's label | the label, which the `.arch` file declares |

A control's description is its identity in the `.controls` file, and it is its
identity here. A recommendation's text is its identity, for the same reason.
An action already carries a label, which is a stable id a person chooses, so
an `action` block keys on that and not on its text.

### 3.4 The values

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

A date is a calendar date written `YYYY-MM-DD`. The parser refuses text that
is not one, and it refuses `2026-02-30`.

### 3.5 What the parser refuses

| Check | Message |
| --- | --- |
| a date that is not `YYYY-MM-DD` | `<attribute> is "<raw>"; a date is written YYYY-MM-DD` |
| a date that is not a calendar date | `<attribute> is "<raw>", which is not a date` |
| an `effort` outside the three | `effort is "<raw>"; this application holds "small", "medium", "large"` |
| a `status` outside the four | `status is "<raw>"; this application holds "planned", "in_progress", "done", "dropped"` |
| a threat block with no `on` | `a threat says what raised it: on component, on zone or on flow` |
| two blocks with one key | `<key> is governed twice` |

### 3.6 `stale`

`stale` marks a stanza whose control is no longer accepted, whose
recommendation is gone, or whose threat the architecture no longer raises. The
rule is the rule section 5.4 of `LANGUAGE.md` gives: nothing deletes a stale
block, the application applies nothing it holds, and a person deletes it.

A `stale` stanza does not fail `threatmodeller check`. The `.controls` file
already fails the build for a stale answer, and failing twice for one cause
tells a person nothing new.

## 4. The compile

`threatmodeller compile` writes the `.governance` file after it writes the
`.controls` file, because what it writes is read from the compiled answers.

| Case | Result |
| --- | --- |
| a control is `accepted` and the file governs it | the stanza is kept whole |
| a control is `accepted` and the file does not govern it | a stanza appears with every field empty |
| a recommendation exists and the file does not govern it | a `work` stanza appears with every field empty |
| an `.arch` action exists and the file does not govern it | an `action` stanza appears with every field empty |
| a control is no longer `accepted` | the stanza is marked `stale` |
| a recommendation or an action is gone | the stanza is marked `stale` |
| a threat is no longer raised | its whole block is marked `stale` |

The order the writer writes is the order the resolver gives, which is the order
the `.controls` writer already uses, then the actions in the order the `.arch`
file declares them. Two compiles of one project write the same bytes.

## 5. `threatmodeller check`

`check` gains four failures. Each exits 1, which is the code an unanswered
threat already exits.

| Failure | Printed |
| --- | --- |
| a control is `accepted` and no stanza governs it | `<key> is accepted and has no governance entry; run threatmodeller compile` |
| an `accepted` stanza has no `owner` | `<key> is accepted by nobody; the accepted risk needs an owner` |
| an `accepted` stanza has no `review_by` | `<key> is accepted with no review date` |
| an `accepted` stanza's `review_by` has passed | `<key> was accepted for review by <date>, which has passed` |

A `work` stanza and an `action` stanza fail nothing. Planned work with no owner
is a gap in a plan; an accepted risk with no owner is a decision nobody made.
The report prints both.

`review_by` is compared against the date `Clock` gives, which
`modelling/gateway/Clock.swift` already defines and `FixedClock` already fakes.
No test reads the wall clock.

WARNING: this changes an existing project's build. A project that accepts risks
today and has no `.governance` file fails `check` the first time it runs after
this change. The fix is two steps, and the plan states them in the README and
in the release note: run `threatmodeller compile`, then fill in the owner and
the review date in each stanza the compile wrote.

## 6. The report

### 6.1 `## Accepted risks`

The section sits after `## Recommendations` and before `## Assumptions`. A
model that accepts nothing writes no section.

```markdown
## Accepted risks

Each row is a risk the organisation decided to carry. The score is the full
score: accepting a risk lowers nothing.

| Threat | Element | Score | Owner | Accepted | Review by | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| Credential theft | api | 12 | Head of Platform | 2026-09-01 | 2027-03-01 | The MFA rollout waits on the SSO migration. |
| Data exfiltration | ledger | 9 | — | — | — | — |
```

A row is written for every accepted control, governed or not, so a reader sees
the ungoverned ones as a row of dashes rather than not at all. Rows sort by
score, worst first, then by threat name.

A row whose `review_by` has passed is marked `**overdue**` beside the date, and
the executive summary states the count: `2 accepted risks are past their review
date.`

### 6.2 The Recommendations section

`MarkdownRecommendations` gains three columns of governance, printed as one
line under the existing lines:

```markdown
- Protect the managed preferences plist
  - Credential theft on api, risk 12
  - Deny write from anything but the MDM daemon.
  - Platform team, medium effort, due 2026-11-30, planned
```

A recommendation with no governance writes no such line. The leverage section
gets the same line for an action.

### 6.3 The threat card

`ThreatCard` shows the owner and the review date beside a control whose status
is `accepted`, and marks a passed review date. It writes nothing.

## 7. Where the code goes

| File | Change |
| --- | --- |
| `architecture/domain/GovernanceSource.swift` | new: `GovernanceSource`, `SourceAcceptedRisk`, `SourcePlannedWork`, `GovernanceRead` |
| `architecture/gateway/GovernanceSourceGateway.swift` | new |
| `ArchitectureDSL/GovernanceParser.swift` | new |
| `ArchitectureDSL/GovernanceWriter.swift` | new |
| `ArchitectureDSL/HclGovernanceSource.swift` | new |
| `ArchitectureDSL/ControlsParser.swift` | the `threat … on …` header moves to shared code |
| `assessment/domain/RiskAcceptance.swift` | new |
| `assessment/domain/PlannedWork.swift` | new |
| `assessment/domain/GovernanceDate.swift` | new: the date value and its parser |
| `architecture/usecase/CompileGovernance.swift` | new |
| `architecture/usecase/ApplyGovernance.swift` | new |
| `architecture/usecase/CheckGovernance.swift` | new |
| `architecture/usecase/CheckControlAnswers.swift` | calls it, and carries its failures |
| `architecture/domain/ProjectConvention.swift` | `governanceExtension`, and `system(atPath:)` opens a project from a `.governance` file |
| `architecture/domain/ProjectLayout.swift` | `ProjectSystem.governancePath` |
| `architecture/gateway/ProjectSourceGateway.swift` | reads and writes the file |
| `reporting/domain/Report.swift` | the accepted-risk rows and the governance fields |
| `reporting/usecase/BuildThreatModelReport.swift` | fills them |
| `reporting/usecase/MarkdownAcceptedRisks.swift` | new |
| `reporting/usecase/MarkdownRecommendations.swift` | the governance line |
| `reporting/usecase/MarkdownLeverage.swift` | the governance line |
| `reporting/usecase/MarkdownExecutiveSummary.swift` | the overdue count |
| `reporting/usecase/ExportModelAsMarkdown.swift` | places the section |
| `CommandLineApplication/CommandLineApplication.swift` | compile writes the file, check reads it, usage text |
| `threatmodeller/sidebar/ThreatCard.swift` | the two lines |
| `threatmodeller/project/ProjectSession.swift` | follows the third file |
| `docs/LANGUAGE.md` | a new section 7 for the governance language, after the library language, and the sections after it renumber |
| `README.md` | the migration steps |

## 8. Testing

| Test | Says |
| --- | --- |
| `GovernanceParserTests` | every block of section 3.1 parses, and round-trips through the writer unchanged |
| | each row of the table in section 3.5 |
| | a `stale` stanza parses and stays stale |
| `GovernanceDateTests` | `2026-09-01` parses; `01-09-2026`, `2026-9-1` and `2026-02-30` each fail with the message of section 3.5 |
| `CompileGovernanceTests` | each row of the table in section 4 |
| | a system with no accepted control and no recommendation writes no file |
| | two compiles write the same bytes |
| `CheckGovernanceTests` | each row of the table in section 5, against `FixedClock` |
| | a `work` stanza with no owner fails nothing |
| | a `stale` stanza fails nothing |
| `MarkdownAcceptedRisksTests` | the table of section 6.1, the dashes for an ungoverned row, the overdue mark, and no section when nothing is accepted |
| `MarkdownRecommendationsTests` | the governance line, and no line without governance |
| `ProjectSessionTests` | the third file is followed, and a change to it reloads the model |

## 9. The risk in this design

The file adds a fourth language and a fourth file to every project that accepts
a risk. Two things keep that cost down, and the plan holds both.

The first is that the file is written, not invented. A person never creates a
`.governance` file or works out what goes in it. `compile` writes the stanza
and the person fills the fields.

The second is that the language reuses what is there: the same lexer, the same
block syntax, the same `threat … on …` header, the same `stale` rule, and the
same merge rules as the `.controls` file. A person who can read a `.controls`
file can read this one.
