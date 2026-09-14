# Attack trees as a fourth source file — design

Date: 2026-09-14
Status: approved for planning

## 1. Why

The model scores every threat on its own. `AttackPaths` walks the flow graph
and prints the routes it finds, but a route is a list of components with the
worst threat on each one written beside it. Nothing states that the threat on
one hop makes the threat on the next hop reachable.

A two-tier AWS web application shows the gap. Its report holds these five rows:

| Threat | Raised on | Score |
| --- | --- | --- |
| Server-Side Request Forgery | Application Server | 5 |
| Credential Theft | Application Server | 2 |
| Excessive Permissions | Secrets Manager | 6 |
| Privilege Escalation | Secrets Manager | 11 |
| Data Exfiltration | PostgreSQL Database | 5 |

Those five rows are one route to the customer records. A reader has to join
them up in their head, and the file says nothing that helps.

Three things are missing, and each one is a thing a person knows and the file
cannot hold:

1. **An order.** Which threat comes before which.
2. **A conjunction.** "The application role can list every secret **and** no
   permission boundary caps it." The grammar has no word for "and".
3. **A dead branch.** IMDSv2 is required on the instance, so the metadata route
   is closed. The model states the control. It does not state which route the
   control closed.

This design gives a person a place to write all three, and it makes the score
of the goal answer to them.

## 2. Scope

**In scope.** A fourth source file, `<stem>.attacktree`, that a person writes;
`tree` and `stale tree` stanzas in the `.controls` file that the compiler
writes; a binding rule; one more scoring stage; a report section; the
diagnostics for all of it.

**Out of scope.** Attack trees in a `.lib` file. Section 9 states why.

**Out of scope.** Generating a tree. `AttackPaths` proposes the routes today
and this design does not change it. A person promotes a route to a tree.

**Out of scope.** Drawing a tree. `threatmodeller draw` writes no tree picture
in this design.

**Out of scope.** The application window. The macOS application reads the file
and shows nothing new. A later design adds the canvas work.

## 3. The language

A `.attacktree` file sits beside the `.arch` file it belongs to and takes the
same stem: `threatmodel/payments.arch` pairs with
`threatmodel/payments.attacktree`. A project with no trees holds no such file.

The file shares the lexer and the block syntax of the other three languages.
Sections 2 and 3 of the language guide hold what is common.

### 3.1 Shape

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
        step "credential-theft" on component "appserver" {
          note = "Through the instance metadata service."
        }

        all_of {
          step "excessive-permissions" on component "secrets"
          step "privilege-escalation" on component "secrets"
        }
      }
    }
  }
}
```

### 3.2 Grammar

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

The header takes two keywords in turn, the same way the controls file does, so
the two messages read the same way: a file that does not start with
`attack_trees` is the error `expected attack_trees, not "<word>"`, and a block
missing `for` is the error `expected for, not "<word>"`.

`goal` and `step` take the two-label shape the controls language already uses
for `threat "<id>" on component "<id>"`. One shape, read by one rule, in three
languages.

A `step` with no body is that same step with an empty body, which follows the
rule `flow a -> b` already sets.

### 3.3 The blocks and the attributes

| Block | Label | Attribute | Values | Default |
| --- | --- | --- | --- | --- |
| `attack_trees for` | the system name | `catalogue` | a tag string | the catalogue in use |
| `tree` | the tree id | `name` | string | the label |
| | | `description` | string | none |
| | | `raises_risk_by` | number, 0 to 100 | `0` |
| `goal` | the threat id, then the source | | | **required** |
| `step` | the threat id, then the source | `note` | string | none |

**`raises_risk_by = 0` is a tree that narrates and scores nothing.** The report
prints it, `check` gates on it, and no number moves. A team that wants the
picture without the arithmetic writes no number at all, because the writer does
not write an attribute holding its default.

A tree body holds exactly one root, which is one `all_of`, one `any_of` or one
`step`.

### 3.4 Identity

The label of a `tree` block is its id, and the file writes each one once.

A `tree` stanza in the controls file keys on that same tree id, and each `step`
inside it keys on `<threat id>@<kind>:<source id>`, which is the key section 5.9
of the language guide already mints.

### 3.5 What the parser refuses

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

A step naming a component the `.arch` file does not declare is **not** a parser
error. The parser reads one file and the architecture is another. Section 5
states what happens instead: the step does not bind, and the compile moves the
tree into `stale tree`. This follows the rule the language guide already states
in section 4.10, where `ImportArchitecture` raises the catalogue warning
"because only the import knows the catalogue".

## 4. The controls file

The `.attacktree` file states what a person believes. The `.controls` file
states what the model found, which is the file the compiler already owns.

### 4.1 `tree`

```hcl
controls for "Two-Tier Web Application" {
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
      by    = "Enforce IMDSv2 with a hop limit of 1 to prevent SSRF-based metadata access"
    }

    step "excessive-permissions@component:secrets" {
      state = "open"
    }

    step "privilege-escalation@component:secrets" {
      state = "open"
    }
  }
}
```

Every attribute in this stanza is written for the reader. The application
recomputes all of them, the same way it recomputes `severity` and `score` on a
threat stanza, so an edit to any of them changes nothing.

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
whole tree into `stale tree`. Section 4.2 is the only place that word is
written.

### 4.2 `stale tree`

```hcl
stale tree "read-every-customer-record" {
  step "credential-theft@component:appserver" {
    state = "unbound"
  }
}
```

`stale` marks a tree the architecture no longer supports: a step names a
component that has gone, or the model no longer raises that threat there, or the
goal itself no longer binds.

Nothing deletes a stale block and the application applies nothing it holds. A
person deletes it, or restores what the tree named. `threatmodeller check`
exits 1 while one remains and prints
`the tree "<id>" is written but no longer binds`.

This is the rule `StaleAnswers` already runs for an answer, in the same shape
and with the same round trip: when the architecture supports the tree again, the
next compile moves it back out.

### 4.3 The merge

| Case | Result |
| --- | --- |
| the `.attacktree` file states a tree and every step binds | a `tree` stanza, rewritten from the model |
| a step stops binding | the whole tree moves into `stale tree` |
| the goal stops binding | the whole tree moves into `stale tree` |
| a stale tree binds again | it moves back out of `stale tree` |
| the `.attacktree` file drops a tree | the stanza is deleted, because the person deleted its source |

The last row differs from a threat answer, and the reason is ownership. A
threat answer is the only copy of what a person said, so the compile keeps it in
a `stale` block. A tree stanza is derived from a file a person owns, so
deleting the tree deletes the stanza and loses nothing.

## 5. Binding

### 5.1 What a step binds to

A step binds when the resolved model raises that threat on that source. The
resolver already produces the set; the binder reads it and matches on the key
`<threat id>@<kind>:<source id>`.

A step that does not bind is `unbound`, and one unbound step makes the whole
tree stale. A tree is a claim about a route, and a route with a missing step is
not a weaker claim; it is a claim about a system that is no longer there.

### 5.2 When a step is open

A bound step is **closed** when its threat holds at least one `implemented`
control or a `compensating` block. It is **open** otherwise.

This is deliberately not the `isAnswered` predicate that `CheckControlAnswers`
uses. That predicate counts `not_applicable` and `accepted` as answers, and
neither of them closes a route:

| Status | Answers the threat | Closes the step | Why |
| --- | --- | --- | --- |
| `implemented` | yes | yes | the control is in place |
| `compensating` | yes | yes | something else stops it |
| `not_applicable` | yes | **no** | the control does not apply, so nothing here stops the step |
| `accepted` | yes | **no** | the team lives with it, and an attacker still does it |
| `not_implemented` | no | no | |

A `likelihood` finding never closes a step. It lowers the step's factor, which
section 6.2 reads.

### 5.3 The node rules

| Node | Open while | Factor |
| --- | --- | --- |
| `step` | section 5.2 says open | the threat's own likelihood factor |
| `any_of` | any child is open | the **strongest** open child |
| `all_of` | every child is open | the **weakest** child |

A tree whose root is closed gives no boost.

`any_of` takes the strongest child because an attacker picks the easiest branch.
`all_of` takes the weakest because the chain needs every one of them.

## 6. The score

### 6.1 The stage

The resolver runs seven stages today, and `ThreatResolver.resolve()` runs them
one threat at a time: `raise` calls `compensated(likelihooded(threat))`.

A tree stage cannot sit inside that pipeline. Whether a step is open depends on
another threat's answers, so the stage needs the whole resolved set. It runs as
a second pass over the output of `resolve()`, and it is stage 8.

```
score = min(16, round(goal score × (1 + raises_risk_by ÷ 100 × chain factor)))
```

The goal score the stage reads is the score after all seven stages, so the zone
reduction, the controls, the mitigations, the likelihood and the compensating
control have all already lowered it. The boost raises what is left.

16 is the top of the scale `RiskScore` states.

**The target score takes the same boost.** A threat carries two numbers: the
residual score, and the target score the report prints as "if the assumptions
hold". The stage raises both by the same boost, with the same clamp.

The reason is that an assumed `mitigates` edge lowers a score and answers
nothing. Section 5.2 states that a step closes on an implemented control or a
compensating control, and on nothing else, so adopting every assumed edge
closes no step and leaves the chain exactly as it was. The same chain gives the
same boost.

WARNING: a stage that raises the residual score and leaves the target score
alone makes the two differ on a threat that carries no assumed mitigation at
all. The report prints the "if the assumptions hold" line whenever the two
differ, so that threat would state an assumption nobody made.

### 6.2 The chain factor

The chain factor is the root node's factor, by the rules of section 5.3. A step
takes the factor the likelihood stage gave its threat: `commodity` 1.0,
`targeted` 0.6, `research` 0.25, or a `prior` divided by 100.

**The goal is not a step and never enters the chain.** Stage 6 already applied
the goal's own likelihood to the goal's own score. Counting it a second time in
the chain would apply it twice.

**The weakest step, not the product of the steps.** The two rules agree on a
chain of `commodity` steps and disagree on a long chain of `targeted` ones:

| Chain | Weakest | Product |
| --- | --- | --- |
| 4 × commodity | 1.00, so +40% | 1.00, so +40% |
| 4 × targeted | 0.60, so +24% | 0.13, so +5% |
| 3 × commodity, 1 × research | 0.25, so +10% | 0.25, so +10% |

A product says a four-step targeted route is nearly free, and that route is what
a funded attacker runs. The likelihood in this application also means how many
attackers use a technique, not how often a step works, so a product of those
numbers is not a probability of anything.

### 6.3 The worked example

The two-tier model's goal, Data Exfiltration on the database, scores 5. Every
step in the tree of section 3.1 is `commodity`, and the closed metadata branch
sits under an `any_of` beside an open branch, so the root stays open at 1.0.

```
5 × (1 + 40 ÷ 100 × 1.0) = 7
```

Data Exfiltration on the database moves from 5 to 7. The level stays Medium,
because the Medium band runs from 4 to 7. The report prints both numbers and the
chain, so a reader sees the move even when the band does not change.

### 6.4 What this stage does not change

- A threat no tree names keeps the score it has today.
- A model with no `.attacktree` file scores exactly what it scores today.
- A step's own score never moves. Only the goal's does.
- `threatmodeller check` still fails a threat with no answer, by the rule it
  uses today. A tree neither answers a threat nor excuses one.

## 7. The report

One new section, `## Attack trees`, placed after `## Attack paths`, because the
paths propose the routes and the trees state the ones a person confirmed.

```markdown
## Attack trees

### Read every customer record — 5 → 7, chain 100%

An unauthenticated caller reaches the customer table.

Goal: Data Exfiltration on the PostgreSQL Database.

| Step | Raised on | State | Closed by |
| --- | --- | --- | --- |
| Server-Side Request Forgery | Application Server | open | — |
| Credential Theft | Application Server | closed | Enforce IMDSv2 with a hop limit of 1 |
| Excessive Permissions | Secrets Manager | open | — |
| Privilege Escalation | Secrets Manager | open | — |

The weakest open step is Commodity, so the tree raises the goal by the whole 40%.
```

Two more places state a tree:

- **`## Executive summary`.** A goal whose score a tree raised says so on its
  line, so the three worst rows never hide the reason one of them is there.
- **`Appendix A`.** A threat stanza for a goal prints the score before the tree
  and the tree that raised it, beside the lines that already print the score
  before controls and before compensation.

The section states the count of trees written against the count of routes
`AttackPaths` found, so a reader sees how much of the graph a person has
confirmed:

```
This model states 1 tree. The walk found 20 routes.
```

## 8. The command line

No new verb.

| Verb | What changes |
| --- | --- |
| `compile` | reads the `.attacktree` file, binds every tree, writes the `tree` and `stale tree` stanzas |
| `check` | exits 1 for a `stale tree`, and prints `the tree "<id>" is written but no longer binds` |
| `report` | writes the new section |
| `format` | rewrites every `.attacktree` file in its canonical shape |
| `draw` | unchanged |

Exit codes do not change. A stale tree joins the list of things that exit 1,
alongside an unanswered threat and a stale answer.

The canonical form follows the rules section 8 of the language guide already
states: two spaces of indentation, aligned equals signs, a blank line between
blocks, no attribute holding its default. A `tree` block writes `name`, then
`description`, then `raises_risk_by`, then `goal`, then the root node. A node
writes its children in the order the source declares them, because the order is
what a person reads.

## 9. What this design does not do

**No trees in a `.lib` file.** A library pattern would be written over threat
ids and would name no component, so it would be a query. The catalogue holds 55
threats, and a query such as `ssrf-attack → credential-theft →
data-exfiltration` fits any system with a compute component, a secret store and
a database. It fits the two-tier model, and it fits nearly every other one.

The repository has already measured this hazard for a weaker case.
`2026-09-13-mitre-attack-import-design.md` section 8 records that `T1059` is
performed by 124 of 176 ATT&CK groups, and states that a long `Performed by:`
line must not read as evidence. That is a report line. A library pattern under
this design would move a score.

The library layer is also definitional. `technology`, `threat`, `control`,
`mitigation` and the planned `threat_actor` all answer "what is this thing". A
tree answers "what is true of this account": "the application role can list
every secret and no permission boundary caps it" is a fact about one AWS
account, not about Secrets Manager.

A library pattern can be added later, on top of this design, without changing
the `.attacktree` grammar. Nothing here forecloses it.

**No reuse across systems.** A team with twelve systems writes the tree twelve
times. This is the cost of the paragraph above.

**No automatic promotion.** `AttackPaths` proposes and a person writes. The
compile never writes a tree into the `.attacktree` file.

**No reach for a threat actor.** `2026-09-13-threat-actors-design.md` section 7
states that its design "does not model where an actor starts or what it can
reach", and this design does not close that either. A tree states a route; it
does not state who walks it.

## 10. Testing

| Test | Says |
| --- | --- |
| `AttackTreeLanguageTests` | the block of section 3.1 parses and round-trips through the writer |
| | a `step` with no body reads as a step with an empty body |
| | each row of the diagnostics table of section 3.5 |
| `AttackTreeBindingTests` | a step binds when the model raises that threat on that source |
| | one unbound step makes the whole tree stale |
| | an unbound goal makes the whole tree stale |
| | each row of the status table of section 5.2, `accepted` and `not_applicable` included |
| | the three node rules of section 5.3 |
| `AttackTreeScoreTests` | the worked example of section 6.3 reaches 7 |
| | a closed root gives no boost |
| | `raises_risk_by = 0` moves no number |
| | a boost never carries a score above 16 |
| | the weakest step decides the chain, in each row of the table of section 6.2 |
| `AssessThreatModelTests` | a model with no `.attacktree` file scores exactly what it scores today |
| `CompileControlsTests` | each row of the merge table of section 4.3 |
| `CheckControlAnswersTests` | a stale tree exits 1 and prints its message |
| `MarkdownAttackTreesTests` | the section of section 7, and no section when a model states no tree |
| `ProjectConventionTests` | a `.attacktree` file pairs with its `.arch` file by stem |

The regression test that matters is the `AssessThreatModelTests` row. Every
sample model in `Resources/Samples/` states no tree, so every score in every
existing test stays where it is.

## 11. Where the code goes

| File | Change |
| --- | --- |
| `ArchitectureDSL/AttackTreeParser.swift` | new, section 3 |
| `ArchitectureDSL/AttackTreeWriter.swift` | new, the canonical form |
| `ArchitectureDSL/ControlsParser.swift` | reads `tree` and `stale tree` |
| `ArchitectureDSL/ControlsWriter.swift` | writes them |
| `architecture/domain/AttackTreeSource.swift` | new, the value tree |
| `architecture/domain/ControlsSource.swift` | the tree stanza |
| `architecture/domain/ProjectConvention.swift` | `attackTreeExtension`, the field on `ProjectSystem`, the line in `systems(in:fileNames:)`, the extension in `system(atPath:)` |
| `architecture/gateway/AttackTreeSourceGateway.swift` | new, beside `ControlsSourceGateway` |
| `architecture/usecase/CompileControls.swift` | binds and merges |
| `architecture/usecase/CheckControlAnswers.swift` | the stale tree exit |
| `architecture/usecase/StaleAnswers.swift` | lists and removes a stale tree |
| `assessment/domain/AttackTree.swift` | new, the tree, the node and the step |
| `assessment/domain/AttackTreeBinding.swift` | new, sections 5 and 6 |
| `assessment/usecase/AssessThreatModel.swift` | runs stage 8 over the resolved set |
| `modelling/domain/ThreatModel.swift` | `attackTrees` |
| `reporting/domain/Report.swift` | the tree section and the stanza fields |
| `reporting/usecase/BuildThreatModelReport.swift` | fills them |
| `reporting/usecase/MarkdownAttackTrees.swift` | new |
| `reporting/usecase/MarkdownExecutiveSummary.swift` | the line on a raised goal |
| `reporting/usecase/MarkdownThreatStanza.swift` | the two appendix lines |
| `reporting/usecase/ExportModelAsMarkdown.swift` | places the section after the attack paths |
| `CommandLineApplication/CommandLineApplication.swift` | reads one more file per system |
| `docs/LANGUAGE.md` | a new section 7, and the sections after it move |

## 12. The risk in this design

**A team writes one tree and believes the model covers routes.** It covers the
one route they wrote. Section 7 holds this back: the section prints the count of
trees against the count of routes `AttackPaths` found, so a reader sees one
tree beside twenty routes and knows what that means.

**`raises_risk_by` is a number a team can turn until it likes the answer.** Two
things hold this back. The number is in a file a pull request shows, beside the
steps that justify it. The report prints the chain, the weakest open step and
both scores, so a reader checks the reasoning rather than the number.

**A step marked `accepted` stays open, and a reader may find that surprising.**
The report section states it: an accepted risk closes nothing, because the
attacker still does the thing the team accepted. The table of section 5.2 is the
rule, and the glossary states it in the report.

**Four languages is one more than three.** `LANGUAGE.md` grows past 1624 lines,
and every language gains a diagnostics table nobody reads until it fires. The
lexer and the block syntax are shared, so the new language is a set of keywords
and block shapes rather than a new parser family. That holds the cost down. It
does not remove it.
