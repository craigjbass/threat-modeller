# The policy file — design

Date: 2026-09-14
Status: approved for planning

## 1. Why

`threatmodeller check` fails a build for an unanswered threat, a stale answer,
a stale tree and an accepted risk nobody governs. It fails for nothing a team
decides for itself.

A team rules "no critical threat is accepted without an owner", "no restricted
data in a public zone", "every assumption names an owner", or "no open threat
above high". Today they write a script over the report, or they do not enforce
the rule at all. A rule nobody enforces is a rule nobody keeps.

## 2. The decision: named rules, not an expression language

The set is a fixed list of named rules a project turns on. It is not an
expression language over the model.

An expression language would be more powerful and would cost more than it is
worth here:

- **A rule a team cannot mistype.** An unknown rule name is an error with the
  list of names beside it. An expression that reads the wrong field is a rule
  that silently passes.
- **A rule the report can explain.** Each named rule states, in the report,
  what it asks and whether it holds. An expression can be printed and not
  explained.
- **A rule this application can keep working.** A named rule survives a change
  to the value tree, because the code moves with it. An expression written
  against a field name breaks when the field is renamed, and breaks in a
  project the authors of the change never see.

A team that needs a rule this set does not hold opens an issue for it, and the
set grows by one name that every project then gets. Section 8 states what a
later design would add if the set outgrows a flat file.

## 3. The file

One `threatmodel/policy.hcl` for the whole project, beside the systems it
governs. Every system is checked against it. A project with no such file checks
exactly as it does today.

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

The file holds exactly one `policy` block. Text after its closing brace is not
read. A file that does not start with `policy` is the error `expected policy,
not "<word>"`.

### 3.1 The rules

| Rule | Type | What it asks |
| --- | --- | --- |
| `max_open_at_level` | a risk level | no threat at that level or worse is unanswered |
| `accepted_requires_owner` | boolean | every accepted risk names an owner |
| `accepted_requires_review_by` | boolean | every accepted risk names a review date |
| `implemented_requires_evidence_above` | a risk level | every implemented control on a threat at that level or worse, before its controls, states an evidence tier |
| `restricted_data_stays_out_of_public_zones` | boolean | no component holding restricted data sits in a public zone, or outside every zone |
| `assumptions_require_owner` | boolean | every assumption names an owner |
| `system_requires_owner` | boolean | the `.arch` file states `owner` |

A rule the file does not state is not in force. `false` is the same as not
stating it, so a team can turn one off without deleting the line.

A risk level is `low`, `medium`, `high` or `critical`. A value outside the four
is the error `<rule> is "<raw>"; this application holds "low", "medium",
"high", "critical"`. A name outside the set is the error `a policy holds
<the seven names>, not "<word>"`.

### 3.2 What a breach prints

One line per breach, in the shape `check` already prints, and in the
`--format github` shape as an `::error` on the file the breach is about:

```
threatmodel/payments.controls: max_open_at_level: credential-theft on component "api" (Critical) is open at or above high
threatmodel/payments.governance: accepted_requires_owner: data-exfiltration@component:db is accepted by nobody
threatmodel/payments.arch: restricted_data_stays_out_of_public_zones: "ledger" holds restricted data in a public zone
threatmodel/payments.arch: system_requires_owner: this system states no owner
```

Every line names the rule first, because a person reading a build log is
looking for which rule they broke.

Any breach exits 1, which is the code every other `check` failure exits.

### 3.3 `owner` on a system

`system_requires_owner` needs somewhere for the owner to live, so the `.arch`
file's `system` block takes one more attribute:

```hcl
system "Payments" {
  owner = "Payments team"
}
```

It is a string, it defaults to empty, and nothing but this rule and the report
reads it.

## 4. Where the rules overlap what is already there

Three of the seven restate a check that already exists:

| Rule | Already checked by |
| --- | --- |
| `accepted_requires_owner` | the governance check, always |
| `accepted_requires_review_by` | the governance check, always |
| `implemented_requires_evidence_above` | `requires_evidence_above` in one `.arch` file |

They stay in the set, and the checks stay where they are. The policy file is
where a project states the rule once for every system, and the `.arch`
attribute is where one system states its own. **The stricter of the two
applies**, and a breach is printed once: the check that finds it first names
it, and the policy check skips a breach the governance check already printed.

## 5. The report

`## Policy` sits after `## Executive summary` and before `## Methodology`. A
project with no policy file writes no section.

```markdown
## Policy

The rules this project enforces, and whether this system keeps them.

| Rule | Asks | Holds |
| --- | --- | --- |
| max_open_at_level | no threat at high or worse is unanswered | no — 3 breaches |
| accepted_requires_owner | every accepted risk names an owner | yes |
| system_requires_owner | the file states an owner | yes |
```

A reader of the report sees what the team enforces, not only what it failed.

## 6. Where the code goes

| File | Change |
| --- | --- |
| `architecture/domain/PolicySource.swift` | new: `PolicySource`, `PolicyRuleName`, `PolicyRead` |
| `architecture/gateway/PolicySourceGateway.swift` | new |
| `ArchitectureDSL/PolicyParser.swift` | new |
| `ArchitectureDSL/HclPolicySource.swift` | new |
| `architecture/usecase/CheckPolicy.swift` | new: one function per rule |
| `architecture/usecase/CheckControlAnswers.swift` | reads the policy and carries its breaches |
| `architecture/domain/ProjectConvention.swift` | `policyFileName` |
| `architecture/domain/ProjectLayout.swift` | `policyPath` |
| `architecture/domain/ArchitectureSource.swift` | `owner` |
| `ArchitectureDSL/ArchitectureParser.swift` | reads it |
| `ArchitectureDSL/ArchitectureWriter.swift` | writes it |
| `modelling/domain/ThreatModel.swift` | `owner`, and the policy in force |
| `reporting/domain/Report.swift` | `ReportPolicyRule` |
| `reporting/usecase/MarkdownPolicy.swift` | new |
| `reporting/usecase/ExportModelAsMarkdown.swift` | places the section |
| `CommandLineApplication/CommandLineApplication.swift` | reads the file, prints the breaches |
| `docs/LANGUAGE.md` | the policy language |
| `README.md` | the file and the seven rules |

## 7. Testing

| Test | Says |
| --- | --- |
| `PolicyParserTests` | every rule parses; an unknown name and a level outside the four each give the stated message |
| `CheckPolicyTests` | each of the seven rules has a test that breaches it and a test that satisfies it |
| | a project with no policy file breaches nothing |
| | a breach the governance check already printed is not printed twice |
| `MarkdownPolicyTests` | the table of section 5, and no section without a policy file |
| `CommandLineApplicationTests` | a breach exits 1 and prints the line, in both formats |

## 8. What a later design would add

If the set outgrows a flat file, the next step is a rule that takes a
parameter list rather than one value — `max_open_at_level` per zone, say — and
that is a block rather than an attribute. The grammar of section 3 leaves room
for it: an attribute and a block are told apart by the token after the name,
the way every other language in this application tells them apart.
