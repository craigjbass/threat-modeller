# Evidence on a control — design

Date: 2026-09-14
Status: approved for planning

## 1. Why

A `control` block takes `status = "implemented"` and a `note`, and the score
moves on the status alone. Nothing states what proves the control is in place.

Four teams write the same word and mean four things: somebody believes the
control is on; a written policy says it is on; somebody read the configuration
last Tuesday; a test in CI fails when it is off. A reader cannot tell them
apart, and the executive summary counts all four the same.

`2026-09-13-governance-file-design.md` section 2 names this as out of its
scope: "Evidence tiers on a control note. A later design." This is that design.

## 2. Scope

**In scope.** An `evidence` tier, a `reference` and a `verified_on` date on a
`control` block and on a `compensating` block; the diagnostics for all three;
the tier beside each implemented control in the report; a count in the
executive summary; one new `check` failure a project turns on for itself; two
read-only lines on the threat card.

**Out of scope. The score.** A tier moves no score. Section 5 states why, and
that decision is the whole reason this design is safe to add to a model a team
already scored.

**Out of scope.** A policy file of named rules. That is issue #66, and the one
rule this design adds is stated in the `.arch` file until that file exists.

**Out of scope.** Any editor in the application. Evidence is authored in files.

## 3. The tiers

Five tiers, weakest first. The order is the order of what a reader can check
for themselves.

| Tier | Means | A reader can |
| --- | --- | --- |
| `asserted` | somebody says the control is in place | ask them |
| `documented` | a written policy or procedure states it | read the document |
| `configured` | somebody read the running configuration | read the same setting |
| `tested` | a test runs and fails when the control is off | read the test and its last run |
| `audited` | an independent audit found the control in place | read the audit |

A control that states no tier is **unevidenced**, which is what every control
in every file is today. Unevidenced is not a tier: it is the absence of one,
and the report and the check both say so in those words.

`reference` says where the proof is: a URL, a document number, a test name, an
audit finding. `verified_on` is the calendar date somebody last checked, written
`YYYY-MM-DD`, which is the shape `2026-09-13-governance-file-design.md` section
3.4 already gives.

## 4. The language

```hcl
control "Enforce MFA on all administrative access" {
  status      = "implemented"
  note        = "Okta, enforced group-wide"
  evidence    = "tested"
  reference   = "ci/okta-mfa-enforced-test"
  verified_on = "2026-09-01"
}

compensating "Watched by the SIEM" {
  reduces_risk_by = 50
  rationale       = "The one account left alerts on use."
  evidence        = "configured"
  reference       = "splunk/saved-search/admin-login"
  verified_on     = "2026-08-30"
}
```

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `evidence` | string | `asserted`, `documented`, `configured`, `tested`, `audited` | none |
| `reference` | string | any | empty |
| `verified_on` | string | a date, `YYYY-MM-DD` | none |

A control that states none of the three parses exactly as it does today, and
the compile writes none of them back, because the writer never writes an
attribute holding its default.

### 4.1 What the parser refuses

| Check | Message |
| --- | --- |
| an `evidence` outside the five | `evidence is "<raw>"; this application holds "asserted", "documented", "configured", "tested", "audited"` |
| a `verified_on` that is not `YYYY-MM-DD` | `verified_on is "<raw>"; a date is written YYYY-MM-DD` |
| a `verified_on` that is not a calendar date | `verified_on is "<raw>", which is not a date` |

The two date messages are the messages `GovernanceDate` already gives, so one
date fault reads the same in every language.

## 5. What a tier does to a score: nothing

A tier changes no score, and this is deliberate.

A score that moved with the tier would make a team's numbers fall when they
wrote down what they already knew, and rise when a document went stale. Both
readings are wrong: the control is either in place or it is not, and the tier
says how well a reader can check that claim, not how much of the control is
there.

So the tier moves the report and the check, and the arithmetic is untouched. A
model saved today opens unchanged and scores exactly what it scored before.

## 6. `threatmodeller check`

`check` exits 0 for a control with no evidence by default. A project that wants
more states it in its `.arch` file:

```hcl
system "Payments" {
  requires_evidence_above = "high"
}
```

The value is a risk level: `low`, `medium`, `high` or `critical`. The rule is:
an `implemented` control on a threat whose risk level **before its controls**
is that level or worse must state an `evidence` tier.

The level is read before the controls, not after, because reading it after
makes the rule circular: the controls lower the residual score, and a threat
whose controls have lowered it far enough would exempt those same controls from
proving they are in place. The question evidence asks is what the threat is
worth if the controls are not really there, and that is the score before
them. A breach prints

```
<key>: "<control>" is implemented above <level> risk with no evidence
```

and exits 1, which is the code every other `check` failure exits. A level
outside the four is the error `requires_evidence_above is "<raw>"; this
application holds "low", "medium", "high", "critical"`.

A project that states nothing fails nothing, so this design breaks no build.

## 7. The report

A threat's controls already print as a checklist. An implemented control gains
its tier, its reference and the date in one trailing clause:

```markdown
Controls:

- [x] Enforce MFA on all administrative access — tested, ci/okta-mfa-enforced-test, verified 2026-09-01
- [x] Use IAM roles with minimal permissions — no evidence
- [ ] Rotate credentials regularly
```

Only an implemented control states evidence: an unanswered control has nothing
to prove. A compensating control states its tier the same way, on the line the
report already writes for it.

The executive summary states the count, because a reader who reads one page
should see it:

```
12 of 31 implemented controls state no evidence.
```

A model where every implemented control states a tier writes no such line.

## 8. The application

`ThreatCard` shows the tier, the reference and the date under a control whose
status is `implemented`, read only, the way it shows the owner of an accepted
risk. Nothing on screen writes evidence.

## 9. Where the code goes

| File | Change |
| --- | --- |
| `assessment/domain/ControlEvidence.swift` | new: the tier, its order and its label |
| `architecture/domain/ControlsSource.swift` | the three attributes on `SourceControlAnswer` and on the compensating block |
| `assessment/domain/CompensatingControl.swift` | the three attributes |
| `ArchitectureDSL/ControlsParser.swift` | reads them, and refuses the three faults |
| `ArchitectureDSL/ControlsWriter.swift` | writes them |
| `architecture/domain/ArchitectureSource.swift` | `requiresEvidenceAbove` |
| `ArchitectureDSL/ArchitectureParser.swift` | reads it and refuses a level outside the four |
| `ArchitectureDSL/ArchitectureWriter.swift` | writes it |
| `modelling/domain/ThreatModel.swift` | `requiresEvidenceAbove`, and the evidence on a control status |
| `architecture/usecase/ApplyControlAnswers.swift` | carries the evidence onto the model |
| `architecture/usecase/CompileControls.swift` | keeps the three attributes through a merge |
| `architecture/usecase/CheckControlAnswers.swift` | the new failure |
| `assessment/usecase/AssessThreatModel.swift` | the evidence on `AssessedControl` |
| `reporting/domain/Report.swift` | the evidence on `ReportControl`, and the summary count |
| `reporting/usecase/MarkdownThreatStanza.swift` | the trailing clause |
| `reporting/usecase/MarkdownExecutiveSummary.swift` | the count |
| `threatmodeller/sidebar/ThreatCard.swift` | the two lines |
| `docs/LANGUAGE.md` | the attributes, the tiers and the rule |

## 10. Testing

| Test | Says |
| --- | --- |
| `ControlEvidenceTests` | the five tiers order weakest first, and an unknown word is no tier |
| `ControlsParserTests` | the three attributes parse, round-trip, and each row of the table in section 4.1 |
| | a control that states none of the three parses and writes back unchanged |
| `CompileControlsTests` | the three attributes survive a merge, and two compiles write the same bytes |
| `CheckControlAnswersTests` | a project that states no rule fails nothing; a project that states one fails an implemented control above that level with no evidence, and passes the same control with a tier |
| `MarkdownThreatStanzaTests` | the trailing clause, `no evidence`, and nothing on an unanswered control |
| `MarkdownExecutiveSummaryTests` | the count, and no line when every implemented control states a tier |
| `AssessThreatModelTests` | a model that states no evidence scores exactly what it scores today |
