# The governance file — implementation plan

Date: 2026-09-14
Spec: `docs/superpowers/specs/2026-09-13-governance-file-design.md`
Status: delivered

## Order of work

1. **The date.** `assessment/domain/GovernanceDate.swift`: a calendar date
   written `YYYY-MM-DD`, its parser and the two messages of section 3.5. It is
   a pure value, so it is written and tested before anything reads a file.
2. **The value tree.** `architecture/domain/GovernanceSource.swift` and
   `architecture/gateway/GovernanceSourceGateway.swift`.
3. **The language.** `ArchitectureDSL/GovernanceParser.swift`,
   `GovernanceWriter.swift` and `HclGovernanceSource.swift`. The parser gives
   every message of section 3.5 word for word, and a rewrite of an unchanged
   file produces no diff.
4. **The project.** `ProjectConvention.governanceExtension`,
   `ProjectSystem.governancePath`, and `system(atPath:)` opening a project
   from a `.governance` file.
5. **The compile.** `architecture/usecase/CompileGovernance.swift`, following
   the seven rows of section 4. It reads the compiled `ControlsSource` and the
   model's actions, so what it writes and what `check` reads can never
   disagree.
6. **The check.** `architecture/usecase/CheckGovernance.swift`, the four
   failures of section 5, against `Clock`. `CheckControlAnswers` calls it and
   carries the failures.
7. **The report.** `ReportAcceptedRisk` and the governance fields;
   `MarkdownAcceptedRisks`; the governance line in `MarkdownRecommendations`
   and in `MarkdownLeverage`; the overdue count in the executive summary; the
   section placed after `## Recommendations`.
8. **The command line.** `compile` writes the file, `check` reads it, and both
   take it in every format `--format` names.
9. **The application.** Two read-only lines on `ThreatCard`, and
   `ProjectSession` following the third file.
10. **The documentation.** `docs/LANGUAGE.md` gains the governance language,
    and the README states the two migration steps.

## The migration this forces

A project that accepts a risk today and holds no `.governance` file fails
`check` the first time it runs after this change. The fix is two steps, stated
in the README and in the release note: run `threatmodeller compile`, then fill
in the owner and the review date in each stanza the compile wrote.

## What this plan leaves out

Document control, evidence tiers on a control note, any change to how a score
is computed, and any editor in the application. Section 2 of the design states
each one as out of scope.
