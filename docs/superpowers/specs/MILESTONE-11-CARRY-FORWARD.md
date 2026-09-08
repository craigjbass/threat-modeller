# Carry-forward after Milestone 10B

The code-first line is complete: a team writes `.arch`, a compiler writes
`.controls`, a person answers it, and the application, the report and
continuous integration all read the same two files.

## Closed in Milestone 10B

- The controls language, its parser, its writer and its shared contract.
- `ControlStatus` and `CompensatingControl` in the model, and the scoring order
  of spec §5: base, override, zone, pathway, then compensation, applied last
  and multiplicatively, with the stronger of two rather than the sum.
- Document format version 3, which reads versions 1 and 2.
- `CompileControls`, the merge that never deletes an answer.
- `ApplyControlAnswers` and `CheckControlAnswers`.
- The report: a status beside each control, what compensated a threat and what
  it bought, and the controls counted by status.
- `compile`, `check` and `report` in the executable, and an Ubuntu job that
  runs the whole line.
- The four-way status control, the compensating sheet, a save that merges the
  answers on screen into the controls file, and `Compile Report`.

## New in Milestone 10B

1. **A threat card can hold only one compensating control from the interface.**
   The model and the file hold a list; the sheet writes one. A person who wants
   two writes them in the file.

2. **The compensating sheet does not read back the percent or the rationale.**
   It reads back the label. Opening it on an existing compensating control
   shows 40 percent and an empty rationale until the person types.

3. **`SaveSystemAnswers` resolves the model twice**: once inside
   `CompileControls` and once to read the statuses on screen.

4. **Nothing writes a `note` from the interface.** The file holds one per
   control, the report does not print it, and the sidebar cannot set it.

5. **A stale answer is invisible in the application.** The file keeps it, the
   executable reports it, and the sidebar says nothing.

6. **`check` counts a threat as answered when one control is answered.** A
   threat with ten controls and one `accepted` passes. Whether that is the right
   rule is a question for a user, not a defect.

7. **The interface journey reads the summary, not a threat card.** Cards scroll,
   and an off-screen card is not in the accessibility tree, so the journey
   asserts "1 of 39 controls in place" rather than the card's own text.

8. **The severity and the score in a controls file are written but never read.**
   A person who edits them changes nothing, as the file says.

9. **`report` in the executable builds one composition root per system**, so a
   project of twenty systems parses the catalogue once but resolves twenty
   times, unmeasured.

## Standing

- The zone-drag undo defect of Milestone 6B, and the interface journey that no
  longer walks an undo.
- Everything in `MILESTONE-10B-CARRY-FORWARD.md`: no directory watching, no
  app-scoped bookmark, one project window, `OpenProject` reading the directory
  twice, warnings without a line number, and `format` rewriting whole files the
  first time it is run.
- The older lists in `MILESTONE-10-CARRY-FORWARD.md`, less the sensitivity gap,
  which Milestone 9 closed.
