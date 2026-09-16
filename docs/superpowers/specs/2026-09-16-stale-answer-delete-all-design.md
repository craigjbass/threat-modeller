# Deleting every stale answer at once — design

Date: 2026-09-16
Status: approved for planning

## 1. Why

Issue #115 asks for a "Delete all" control on the stale answers panel, and a
confirmation sheet that lists what each stale stanza holds before the delete
runs. The issue leaves one question open: whether the existing single-row
Delete button should show the same confirmation sheet with one row, or stay a
single click with no sheet.

## 2. The decision

The single-row Delete button stays a single click. Only "Delete all" opens
the confirmation sheet.

## 3. Why

A row already states what a person needs before they click its own Delete
button: the threat id, the source, and the control count sit in the row
itself. A sheet under a single row would repeat what the row already says,
in a second window a person has to close.

"Delete all" is a different kind of decision. It removes every stale stanza a
system holds in one action, and a system whose architecture changed a lot can
hold many. A person clicking through rows one at a time sees each stanza as
they delete it; a person who presses one button sees none of them unless the
application shows what it is about to do. The sheet is what "Delete all"
needs to be as safe as clicking through the rows one at a time.

## 4. What this means for the tests

The existing single-row delete tests (`AnalystFlowTests.deletesOneAnswerAPersonSaysToDelete`,
`CheckSummaryTests.rereadsTheSummaryWhenAStaleAnswerIsDeleted`, and the row's
own `Button("Delete", role: .destructive)`) stay exactly as they read today.
The new sheet and its "Delete all" button are additions, not a replacement
for the row's own control.
