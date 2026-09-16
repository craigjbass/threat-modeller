# Reading and writing a system's document-control facts in the window

**Status:** approved for implementation, 16 September 2026.

A `system` block states `owner`, `description`, `authors`, `version`,
`created`, `reviewed`, `links`, `repositories` and free-form `attribute`
blocks. The report builds its document-control table from those attributes.
The window neither shows nor writes any of them.

## The problem

- The policy rule `system_requires_owner` fails a project, and the window
  gives no way to write an owner.
- The report says a model is overdue when `reviewed` is more than
  `DocumentControl.reviewIntervalDays` days old, and the window gives no way
  to write a new `reviewed` date.
- Every other attribute is written by hand in the `.arch` file.

## What is not in scope

- No change to the language. `ArchitectureParser` already reads all nine, and
  `ArchitectureWriter` already writes all nine.
- No change to the report table or to the policy rule.
- No new attribute name. The `attribute` block is the place a team states what
  the language does not name.

## The decision

### Where it sits

A section at the top of the architecture column, in `AssumptionsPanel`, above
what the system takes on trust. The panel already holds the facts about the
system the diagram cannot draw, and these are facts of the same kind.

The section is named **What this document states about itself**.

### How a field writes

Every text field is a `DeferredTextField`: it reads the model, and it writes
one change when the edit ends. No form, and no **Save** button, because there
is exactly one set of facts and a form would have to be seeded from the model
and kept in step with it.

`authors`, `links` and `repositories` are lists. Each one is one field, and
the person separates the items with commas. The field shows the list joined
by `", "`.

### How a date writes

`created` and `reviewed` use a `DatePicker`, not a text field. A person cannot
type a date that is not a date.

A date is optional, so each date carries a toggle beside it:

- The toggle off writes an empty string, and the writer writes no line.
- The toggle on writes the picked day.

The picker runs on `Calendar.current`, so the day a person sees is the day
that is written. `CheckGovernance.today(_:)` reads UTC and is for the report,
not for the picker.

### What the use case refuses

`SetSystemFacts` still reads every date with `GovernanceDate.read`. A request
whose `created` or `reviewed` is not `YYYY-MM-DD` returns `.notADate` and
writes nothing at all, so a caller that is not the picker cannot put a date
in the file that the parser then refuses.

### Free-form attributes

`SetSystemAttribute` writes one `attribute` block by name. Writing a name
that is already there changes its value. `RemoveSystemAttribute` takes one
off. The panel lists each attribute with a pencil and a bin, in the shape the
third parties section uses.

### A field that is left alone

Every field of `SetSystemFactsRequest` is optional. Nil states "leave what the
model states". An empty string, or an empty list, clears the attribute and the
writer then writes no line for it. One field writes without the panel having
to send the other eight.

## The parts

| Part | File |
| --- | --- |
| `SetSystemFacts`, `SetSystemAttribute`, `RemoveSystemAttribute` | `modelling/usecase/SetSystemFacts.swift` |
| `ViewedSystemFacts`, `ViewedSystemAttribute` | `modelling/usecase/ViewThreatModel.swift` |
| Change labels | `modelling/gateway/ThreatModelGateway.swift` |
| Session methods | `threatmodeller/ThreatModelSession.swift` |
| The editor | `threatmodeller/sidebar/AssumptionsPanel.swift` |
