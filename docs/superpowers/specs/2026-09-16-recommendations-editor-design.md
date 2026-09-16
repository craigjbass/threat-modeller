# Writing a recommendation in the window

**Status:** decided, 16 September 2026.

## The problem

A `recommendation` block in a `.controls` file says what a team should do
about one threat. `ControlsParser` reads it, `ControlsWriter` writes it,
`RecommendationsReport` builds the report's Recommendations section from it,
and `CompileGovernance` plans work against it. The window writes none of
them, and shows none of them: the word `recommendation` had zero hits in
`threatmodeller/`.

The mitigates sheet writes an edge recommendation on an assumed edge. It
writes the label and the text, and leaves `note`, `blocked_by` and `sources`
unreachable, although `SetMitigatesEdge` already takes all three.

## The decision

### The threat card lists what the file holds

`AssessedThreat` gains a `recommendations` list. `AssessThreatModel` fills it
from `model.recommendations`, the map `ApplyControlAnswers` reads out of the
controls file. `ThreatCard` prints one row per recommendation, with its note
and its sources, under the compensating control row.

### One editor writes, edits and removes a block

`RecommendationsSheet` lists the blocks the threat holds. A person writes a
new one, opens one to edit it, or removes one. The sheet writes through
`WriteRecommendation` and `RemoveRecommendation`, the disk-backed use cases,
the way `WriteImpacts` writes an `impacts` list: read the `.controls` file,
change one threat's recommendation list, write every other block back
unchanged.

### The text names the block

A `recommendation` block carries no id. `CompileGovernance` already matches a
planned work item to a recommendation by its text, so the text names the
block here too. A write states the text it replaces, or nil for a new block.
Two blocks on one threat may not say the same text, because a second one
would name the same planned work item.

`WriteRecommendation` refuses a block with no text, and refuses a replacement
whose text another block on the same threat already holds.

### The mitigates sheet writes the three missing fields

`MitigatesSheet` gains a note field, a sources field and a blocked-by picker.
The picker lists the assumptions the system declares, because
`ArchitectureParser` drops an action whose `blocked_by` names an assumption
no `assumption` block declares. `ViewedMitigation` carries the three fields
back, so opening the sheet again shows what the edge holds.

### Where the code sits

| File | What it holds |
| --- | --- |
| `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/WriteRecommendation.swift` | `WriteRecommendation` and `RemoveRecommendation`, and the `ControlsFile.changing(_:recommendationsTo:)` helper |
| `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift` | `AssessedRecommendation`, and the list on `AssessedThreat` |
| `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/ViewThreatModel.swift` | `actionNote`, `actionBlockedBy` and `actionSources` on `ViewedMitigation` |
| `threatmodeller/sidebar/RecommendationsSheet.swift` | the editor |
| `threatmodeller/sidebar/ThreatCard.swift` | the list of blocks and the button that opens the editor |
| `threatmodeller/project/ProjectSession.swift` | `writeRecommendation`, `saveRecommendation`, `removeRecommendation` and `deleteRecommendation` |
| `threatmodeller/canvas/MitigatesSheet.swift` | the note field, the sources field and the blocked-by picker |

A window with no project offers no editor, the same as `onDecideSeverity`:
there is no `.controls` file to write.
