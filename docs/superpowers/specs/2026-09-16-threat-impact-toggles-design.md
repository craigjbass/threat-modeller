# Toggling a threat's impacts on the threat card

**Status:** decided, 16 September 2026.

## The problem

A `threat` stanza's `impacts` attribute states what the threat harms:
confidentiality, integrity, availability. A threat that states none reads as
the STRIDE default (`ThreatImpact.derived`). `ThreatCard` shows the impacts
as chips and `ThreatFilter` reads them, but nothing in the window writes
`impacts`. A team that wants its own answer edits the `.controls` file by
hand.

## The decision

### The chips become toggles

`ThreatCard` shows one chip per `ThreatImpact` case (confidentiality,
integrity, availability), not only the impacts a threat currently states. A
filled chip is on; an outlined chip is off. A tap toggles that one impact and
writes the full three-item state as one list, through `WriteImpacts`, the
disk-backed writer, the way `WriteSeverityDecision` writes a
`severity_override` block: read the `.controls` file, change one threat's
`impacts` list, write every other block back unchanged.

### Turning off the last chip is refused

`ThreatResolver` and `ApplyControlAnswers` both read an empty `impacts` list
the same way they read a missing one: `impactsOverride.isEmpty ? threat.impacts
: impactsOverride` falls back to the STRIDE default the moment the override
is empty. A written empty list is not "this threat harms nothing" — it is
"this threat states no override", so the file would show three chips off and
the model would still show the STRIDE default on the next read. That
mismatch is worse than not letting the write happen.

`WriteImpacts` refuses a request whose list is empty, with the reason "a
threat needs at least one impact". The card disables the last remaining
chip's toggle, so a person cannot press a control that does nothing.

### Where the code sits

| File | What it holds |
| --- | --- |
| `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/WriteImpacts.swift` | the use case, and the `ControlsFile.changing(_:impactsTo:)` helper it shares with `WriteSeverityDecision` |
| `threatmodeller/sidebar/ThreatCard.swift` | the chips, now toggles |
| `threatmodeller/project/ProjectSession.swift` | `writeImpacts` and `saveImpacts`, the same shape as `writeSeverityDecision` and `saveSeverityDecision` |
| `threatmodeller/sidebar/ThreatSidebar.swift` | wires the card's toggle to the project, the way it wires `onDecideSeverity` |

A window with no project offers no toggle, the same as `onDecideSeverity`:
there is no `.controls` file to write.
