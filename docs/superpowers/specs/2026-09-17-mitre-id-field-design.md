# A MITRE id is picked by search, not typed from memory

**Status:** decided, 17 September 2026. Issue #148.

## The problem

Every place the window takes a MITRE ATT&CK id is a plain text box. The threat
actors sheet reads `TextField("Technique ids, separated by a comma", text:
$draft.techniques)`, so a person types `T1190, T1078` from memory. Nothing
states whether the id exists, nothing names the technique beside the id, and a
person who knows the name and not the id has no way to find it.

The data is already on the machine. `SynchroniseAttack` writes `groups.json`
and `techniques.json` into the data directory, and `MitreActorSource` reads
both.

## The decision

### One use case searches the data

`ThreatModelKit/attack/usecase/SearchAttackData.swift` reads the synchronised
data through `MitreActorSource` and answers the rows that match.

| Type | What it holds |
| --- | --- |
| `AttackSearchKind` | `technique` or `group` |
| `AttackSearchRow` | `id`, `name`, `isSubTechnique` |
| `SearchAttackDataRequest` | `text`, `kind`, `limit` |
| `SearchAttackDataResponse` | `rows`, `holdsData` |

A technique row's id is the ATT&CK technique id, `T1190` or `T1059.001`. A
group row's id is the ATT&CK group id, `G0046`.

The rank of a row, best first:

| Rank | The text matches |
| --- | --- |
| 0 | the whole id |
| 1 | the start of the id |
| 2 | the start of the name |
| 3 | any part of the name |
| 4 | any part of an alias |

Two rows of one rank sort by id. The rank is a total order over the rows, so
the same text gives the same list every time.

`holdsData` is false when this machine holds no row of that kind, which is what
a machine that has never synchronised reads.

`MitreActorSource` gains `groups()` and `techniques()`. Both read the file the
first time something asks and keep what they read, so a search costs one parse
per run of the application and a filter per keystroke.

### One control takes every MITRE id

`threatmodeller/project/MitreIdField.swift` draws the control.

- A text box takes what a person types. Each keystroke calls the use case and
  the rows draw under the box, id and name in each row.
- Clicking a row adds the id as a token. A list field holds many tokens; a
  single field holds one, and a second pick replaces the first.
- A token states the id, names the technique or the group on hover, and comes
  off with the cross beside it or with the Delete key.
- Return adds what is typed as a token, whatever the data holds. An id the data
  lacks is kept and marked unknown, and the field states that the id is not in
  the synchronised matrix. A library may state a technique the matrix version
  on this machine does not, and the file must round trip.
- With no synchronised data the box still takes an id by hand, and the field
  states how to synchronise and draws the button that runs it.

The control writes `[String]`: the same `techniques = [...]` list the parser
reads today, ids only.

`ThreatModelSession` gains `searchAttackData(_:kind:)`, which calls the use
case, and `onSynchroniseAttack`, which `ProjectSession` sets when it builds the
model. The window's one synchronise path stays in `ProjectSession`.

### Where the control is used

`ThreatActorsSheet` writes the local `threat_actor` block's `techniques` list
through the control. `Draft.techniques` becomes `[String]`, and the control
keeps the accessibility identifier `threat-actor-techniques`, so the parity
list is unchanged.

No other window field takes a MITRE id today. `MitreIdFieldTests` reads every
Swift file under `threatmodeller/` and states that no plain text box names a
MITRE id, so a field added later fails the test until it takes the control.
