# A list of component ids is picked with tokens, not a menu

**Status:** decided, 18 September 2026. Issue #179.

## The problem

The user panel draws `Uses` and `Reaches` as a `Menu` of one `Toggle` per
component. A macOS menu closes on every pick, so a person who wants three
clients opens the menu three times. A menu with a tick per row reads as one
choice, not a set. The component panel draws `Holds` the same way, with the
same fault. Neither field shows at all when the system holds no component or
no asset yet, so a person who makes the user first sees no control at all.

`MitreIdField` (issue #148) already solves the same shape of problem for
ATT&CK ids: tokens in a field, a search that stays open, one pick at a time,
no menu. `Uses`, `Reaches` and `Holds` need the same control over a fixed list
of named choices instead of a live ATT&CK search.

## The decision

### One control: `IdTokenField`

`threatmodeller/canvas/IdTokenField.swift` draws the control. It takes:

- `identifier`: the accessibility identifier of the field. Every derived
  control builds its identifier from this word, the way `MitreIdField` does.
- `ids`: a `Binding<[String]>`, the list the field writes.
- `choices`: every `IdTokenField.Choice` the field may add: an id, a name and
  an SF Symbol name for the token's icon.
- `emptyMessage`: what the field says in place of the control when `choices`
  is empty.

A chosen id draws as a token: the icon, the name, and a remove button. An "Add…"
button opens a search box and the list of choices not yet chosen. The list
stays open after a pick, so a person picks several choices before closing it.
Closing clears what was typed. This differs from `MitreIdField`, whose list
only shows while a person is typing a match: `MitreIdField` searches a few
hundred ATT&CK rows, so a list with nothing typed would be a wall of items.
`IdTokenField` opens on a fixed set the user already narrowed by system, so
the whole list shows even before a person types.

### The icon a token draws

- A component choice's icon comes from its shape: `person.fill` for an actor,
  `cylinder.fill` for a store, `circle.fill` for a process.
- An asset choice's icon is fixed: `archivebox.fill`. An asset carries no
  shape of its own.

### Where it replaces the menu

- `UserPanel`'s `Uses` and `Reaches` fields draw `IdTokenField` over every
  component that is not a user. Both fields show even when the system holds
  no such component, with "No component to pick yet. Add one on the canvas."
  in place of the control.
- `ComponentPanel`'s `Holds` field draws `IdTokenField` over the system's
  named assets. It shows even when the system holds no asset, with "No asset
  to pick yet. Add one in Assets." in place of the control.
- The palette gesture from issue #178, a technology dropped onto a user, still
  writes `uses` through `ThreatModelSession.addClient`. The token appears the
  next time the panel draws, because the panel reads `session.canvas` fresh
  on every render; no control here changes for the gesture to keep working.

### `faces`, left as it draws today

The system's `faces` list already avoids the fault this issue fixes.
`ThreatActorsSheet` draws every threat actor as a row with a checkbox, in a
sheet that stays open for as long as a person leaves it open; ticking one row
never closes the sheet, so a person ticks as many actors as they like without
reopening anything. The sheet also carries columns `IdTokenField` has no room
for: capability, intent and a search over roughly 180 synchronised ATT&CK
groups. Moving `faces` to `IdTokenField` would lose those columns for no gain,
so `faces` keeps its own control. `WindowModelParityList` still names
`faces-` as the identifier that writes it.
