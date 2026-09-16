# The System menu and the sheets it opens

**Status:** approved for implementation, 16 September 2026.

This design sorts the ten editors of the architecture sidebar into two groups.
It states the rule that decides the group, the one shape every moved editor
gets, the menu and the toolbar control that open them, and the badge each menu
item shows.

## The problem

`threatmodeller/sidebar/AssumptionsPanel.swift` is 845 lines and one scrolling
column of ten editors. Each editor holds a list, an add form, a pencil and a
bin. A person modelling the architecture scrolls past nine add forms to reach
the assumptions, which is the one section the stage is for.

Most of the ten are written once per system and read rarely: the document's
owner, its version, the third parties, the pictures beside the diagram. They
are not part of drawing the system and do not belong beside the canvas.

Threat actors already take the wanted shape. A toolbar control opens
`ThreatActorsSheet`, and the sidebar holds nothing for them.

## What is not in scope

- No change to the language. Every sheet writes the same blocks the panel
  wrote, through the same use cases.
- No change to `GovernanceSheet` or `RecommendationsSheet`. Those two edit one
  stanza of one threat, reached from a threat card, not a fact about the
  system.
- No new field. A moved editor keeps the fields it had.

## The rule

An editor stays in the architecture sidebar when **either** of these holds:

1. **It holds no add form.** The section is a read-only list, or one picker.
   Such a section costs the column one row, and a menu item plus a sheet to
   save one row is a worse trade.
2. **Its add form writes a fact about the parts the canvas draws.** A person
   types it while looking at the diagram, and the words name a component, a
   flow, a zone, or what the diagram cannot draw about those same parts.

An editor moves to a sheet when **neither** holds: the editor has an add form,
and that form states a fact about the document or about the system as a whole
rather than about the parts the canvas draws.

The rule is one question with a yes or a no, so the next editor lands in a
group without a debate.

### The ten editors, sorted

| Section heading | Add form | About the drawn parts | Group |
| --- | --- | --- | --- |
| What this system takes on trust (assumptions) | yes, 3 fields | yes | sidebar |
| What one component lowers on another (mitigates) | no | yes | sidebar |
| Risk tolerance | no, one picker | no | sidebar |
| What this system holds (assets) | yes, 4 fields | no | sheet |
| What this document states about itself | yes, 8 fields | no | sheet |
| Anything else this document states (attributes) | yes, 2 fields | no | sheet |
| Pictures this system keeps beside its diagram | yes, 2 fields | no | sheet |
| Who outside this team this system depends on | yes, 9 fields | no | sheet |
| What a person does with this system (use cases) | yes, 2 fields | no | sheet |
| What this model does not cover (exclusions) | yes, 3 fields | no | sheet |
| Threat actors (already a sheet) | yes, 8 fields | no | sheet |

The document-control fields and the free attributes are one sheet, because both
write what the document states about itself and a person writes them in one
sitting. That gives seven sheets.

### What the sidebar keeps

The sidebar draws, in this order:

1. **What this system takes on trust**: the assumption list, then the add form.
2. **Risk tolerance**: the four-level picker.
3. **What one component lowers on another**: the mitigates list, read only,
   drawn only when the model holds one.

The assumptions come first because the stage is for them. The header then sits
at the top of the column and is visible with no scroll at every window height.

## The sheet shape

`ThreatActorsSheet` wins the outer frame. `RecommendationsSheet` wins the rows
and the buttons. `GovernanceSheet` loses on width: a fixed 480 points holds a
form and no list.

One container, `SystemSheet`, draws every System sheet:

```
+--------------------------------------------------------------+
| Title                                                        |
| One sentence that says what this states.                     |
+---------------------------+----------------------------------+
| the list                  | the form                         |
| one row per entry,        | the fields, then Add or Save     |
| each with Edit and Remove |                                  |
+---------------------------+----------------------------------+
| This writes payments.arch.        [ Close ]  [ Add ] / [ Save ] |
+--------------------------------------------------------------+
```

- The list is on the left, in its own scroller, at 300 points wide.
- The form is on the right, and takes the rest.
- Each list row holds **Edit** and **Remove**, in that order, at its trailing
  edge. Edit reads the row into the form. Remove takes the entry off.
- The form's write button reads **Add** while the form writes a new entry, and
  **Save** while the form holds a row a person opened with Edit.
- **Close** carries `.cancelAction`, so Escape closes the sheet.
- The write button carries `Cmd+S`, so a person saves with the key the rest of
  the application saves with.
- The footer states the file the sheet writes, by name.
- The frame is `minWidth: 760, minHeight: 520`.

A sheet holds no Cancel: every write goes straight through the use case and the
model, the way the panel wrote, and the project's own save writes the file. The
sheet states the file so a person knows which one changed.

## The System menu

A `CommandMenu("System")` in the menu bar. The title is **System**, which no
standard macOS menu uses. Issue #153 states that `CommandMenu("View")`
duplicates the standard View menu; the new menu must not repeat that fault.

The same rows sit under one toolbar control, a menu button labelled **System**.
The rows are a value, `SystemMenu.rows`, and `ElementMenuView` draws them in
both places, so the two entry points cannot drift. This is the pattern
`ElementMenu` and `TreeMenu` already use.

The seven items, in this order:

| Item | Sheet | What it counts |
| --- | --- | --- |
| Document Control… | `DocumentControlSheet` | the attributes the document states |
| Assets… | `AssetsSheet` | `system_asset` blocks |
| Third Parties… | `ThirdPartiesSheet` | `third_party` blocks |
| Use Cases… | `UseCasesSheet` | `use_case` blocks |
| Exclusions… | `ExclusionsSheet` | `exclusion` blocks |
| Diagrams… | `DiagramsSheet` | `diagram` blocks |
| Threat Actors… | `ThreatActorsSheet` | the actors this system faces |

Every item is off while no system is drawn.

### The badge

Each item's title ends with the count the model holds, after an en space:

- `Assets  3` when the model holds three assets.
- `Assets  —` when the model holds none.

Document Control counts the nine named fields the document states plus the free
attributes, so a document that states nothing shows a dash and a document that
states an owner alone shows 1.

Threat Actors counts the actors the system faces, not every actor the project
holds, because the `faces` list is what this system states.

## Where the state lives

`ProjectSession` holds `systemSheet: SystemSheetKind?`. A menu row writes it, a
toolbar row writes it, and `ProjectWindow` presents the sheet for it. The state
is on the session rather than in the view, so a test runs a row and reads which
sheet opened.

## The tests

- One test per sheet: run the row from the menu, run the row from the toolbar,
  write one entry through the sheet's own verb, save, and read the file back.
- A `ViewRenderTests` pixel test draws the sidebar and states the assumptions
  header sits inside the first 640 points.
- A `WindowLayoutTests` test states the sidebar's content height fits the
  column the default window height gives it, for a model with one assumption
  and one mitigates edge.
- A test states each badge equals the count the model holds.
- Every flow test for a moved editor keeps its writes and its reads, and points
  at the sheet instead of the panel.
