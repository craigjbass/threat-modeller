# Reading and writing threat actors in the window

**Status:** approved for implementation, 16 September 2026.

This design adds the view and the editor that
`2026-09-13-threat-actors-design.md` section 2 put out of scope. That
document states the language, the score rule and the report. Nothing here
changes any of the three.

## The problem

`threatmodeller actors list [--mitre]` says which threat actors a project may
face, and how much of the catalogue each one touches. The window says almost
nothing:

- `listThreatActorsInUse()` is built in `threatmodeller/Dependencies.swift`
  and no view calls it.
- A threat card holds one read-only **Performed by** line.
- A `faces` list and a local `threat_actor` block are written by hand in the
  `.arch` file. The window neither shows them nor writes them.

A person who wants to state which adversaries a system faces leaves the
window and edits the file. The `faces` list sets the likelihood of every
threat at once, so it is the one line in the file with the widest effect on
the score.

## What is not in scope

- No change to the language. `docs/LANGUAGE.md` states what `faces` and
  `threat_actor` are, and the window writes that file and nothing else.
- No editing of a library actor. A library is a vendored file, and the way to
  change an imported actor is a local block that overrides it, which is
  section 3.2 of the 13 September design.
- No change to the score rule of section 4.2 of that design.
- No new ATT&CK download. The window lists the groups already on this
  machine.

## The decision

### Where it sits

A sheet, opened from the project window's toolbar, named **Threat Actors**.
It sits beside **Attack Trees** and **Planned Work**, which are the other two
sheets that write one part of the model.

The toolbar, rather than the architecture column, because the list holds every
ATT&CK group on this machine. That is about 180 rows, and the architecture
column is 280 to 480 points wide.

The sheet holds two parts:

- **The actors this project may face**, as a list.
- **An actor this system declares**, as a form, in the shape the assumptions
  panel already uses: the rows above, the fields below, one **Add** button.

### What one row states

| Column | Where it comes from |
| --- | --- |
| Faces | a tick, which writes the `faces` list |
| Name | the actor's `name` |
| Capability | the actor's `capability`, as the tier's own label |
| Intent | the actor's `intent` |
| Threats performed | the threats the actor performs, by name |
| MITRE groups | see below |

**Threats performed** reads `ActorLikelihood.performers`, which is the rule
the score already applies. So an actor that states `performs_catalogue_tier`
lists every threat the catalogue marks at that tier, and an actor that states
a technique lists every threat that names that technique's parent.

**MITRE groups** answers "which ATT&CK groups are this actor?". An actor
whose id starts with `mitre-` is a group already, so the column states that
actor's own name. Every other actor states the groups that use a technique it
uses, most shared techniques first. A team that writes its own actor then
reads which named intrusion sets work the same way.

The column states group names, not ATT&CK group ids. A `ThreatActor` carries
the group's name and its aliases, and no `G` number.

An actor that performs no threat this model raises still appears in the list,
because a person picks from what exists, not from what is already in use.

### What a person does

| Control | What it writes |
| --- | --- |
| the tick on a row | the actor's id into `faces`, or out of it |
| **Add** under the form | a `threat_actor` block in this `.arch` file |
| **Delete** on a local row | that `threat_actor` block |

The form takes an identifier, a name, a capability picked from the three
tiers, an intent, a list of threat ids and a list of technique ids. Writing
the same identifier again changes the block that is there, which is the rule
every other write use case in this application applies.

Deleting a local block also takes its id out of `faces`, but only when no
library actor and no ATT&CK group holds that id. A local block that overrides
a library actor leaves a `faces` entry that still resolves.

### What writes the file

Three use cases, each one a write to the model:

| Use case | What it changes |
| --- | --- |
| `SetFacedThreatActors` | `model.facedActorIds` |
| `SetLocalThreatActor` | one entry of `model.localActors` |
| `RemoveLocalThreatActor` | one entry of `model.localActors`, and `faces` |

The save then writes the `.arch` file through `ExportArchitecture` and
`HclArchitectureSource`, the way every other change to the architecture is
written. No view edits the text of the file.

### The fault this uncovers

`ArchitectureSourceBuilder.source(from:)` builds the source a save writes, and
it sets neither `faces` nor `threatActors`. A model read from a file that
states them, and then saved, loses both. The parser reads them, the writer
writes them, and the builder between the two drops them.

This design fixes the builder. It is the same fix the editor needs, because
an editor that writes to the model and no further writes nothing to disk.

### The refusals

| Check | Message |
| --- | --- |
| a `faces` entry naming no actor | `This project holds no threat actor called "<id>".` |
| a local block with no identifier | `A threat actor needs an identifier.` |
| a local block with no name | `A threat actor needs a name.` |
| a capability outside the three tiers | `A capability is commodity, targeted or research.` |
| a catalogue tier outside the three tiers | `A catalogue tier is commodity, targeted or research.` |
| a delete naming no local block | `This system declares no such threat actor.` |

The first one matters: the parser states the same fault as an error that stops
the project opening, so the window must never write a `faces` entry that the
next open refuses.

## The code

| File | Change |
| --- | --- |
| `attack/usecase/ListThreatActorsInUse.swift` | reads the model, counts by `ActorLikelihood`, states intent, threat names, MITRE groups, faced and local |
| `modelling/usecase/SetFacedThreatActors.swift` | new |
| `modelling/usecase/SetLocalThreatActor.swift` | new, with the remove verb |
| `modelling/gateway/ThreatModelGateway.swift` | three change labels |
| `architecture/domain/ArchitectureSourceBuilder.swift` | writes `faces` and `threat_actor` |
| `UseCaseFactory.swift` | three verbs |
| `threatmodeller/Dependencies.swift` | wires them |
| `ThreatModelKit/Sources/TestSupport/TestDependencies.swift` | wires them |
| `threatmodeller/ThreatModelSession.swift` | the list and the three writes |
| `threatmodeller/project/ThreatActorsSheet.swift` | new |
| `threatmodeller/project/ProjectWindow.swift` | the toolbar control and the sheet |

## Testing

| Test | Says |
| --- | --- |
| `ThreatActorsInUseTests` | a listed actor states capability, intent, the threats it performs and its MITRE groups |
| | an actor that states `performs_catalogue_tier` lists the threats of that tier |
| | a local block overrides a catalogue actor of the same id, whole |
| | the faced actors sort first |
| `SetThreatActorsTests` | `faces` writes, and refuses an id nothing holds |
| | a local block writes, changes on a second write, and deletes |
| | a delete takes the id out of `faces` when nothing else holds it |
| | a model with `faces` and a local block round trips through the writer |
| | the list says what `threatmodeller actors list --mitre` prints |
| `ThreatActorEditorFlowTests` | the window lists the actors, ticks one, and writes a local block |
| | a written `faces` line leaves every other block where it was |
| | the parser reads a written block back with the same fields |
| | the sheet says so when the system faces nobody |
| | the threat card names the actor that performs the threat |
