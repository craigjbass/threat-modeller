# The `user` block

**Status:** decided, 16 September 2026.

## The problem

A person on the diagram is a technology. `actor-user`, `actor-admin` and
`actor-attacker` in `Resources/Actors/actors.json` are palette entries with
the category `person`, and a component made from one holds a technology, a
sensitivity and a `runs_as` the way a database does.

A `threat_actor` block states who attacks the system. It is not on the
diagram.

The two overlap. An insider is a user of the system and a threat actor at
once, and the model has no way to say that one element is both.

## The decision

### The block

A `user` block declares a human who uses the system.

```hcl
user "alice" {
  name         = "Alice"
  role         = "Operator"
  access       = "admin"
  reaches      = ["api", "ledger"]
  threat_actor = "insider"
}
```

| Attribute | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | the label | what the canvas and the report call the user |
| `role` | string | empty | what the person does with the system |
| `access` | string | `user` | the privilege the user holds on what the user reaches: `user`, `admin`, `root`, `system` or `kernel`, the words `runs_as` takes |
| `reaches` | list of strings | empty | the component ids the user reaches |
| `threat_actor` | string | none | the id of a threat actor this user is |

The label is the user's id. A user and a component share one namespace,
because a flow names either one at an end. A user block sits at the top
level of a system or of a part file, never inside a zone.

`access` takes the words `runs_as` takes, so a flow between a user and a
component with a different privilege is a privilege crossing, the way a flow
between two components is. The word `kernel` is allowed and is not
meaningful for a person; the vocabulary is one list, not two.

`reaches` states which components the user has access to. It is a statement
for the report; it draws no flow and changes no score. A flow between the
user and a component is written the way every flow is written, and a reach
with no flow is not a fault.

### How a user differs from an `actor-*` technology component

| | a `component` with `technology = "actor-user"` | a `user` |
| --- | --- | --- |
| what it is | a technology from the actors library | a human, with no technology |
| threats it raises | the technology's threats: none today | none |
| `data`, `holds`, `asset`, `status`, `provided_by`, `shape` | stated | not stated |
| privilege | `runs_as` | `access` |
| zone | nests in a zone | sits in no zone |
| threat actor | cannot be one | states `threat_actor = "<id>"` |
| shape on the canvas | the actor shape, from the provider | the actor shape, always |
| palette | under External Actors | under Users |
| report | the component table | the Scope section |

A file that holds `actor-user`, `actor-admin` or `actor-attacker` components
reads and writes unchanged. Nothing converts a component into a user, and
the actors library keeps every entry it has. A team that wants the insider
statement writes a `user` block.

### Identity

A user's id is its label, with no prefix. The parser refuses a user
declared twice with `the user "<id>" is declared twice`, and a user whose id
is also a component id with `"<id>" is declared as a component and as a user`.
The merge of a split system refuses the same two faults across files, naming
both files.

### The threat actor a user is

`threat_actor = "<id>"` names an actor a `threat_actor` block in a `.arch`
file or a `.lib` file declares, or the bundled `commodity-crimeware` actor.
The check runs in `ImportArchitecture`, the way the `faces` check runs, because
only the import knows the libraries. An id nothing declares is the error
`the user "<id>" names the threat actor "<actor>", which no threat_actor block
declares`, and the project does not open.

A user that names an actor is faced. `ThreatActorLookup` reads the faced ids
as `faces` first, then every user's `threat_actor`, in model order, with a
repeat dropped. Every reader of the lookup then sees the insider:

- the likelihood rule of the threat actors design, section 4.2, so a threat
  the insider performs takes the insider's capability;
- the report's Threat actors section, which lists the insider with the
  faced actors;
- the actors sheet in the window, which shows the actor as faced.

`faces` need not repeat the id. A `faces` entry that repeats it is not a
fault. To stop facing the actor, take the `threat_actor` line off the user,
because the sheet's toggle writes `faces` and `faces` is not what faces it.

### The domain

A user is a `Component` in the model, so every use case that moves, selects,
connects, copies, deletes and undoes a component reads a user the same way.
`Component` gains one field:

```swift
public var user: UserFacts?

public struct UserFacts: Equatable, Sendable {
    public var role: String
    public var reaches: [String]
    public var threatActorId: String?
}
```

A user component states `technologyId` as `Component.userTechnologyId`, the
word `user`, which no catalogue holds, so `TechnologyLookup` finds nothing and
the resolver raises nothing for it. The resolver skips a user component by
its `user` field, not by the lookup, so a custom technology that happens to be
called `user` raises nothing on a user either. The user's `name` is
`customName`, and `access` is `runsAs`.

A user sits in no zone. `Component.zoneId` reads nil for a user, whatever
rectangle the canvas draws the user inside, so a drag into a zone changes no
score and the file writes no zone.

`RemoveComponents` takes a removed component's id off every user's `reaches`,
so a save never writes a reach the next open refuses. A pasted user keeps the
reaches that name a pasted component and drops the rest.

### The palette

The palette lists a Users section above the technologies, with one row,
User. The row drags onto the canvas and answers a double-click the way a
technology row does. The drop and the double-click call `AddUser`, which
adds a user component named User at the drop point with no role, `user`
access, no reaches and no threat actor. The save writes a `user` block and
no `component` block.

### The canvas

The canvas draws a user with the actor shape, always. `ViewThreatModel`
states `shapeId` as `actor` for a user, and `isUser` as true, so the node
view and the diagram exports draw it without a second rule.

The chip row under a user reads `USER`, the role when the user states one,
the access level, and a Threat actor chip when the user names one. That row
is the mark that tells a user from a technology drawn with the actor shape.

The panel under the canvas for a selected user is `UserPanel`: a Name field,
a Role field, an Access picker, a Reaches menu with one toggle per component
that is not a user, and a Threat actor picker listing every actor the project
holds. Every control writes through `SetUserProperties`, which refuses an
access word outside the five, a reach naming no component and an actor
nothing declares.

### Flows

A flow to or from a user is written the way every flow is written:

```hcl
flow alice -> api
```

The parser and the merge accept a user id at either end. The connection
threats apply to the flow the way they apply to a flow from an `actor-user`
component, because the flow is the same flow.

### The report

The Scope section gains a Users list after the use cases and before the
exclusions. A system that states a user writes the section, so a reader
sees who uses the system beside what they do with it.

```markdown
### Users

- Alice (Operator, Administrator): reaches API and Ledger; is the threat actor Disgruntled operator
- Bob (Customer, User): reaches nothing
```

The component table does not list users, the executive summary's component
count does not count them, and the JSON, OTM and threatcl exports do not list
them. A flow to a user names the user in the flow tables.

### The writer

The writer writes the `user` blocks after the top-level components and
before the flows. Inside a block the attribute order is the order of the
table above. An attribute holding its default writes no line, so a user with
no role writes no `role` line.

A split system keeps each user in the file its block came from, with
`BlockOrigin.user`. A user added in the window goes into the header file.

### The language server

A `user` block completes `name`, `role`, `access`, `reaches` and
`threat_actor`. A flow completes user ids beside component ids, and go to
definition finds a `user` block the way it finds a `component` block.

### The errors

| Fault | Message | Where |
| --- | --- | --- |
| an entry the block does not hold | `a user holds name, role, access, reaches and threat_actor, not "<word>"` | the parser |
| an access word outside the five | `access is "<word>"; this application holds "admin", "kernel", "root", "system", "user"` | the parser |
| a user declared twice | `the user "<id>" is declared twice` | the parser, or the merge naming both files |
| a user id that is a component id | `"<id>" is declared as a component and as a user` | the parser, or the merge naming both files |
| a reach naming no component | `the user "<id>" reaches "<component>", which this file does not declare` | the parser's whole-file check |
| the same, in a split system | `the user "<id>" reaches "<component>", which this system does not declare` | the merge |
| a threat actor nothing declares | `the user "<id>" names the threat actor "<actor>", which no threat_actor block declares` | `ImportArchitecture` |

## What this design does not do

- It does not convert an `actor-user` component into a user, and it does
  not remove the three person entries from the actors library.
- It does not put a user in a zone.
- It does not let a user hold an asset or state a sensitivity.
- It does not make `reaches` draw a flow or move a score.
- It does not list a user in the JSON, OTM or threatcl export. A later
  design may map a user onto an OTM actor.
