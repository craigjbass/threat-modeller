# A user reaches a system through a client

**Status:** decided, 18 September 2026. Issue #178.

## The problem

A person uses a system through something: a web browser, a mobile app, a
terminal, an API client. The model holds two halves of that sentence and no
way to join them. A `user` block states `reaches = ["api"]`, which draws no
flow and changes no score, and a flow `flow alice -> api` joins the user
straight to the component. A browser is a component of the `actor-browser`
technology, and `flow browser -> api` joins the browser to the component.
Nothing states that the browser is Alice's, so:

- the canvas draws the user and the browser as two unrelated nodes, or the
  user with a flow that skips the client;
- the threats a client raises attach to nothing a person holds, and the
  user's `access` and `threat_actor` do not reach the flow that leaves the
  client;
- the report's Scope section lists users and components with no path
  between them, and an attack tree cannot say "the attacker, as this user,
  through this client".

What a person wants to write: Alice, an operator, uses a web browser to
reach the API.

## Cardinality

The shape holds many on both sides.

- One user holds several clients: Alice uses a browser, a mobile app and a
  terminal.
- One client reaches several targets: the browser reaches the API, the
  admin console and the reporting service.
- One client may be held by several users: a shared kiosk browser.

So a user is joined to a set of clients, each client is joined to a set of
components, and the picture is a tree from the user outward, not one line.
The shape must write that tree without repeating the user per flow.

The worked example below holds three users, four clients and ten targets.
Section 2 writes it in each of the three candidate shapes and states which
reads best and how the writer keeps it in canonical order.

A project of many systems holds the same person in several. Section 2.5
states that each `.arch` file declares its own user, that a library declares
no user, and how the report's Scope section then reads.

## 1. The three candidate shapes

Issue #178 names three. Each is written for the same example: Alice holds a
browser and a terminal, Bob holds a mobile app, Carol holds a kiosk and the
same browser; the browser reaches three targets, the terminal reaches four,
the mobile app reaches two, the kiosk reaches one.

### 1.1 `uses` on the user

```hcl
user "alice" {
  uses = ["browser", "terminal"]
}

user "bob" {
  uses = ["mobile"]
}

user "carol" {
  uses = ["kiosk", "browser"]
}

flow browser -> api
flow browser -> console
flow browser -> reports
flow terminal -> api
flow terminal -> ledger
flow terminal -> batch
flow terminal -> audit
flow mobile -> api
flow mobile -> push
flow kiosk -> catalogue
```

Three user blocks, one `uses` line each. Ten flow statements, one per client
and target pair, written the way every flow is written. No user is repeated.
The browser is named twice, once per holder, and its three flows are written
once.

### 1.2 `via` on the flow

```hcl
flow alice -> api      { via = "browser" }
flow alice -> console  { via = "browser" }
flow alice -> reports  { via = "browser" }
flow alice -> api      { via = "terminal" }
flow alice -> ledger   { via = "terminal" }
flow alice -> batch    { via = "terminal" }
flow alice -> audit    { via = "terminal" }
flow bob -> api        { via = "mobile" }
flow bob -> push       { via = "mobile" }
flow carol -> catalogue { via = "kiosk" }
flow carol -> api      { via = "browser" }
flow carol -> console  { via = "browser" }
flow carol -> reports  { via = "browser" }
```

Thirteen flow statements. Alice is named seven times and the browser six.
The browser's three flows are written twice, once per holder, and a flow
`alice -> api` appears twice with a different `via`, which the flow
identity rule of section 4.9 of `LANGUAGE.md` refuses as declared twice.
Nothing states that the browser reaches the API on its own: the fact is
spread over the users.

### 1.3 `held_by` on the client

```hcl
component "browser" {
  technology = "actor-browser"
  held_by    = ["alice", "carol"]
}

component "terminal" {
  technology = "actor-desktop"
  held_by    = ["alice"]
}
```

with the ten flows of section 1.1. Alice is named twice, once per client,
and the count of names is the same as `uses`. The reader of `user "alice"`
learns nothing about what Alice holds; the fact sits in the component blocks,
which nest in zones and split across part files. A client in `arch/edge.arch`
then names a user declared in the header file, and the writer of that part
file cannot place the user beside the client. `held_by` also has to be a
list from the first day, because a kiosk is shared.

### 1.4 The decision

**`uses` on the user.** It is the only shape that writes each user once and
each client-to-target flow once. The question a reader asks, "what does
Alice use", is answered in Alice's block. The question "what does the
browser reach" is answered by the browser's flows, which do not change. The
flow language does not change, so no flow is written twice and no flow gains
an attribute a flow between two components does not read.

## 2. The language

### 2.1 The attribute

`user` gains one attribute:

| Attribute | Type | Default | Meaning |
| --- | --- | --- | --- |
| `uses` | list of strings | empty | the component ids of the clients the user holds |

The table of section 4.6 of `LANGUAGE.md` reads, in writer order: `name`,
`role`, `access`, `uses`, `reaches`, `threat_actor`.

```hcl
user "alice" {
  name         = "Alice"
  role         = "Operator"
  access       = "admin"
  uses         = ["browser", "terminal"]
  reaches      = ["ledger"]
  threat_actor = "insider"
}
```

An entry names a component the system declares. Any component is a client
when a user holds it: the catalogue's `client` category is the palette's word
for the common ones, and the language checks no category. An entry naming a
user is refused with the same message an unknown component takes, because a
user holds no user.

`reaches` stays as it is: a statement that the user has access to a
component, with no flow and no client between. A user that states `uses` may
state `reaches` as well.

A file that states no `uses` reads and writes unchanged, byte for byte.

### 2.2 Canonical order

The writer writes the `uses` entries in the order the client components are
declared in the system: the order `ArchitectureSource.everyComponent`
holds, which is the order the writer writes the component blocks. A client
declared in another part file follows the clients of this file, in the order
stated. Two files that state the same set of clients write the same bytes,
and a diff of one added client is one changed line.

The window appends a client at the end of the model's list and the writer
sorts it into place on save.

### 2.3 What the parser and the merge refuse

| Fault | Message | Where |
| --- | --- | --- |
| a `uses` entry naming no component | `the user "<id>" uses "<component>", which this file does not declare` | the parser's whole-file check |
| the same, in a split system | `the user "<id>" uses "<component>", which this system does not declare` | the merge |
| an entry the block does not hold | `a user holds name, role, access, uses, reaches and threat_actor, not "<word>"` | the parser |

### 2.4 The language server

A `user` block completes `uses` beside the five attributes it completes
today.

### 2.5 A user across systems

Each `.arch` file declares its own users. A library declares no user, and
the library language does not change. The reasons:

- `uses` and `reaches` name components, and a library holds no component.
  A library user could hold no client, which is the whole of this design.
- `access` is the privilege the person holds on what the person reaches,
  and that differs from system to system.
- What is one across systems is the adversary the person is. That is a
  `threat_actor` block in a `.lib` file, and a `user` block in each system
  names it with `threat_actor = "acme-insider"`.

The same id may declare a user in two systems; each system is its own
namespace. The Scope section of one system's report lists that system's
users and nothing of another system's.

## 3. The domain

`UserFacts` gains `uses: [String]`, the client component ids in model order.
`SourceUser` gains the same. `ImportArchitecture`, `ArchitectureSourceBuilder`
and the JSON codec carry it. A JSON file written before this design reads
with no clients.

`SetUserProperties` takes `uses` beside `reaches`, drops a repeat, and refuses
an entry naming no component or naming a user with `.unknownComponent`, the
way it refuses a reach.

`RemoveComponents` takes a removed component's id off every user's `uses`.
`MergeComponents` renames a merged client. A pasted user keeps the clients
that name a pasted component, under their fresh ids, and drops the rest.

## 4. The canvas

### 4.1 The use link

`ViewedConnection` gains `isUse: Bool`. `ViewedModel.connections` lists the
model's flows first, then one **use link** per user and client pair, in
model order, with the id `use:<user>:<client>`, the kind `human`, no
description and `isUse` true. A use link is derived from `uses` and is not a
flow: the model holds no `Connection` for it, the writer writes no `flow`
statement, and the `.arch` file holds `uses` alone.

For Alice with a browser and a mobile app, where the browser reaches the API
and the console and the mobile app reaches the API, the canvas holds three
components once each and five links: `alice -> browser`, `alice -> mobile`,
`browser -> api`, `browser -> console`, `mobile -> api`. It holds no link
`alice -> api`.

The canvas draws a use link in the secondary colour with a dotted stroke and
the arrowhead every flow draws. It carries no risk colour, because it raises
no threat. A click on it selects nothing: `FlowGeometry.connection(under:)`
skips a use link, so the flow panel never opens on one and the delete key
never asks the model to remove one. A person removes it from the user panel.

`DiagramBuilder` draws the same link in the exported picture, dotted. The
Mermaid, DOT and D2 writers write it as one more edge, labelled `uses`.

### 4.2 The layout

`LayOutModelRequest` adds one `SourceFlow` from the user to each client, of
kind `human`, to the flows the layout reads, so a user is placed beside the
clients it holds. Nothing writes those flows.

### 4.3 The chips and the hover

A user's chip row gains no chip. The hover text on a user names the clients:
`User, Operator, the threat actor insider, through Browser and Mobile app`.

### 4.4 Access

`access` is not carried onto the client's outgoing flow as a privilege. The
privilege crossing rule reads `runs_as` on the two ends, which is what the
software runs as; a person's access on the target is a different fact. The
report and the tree state it, section 6 and section 7.

## 5. The score

### 5.1 The rule

The actor a user names is faced across the system, as the user block design
states, so the report's Threat actors section and the actors sheet do not
change. What changes is where the actor **performs**.

The threat actors design left an actor's reach to a later design. This is
that design for one case:

- A user with no `uses` states no reach. Its actor performs threats
  everywhere, as today. No existing file changes a score.
- A user with `uses` reaches: each client it holds; each flow that leaves a
  client; the component each such flow ends at; each component `reaches`
  names; each flow that leaves the user itself and the component that flow
  ends at. Its actor performs a threat only on those sources.

An actor `faces` lists performs everywhere, whatever any user states,
because `faces` is the system's own statement.

An actor named by two users performs wherever either user reaches. An actor
named by a user with `uses` and by a user without performs everywhere.

### 5.2 What that does to a score

Alice, an insider of `commodity` capability who performs `credential-theft`,
holds a browser that reaches the API. The catalogue marks `credential-theft`
on the API `targeted`. The threat on the API is scored `commodity`, set by
the insider: the user's actor raised the likelihood on the client's outgoing
path. The same threat on a ledger the browser does not reach keeps the
catalogue's `targeted`, because the insider does not perform there.

Row four of the threat actors design still holds: a threat no faced actor
performs keeps the catalogue's own likelihood, so a short `uses` list never
lowers a score by leaving a component out. What it can do is stop an actor
from lowering a threat outside the user's reach, which is what stating the
reach is for.

`ThreatResolver` keeps `facedActors` for the list and gains a reach per
actor, `nil` for everywhere, built once from the users. `likelihooded`
filters the faced actors by the threat's source id before it asks
`ActorLikelihood`. `performedBy` on the assessed threat reads the same
filtered set, so the threat card and the report stanza name the actor only
where the actor performs.

## 6. The report

The Scope section's user line gains a clause per client:

```markdown
### Users

- Alice (Operator, Administrator): through Web Browser reaches API and Admin console; through Mobile App reaches API; is the threat actor Disgruntled operator
- Bob (Customer, User): reaches Ledger; through Web Browser reaches nothing
- Carol (User): reaches nothing
```

The line reads, in order: the name, the role and the access in brackets;
`reaches <names>` when the user states `reaches`; then `through <client>
reaches <targets>` for each client in `uses`, the targets being the ends of
the flows that leave the client, in model order; then the actor. A user
that states neither `reaches` nor `uses` reads `reaches nothing`, as today.

`ReportUser` gains `clients: [ReportClient]`, each holding the client's name
and the names of what it reaches. `ReportStagePage` draws the same line.

## 7. The attack tree

`TreeElement.list` reads the use links for adjacency and lists no row for
one: the `.attacktree` language names components, flows and zones, and a use
link is none of those. A user reaches the clients it holds, and a client
reaches the users that hold it, so a route "as Alice, through the browser,
to the API" is three connectable steps: the user, the client, the flow or the
target.

The sidebar's caption on a node anchored on a client held by users reads
`Marked: what an attacker at Web Browser reaches, as Alice.`, naming every
holder. The element rows do not change their names.

## 8. The window

### 8.1 The user panel

The user panel gains a **Uses** menu above Reaches, with one toggle per
component that is not a user, the way Reaches offers them. The closed label
reads `Uses nothing`, `Uses Web Browser`, or `Uses 2 components`. The
accessibility identifier is `user-uses`. It writes through
`SetUserProperties`, and the parity row for `arch.user.uses` names it.

### 8.2 The palette gesture

Two gestures write the shape without a form:

- **A technology dropped on a user.** `CanvasGestures.drop` reads the node
  under the drop point. When it is a user, the session adds the component to
  the right of the user, at the user's x plus the component width plus a
  gap, and adds it to the user's `uses`. The palette's User row dropped on a
  user adds a user beside it and holds nothing, because a user holds no
  user.
- **A flow dragged from a user to a client.** `ThreatModelSession.connect`
  reads the target. When the source is a user and the target's technology
  category is `client`, the session adds the target to the user's `uses`
  and writes no flow. A drag from a user to any other component writes a
  flow, as today. A drag from a client to a user writes a flow, as today.

## 9. The executable

`scripts/cli-smoke.sh` gains a step: a file with a user, two clients and
three targets formats byte for byte, compiles, passes `check` once answered,
and reports a Scope line naming the user, a client and a target.

## 10. What this design does not do

- It does not change the flow language. No flow gains `via`.
- It does not change the component language. No component gains `held_by`.
- It does not add a user to the library language.
- It does not carry `access` into the privilege crossing rule.
- It does not remove `reaches`, and it does not convert a `reaches` entry
  into a client.
- It does not make a use link a flow: it raises no connection threat, it is
  not selected, and `.controls` never names it.
- It does not narrow an actor `faces` lists.

## 11. Tests

| Test | Says |
| --- | --- |
| `UserClientsTests` (kit) | the parser reads `uses`; the golden `user-clients.arch` round trips byte for byte; `users.arch` is unchanged; a use naming no component is the error of section 2.3; the merge states the split-system message; the writer sorts `uses` into declaration order |
| | the scope line of section 6, with a client and a target on one line |
| | the score rule of section 5.2: the API threat takes the actor's tier, the ledger threat keeps the catalogue's |
| | the language server completes `uses` |
| `UserFlowTests` (window) | one user, two clients, three targets: the canvas holds every node once and the five links of section 4.1, and no user-to-target link |
| | the Uses menu writes `uses` and the file reads it back |
| | a technology dropped on a user is added beside the user and written into `uses`; a flow dragged from a user to a client writes `uses` and no flow |
| | the hover names the clients |
| `TreeConnectableTests` | a user's rank marks its client; the caption names the holder |
| `scripts/cli-smoke.sh` | section 9 |
