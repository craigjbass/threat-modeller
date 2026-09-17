# A tree states which controls are sufficient to close the whole route

**Status:** decided, 17 September 2026.

## The problem

Issue #139. A tree closes step by step: a step is closed when its threat
holds an `implemented` control or a `compensating` block (`docs/LANGUAGE.md`
section 7.5), and the tree gives no boost when its root is closed. Nothing
states that one control is sufficient for the whole route. A control that
breaks the chain at one link, or a control that is on no step's threat, such
as a network segmentation between two links or an alert that fires on the
route as a whole, has nowhere to be written. The tree stays open and the
score stays raised after the team has closed the route.

## The two shapes

Two shapes were open.

**A `closed_by` list on the `tree` block in `.attacktree`, naming controls.**

```hcl
tree "read-every-customer-record" {
  raises_risk_by = 40
  closed_by      = ["Segment the network between the application tier and the data tier"]

  goal "data-exfiltration" on component "db"
  ...
}
```

**Control answers inside the `tree` stanza of `.controls`, the way a
`threat` stanza holds them.**

```hcl
tree "read-every-customer-record" {
  goal = "data-exfiltration@component:db"
  ...
  control "Segment the network between the application tier and the data tier" {
    status = "implemented"
  }
}
```

## The decision: `closed_by` in `.attacktree`

The `tree` block gains one attribute, `closed_by`, a list of control
descriptions. A control's description is its identity, the way section 5.6
of the language guide states it for the `.controls` file.

Why the `.attacktree` file and not the `.controls` file:

- The `.attacktree` file states what a person believes about a route. "This
  one control closes this route" is a belief about the route, so it sits
  beside the steps that state the route, in the file a person owns.
- A control has one status per threat, and the `.controls` file holds it.
  A tree that named a status of its own would answer the same control twice,
  once on the threat and once on the tree, and the two could disagree. With
  `closed_by`, the tree names the control and reads the status the threat
  stanzas already hold. The Controls stage writes the status and the
  evidence where it writes every status and every evidence tier today, and
  the tree gains no second status writer.
- The compiled `tree` stanza stays wholly compiler-written. The merge rule
  of `2026-09-14-attack-trees-design.md` section 4.3 stands: a tree the
  `.attacktree` file drops writes no stanza, and nothing is lost, because
  the `closed_by` list went with the tree.
- One writer. `WriteAttackTree` writes the list, so the Attack Trees stage,
  `threatmodeller format` and a hand edit all write the same bytes.

### How `compile` keeps a hand-written answer in a stanza it also writes

It does not need to. The `tree` stanza in `.controls` holds no hand-written
answer under this design. The compile rewrites the stanza from the model on
every run, as it rewrites `chain`, `score` and `score_before`. The answer a
person writes is the `closed_by` list in `.attacktree`, which the compile
reads and never writes, and the statuses in the `threat` stanzas, which the
compile keeps by the rule section 5.12 of the language guide already states.

## The language

### `.attacktree`

```
TreeEntry = "name"           "=" String
          | "description"    "=" String
          | "raises_risk_by" "=" Number
          | "closed_by"      "=" "[" [ String { "," String } ] "]"
          | GoalStatement
          | NodeBlock
          | StepBlock ;
```

| Block | Attribute | Values | Default |
| --- | --- | --- | --- |
| `tree` | `closed_by` | a list of control descriptions | empty |

The writer writes `closed_by` after `raises_risk_by`, in the aligned run of
attributes, and writes nothing for an empty list. A file that states no
`closed_by` reads and writes unchanged. The list writes in the order the
source states it.

A `closed_by` that is not a list is the error `expected [`, which is the
error every list attribute gives.

### The compiled stanza

The `tree` stanza in `.controls` gains one attribute and one block, both
written by the compiler and recomputed on every compile:

```hcl
tree "read-every-customer-record" {
  goal           = "data-exfiltration@component:db"
  chain          = 0
  raises_risk_by = 40
  score          = 5
  score_before   = 5
  closed_by      = "Segment the network between the application tier and the data tier"

  sufficient "Segment the network between the application tier and the data tier" {
    state = "closes"
  }

  sufficient "Alert on the route as a whole" {
    state = "open"
  }

  step "ssrf-attack@component:appserver" {
    state = "open"
  }
}
```

| Attribute | Meaning |
| --- | --- |
| `closed_by` | the sufficient control that closed the tree; absent while none does |
| `sufficient.state` | `closes`, `open`, `unevidenced` or `unknown` |

| State | Meaning |
| --- | --- |
| `closes` | the control is implemented, with evidence where the policy demands it |
| `open` | the control is not implemented, or nothing answers it |
| `unevidenced` | the control is implemented, the policy demands evidence at the goal's level, and no answer states a tier |
| `unknown` | no catalogue or library control has this description |

A stale stanza keeps its `sufficient` blocks and states no number, the way
it keeps its steps.

## The rule

### What "implemented" means for a sufficient control

A sufficient control names a description. The `.controls` file may answer
that description on more than one threat: one control on three instances is
three answers. The tree reads every answer the model holds for that
description and sets `not_applicable` answers aside. The control is
**implemented** for the tree when at least one answer remains and every
answer that remains is `implemented`.

Every answer, not any answer, because a control in place on one element and
not on another is not in place. The team marks the elements the control does
not apply to `not_applicable`, and the tree reads the rest.

A control that no threat of the model offers has no answer, so it is `open`.
The Attack Trees stage offers only the controls the model holds, so a person
who writes through the stage never names one.

### Evidence

`requires_evidence_above` in the `.arch` file and
`implemented_requires_evidence_above` in the policy file both demand an
evidence tier on an implemented control at or above a risk level. The tree
reads whichever of the two is in force, and the lower level when both are.
The demand is judged at the goal's level before its controls, because the
goal is what the tree closes. When the demand holds and an answer that counts
states no tier, the control is `unevidenced` and closes nothing.

### What closes the tree

A tree with at least one sufficient control in state `closes` is **closed as
a whole**: `isOpen` is false, the chain factor is 0, the tree gives no boost,
and `closed_by` names the first such control in the order the file states
them. The steps still bind and still state `open` or `closed` each, so the
report shows the route and the one control that cuts it.

A sufficient control that is `not_implemented`, `accepted` or
`not_applicable` closes nothing, and a tree whose sufficient controls all
leave it open scores by the step rule as it does today.

### `check`

A sufficient control whose description no catalogue or library control holds
makes the tree **stale**, the way an unbound step does. The compile writes
the tree as `stale tree` with the control in state `unknown`, and
`threatmodeller check` exits 1 and prints
`the tree "<id>" is closed by "<control>", which the catalogue and the
libraries do not hold`. A stale tree with an unbound step prints the line it
prints today; a tree with both prints both.

The known set is every control description the catalogue states on any
threat, and every technology mitigation the catalogue and the `.lib` files
state, compared after the whitespace normalisation `ControlIdentity` applies
to a control's identity.

## The report

The tree section heading states what closed the tree:

```markdown
### Read every customer record — closed by Segment the network between the application tier and the data tier
```

A tree that names sufficient controls prints them after the goal line, one
per line, with the state of each:

```markdown
Goal: Data Exfiltration on PostgreSQL Database.

Sufficient controls:

- Segment the network between the application tier and the data tier: closes the tree
- Alert on the route as a whole: not implemented
```

The four states print as `closes the tree`, `not implemented`,
`implemented with no evidence` and `not a control the catalogue or the
libraries hold`.

The step table prints as it does today. The heading `every route is closed`
stays for a tree whose steps close it with no sufficient control.

## The window

### The selection panel

The Attack Trees stage shows the tree's sufficient controls in the selection
panel when the tree is in front with nothing selected, and when the goal is
selected. The panel lists each named control with its state, offers
**Remove** beside each, and offers **Add a sufficient control**, a menu of
every control description the model holds that the tree does not name yet,
in alphabetical order. Picking one adds it to the list and writes the file
through `WriteAttackTree`, the way every change on the stage writes. One
pick is one undoable change.

The state beside each control reads `Closes the tree.`, `Open: not
implemented.`, `Open: implemented with no evidence.` or `Unknown: no control
has this description.`, or `Not written yet.` while the tree is unwritten.

### The threat card

The threat card for the goal's threat states, under the actor line:
`The tree <name> is closed by <control>.` One line per tree that names this
threat as its goal and is closed by a sufficient control.

## What is not wanted

- No status or evidence in the `tree` stanza.
- No change to how a step closes.
- No change to the merge table for trees.
- No control id: the description is the identity, as it is in `.controls`.

## Tests

- `AttackTreeParserTests`: `closed_by` reads as a list; a `closed_by` that
  is not a list is an error.
- `AttackTreeWriterTests`: a tree with `closed_by` writes back byte for
  byte; the canonical file with no `closed_by` writes unchanged; an empty
  list writes nothing.
- `AttackTreeBindingTests`: the two-answer rule, `not_applicable` set
  aside, an unevidenced answer under a demand, an unknown control makes the
  tree stale.
- `AttackTreeScoreTests`: every step open and one sufficient control
  implemented gives no boost; the same tree with that control not
  implemented gives the boost.
- `CompileControlsTests`: the stanza writes `closed_by` and the `sufficient`
  blocks; the controls parser reads them back.
- `CheckToleranceTests`: the failure line for an unknown control.
- `MarkdownAttackTreesTests`: the heading and the list name the closing
  control.
- `TreeSelectionTests`: the tree and the goal state the sufficient controls.
- `AttackTreeEditorFlowTests`: a sufficient control added from the stage
  reaches the file, and the file reads back with it.
- `ThreatCardTests`: the goal's card states the closing tree and control.
