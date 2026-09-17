# A tree reaches the threat list, the cards and the controls

**Status:** decided, 17 September 2026.

## The problem

Issue #140. An attack tree reaches the score in one place.
`AttackTreeScoring.apply` raises the goal's threat while the root is open, and
nothing else in the window reads a tree. `ThreatCard.swift`,
`ThreatSidebar.swift` and `ThreatFilter.swift` name no tree, so:

- a threat that is a step on an open tree looks the same as a threat on no
  tree, and the person answering controls cannot tell that closing it breaks a
  route;
- the goal's card shows a raised score and states no tree that raised it;
- the list cannot be narrowed to one route;
- the Controls stage and the report's Recommendations put a control that
  breaks a route in the same place as a control that breaks nothing;
- a step whose threat holds an `accepted` or a `not_applicable` answer stays
  open (`docs/LANGUAGE.md` section 7.5) and the card does not say so.

## The question: does a step's likelihood read the tree?

An attacker on a route the tree names is already part of the way along it, so
the next step could be read as more likely than the catalogue says.

**The decision: no. The goal's boost is the only number a tree moves.**

Four reasons.

1. The chain factor is built from the step likelihoods. `AttackTreeBinding`
   reads each open step's `likelihood.factor` and folds the weakest, or the
   strongest of an `any_of`, into `chainFactor`, and `AttackTreeScoring`
   multiplies `raises_risk_by` by that factor. A tree that raised a step's
   likelihood would raise the factor built from that likelihood, so the tree's
   own output would feed its own input and the goal would move twice for one
   route.
2. A likelihood is a fact about the world: how often an attack of this kind
   happens anywhere. Stage 6 answers it from the catalogue, from a
   `likelihood` finding a person wrote, and from the threat actors the system
   faces. A tree is a belief about this system. A belief about this system is
   not evidence about how often an attack happens elsewhere, so it does not
   belong in that number.
3. `raises_risk_by` prices the route once, at the goal, where the harm lands.
   The route is one claim, so it moves one score.
4. What the reader needs from a step is not a different number. The reader
   needs to know the step is on a route, which route, and what closing it
   would break. Words on the card and a filter give that, and every score
   stays the score the stage that owns it set.

The score test that states this answer is
`AttackTreeScoreTests.aStepKeepsTheScoreAndTheLikelihoodItsOwnStagesGaveIt`:
a two step tree with `raises_risk_by = 40` moves the goal from 5 to 7, and
each step keeps the score and the likelihood its own stages gave it.

## The order rule

Stated once, and read by the Controls stage and by the report's
Recommendations section.

> **A control that closes a step on an open tree sorts before a control that
> does not. Two controls on the same side of that line keep the order they
> already have.**

A control **closes a step on an open tree** when a tree is open and not stale,
and one of these holds:

- the control's threat is a step of that tree, and that step is open; or
- that tree names the control's description in its `closed_by` list, which
  closes the whole route at once.

`RouteClosing` states the rule and nothing else states it. The Controls stage
orders the controls of one card by it. The report's Recommendations orders its
list by it before the score and the text decide, so the two read the same way:
route first, then worst risk first, then the text.

A recommendation closes a step on an open tree when the threat it names is an
open step of an open tree.

## What the assessment carries

`AssessedThreat` gains `trees`, a list of `AssessedTreeRole`, one entry per
tree that names this threat as its goal or as a step, in file order.

| Field | Meaning |
| --- | --- |
| `treeId` | the tree's id, which the filter matches on |
| `treeName` | the tree's name, which the card prints |
| `isGoal` | true on the goal, false on a step |
| `isTreeOpen` | true while an attacker can walk the whole route |
| `isTreeStale` | true while a step or a sufficient control does not bind |
| `raisesRiskBy` | the per cent the file states |
| `scoreBefore`, `score` | the goal's score before and after the boost |
| `stepState` | `open`, `closed` or `unbound`; nil on the goal |
| `stepClosedBy` | the control that closed this step, or nil |
| `stepIsOpenBecause` | why an open step is open; nil otherwise |

`AssessedControl` gains `closesTreeNames`, the names of the open trees this
control closes a step on, in file order. Empty for every other control.

### Why an open step is open

Read from the answers the step's threat holds, worst answer first:

| The threat holds | The card says |
| --- | --- |
| an `accepted` control | `an accepted control closes no step` |
| a `not_applicable` control | `a control that does not apply closes no step` |
| controls, none implemented | `no control is implemented` |
| no control at all | `no control answers it` |

## The window

### The threat card

Under the actor line and the known vulnerabilities line, one line per tree,
in file order:

```
Goal of Read every customer record. The tree is open and raises this threat by 40 per cent, 5 → 7.
Goal of Read every customer record. The tree is closed and raises nothing.
Goal of Read every customer record. The tree is stale and raises nothing.
Step on Read every customer record. The tree is open and raises its goal by 40 per cent. This step is open: an accepted control closes no step.
Step on Read every customer record. The tree is open and raises its goal by 40 per cent. This step is closed by Rotate the instance role.
Step on Read every customer record. The tree is closed and raises nothing.
```

The line for a stale tree reads `The tree is stale and raises nothing.`
whatever the step is doing, because a stale tree moves no score.

`ThreatCard.treeLines` states the words, so a test reads them without a
window. The line the sufficient control design added,
`The tree <name> is closed by <control>.`, stays where it is and is not
repeated here.

Under a control row whose `closesTreeNames` is not empty, one line per tree:

```
Closing this breaks the tree Read every customer record.
```

### The filter

`ThreatFilter` gains `treeId`. The filter bar gains a picker, **On a tree**,
whose first entry is `Every tree` and which then names one entry per tree,
by name. A threat is kept when its `trees` list holds that id.

`ThreatFilter.trees` reads the entries from the threats the list already
holds, in the order the list first meets each tree, so drawing the bar
assesses nothing again. A tree whose goal and every step left the model has no
threat to show, so the picker does not offer it. A stale tree and a closed
tree are offered like any other: a person reading a closed route still wants
to see it.

### The Attack Trees stage selection panel

The panel's node section gains the controls on the selected node's threat,
each with the four way status picker the threat card draws. The picker writes
through `ThreatModelSession.setControlStatus`, which is the write path the
threat card uses, so one status has one writer and the `.controls` file gets
the same bytes from either stage.

`TreeSelection.Node` gains `controls`, read from the assessment by the node's
threat key. A node the assessment does not hold, and a junction, offer none.

## What is not wanted

- No change to any likelihood, to any step score, or to `raises_risk_by`.
- No second writer for a control status.
- No new attribute in any language file. Nothing here is written to disk.
- No change to the order of the threat list itself: the order rule orders
  controls and recommendations, and the Reorder button keeps governing the
  cards.

## Tests

- `AttackTreeScoreTests`: a step keeps the score and the likelihood its own
  stages gave it, while the goal moves.
- `RouteClosingTests`: the order rule puts a route closing item first and
  holds the rest in order.
- `RecommendationsSectionTests`: a recommendation on an open step of an open
  tree sorts above a higher scoring recommendation that closes no route.
- `AssessThreatModelTests`: a goal carries its tree with the boost, a step
  carries its tree with its role and its reason, and a control on an open step
  names the tree.
- `ThreatCardTests`: the goal's line states the tree and the boost; the step's
  line states the tree, the role and the reason.
- `ThreatFilterTests`: the filter narrows to one tree's threats.
- `TreeSelectionTests`: the selected node states the controls on its threat.
- `AttackTreeEditorFlowTests`: a status changed from the tree stage's
  selection panel reaches the `.controls` file, and the file reads back with
  it.
