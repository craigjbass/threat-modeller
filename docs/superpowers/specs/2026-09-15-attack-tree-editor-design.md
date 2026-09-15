# Writing an attack tree in the window

**Status:** superseded in part, 15 September 2026.
`2026-09-15-attack-tree-canvas-design.md` replaces the form — the **What a
person does** table and the outline column — with a canvas. The sheet, the
use cases, the one writer, the score display and the refusals below stand.

## The problem

An `.attacktree` file is written by hand in a text editor. The window reads
the trees — the report states them, `check` gates on them, and a tree raises
the score of its goal — and offers no way to write one:
`grep -rl "attacktree\|AttackTree" threatmodeller/` names only
`Dependencies.swift`.

So a person modelling in the window leaves it to write the one part of the
model that states **how** an attacker reaches a threat.

## What is not in scope

- No second shape for a tree. The language in `docs/LANGUAGE.md` section 7
  states what a tree is; the window writes that file and nothing else.
- No drawing of a tree on the canvas. A tree is a nesting, not a diagram, and
  the canvas draws the architecture.
- No editing of a tree the window did not read. A project with no
  `.attacktree` file gets one when a person writes the first tree.

## The decision

### Where it sits

A sheet, opened from the **Threats** stage, named **Attack Trees…**. The
threats stage is where a person reads what threatens the system, and a tree
says how one of those threats is reached.

The sheet holds two columns:

- **The trees this system states**, as a list: the tree's name, its goal, and
  the score the assessment bound to it.
- **The tree in front**, as an outline: the goal at the top, then the root
  node and every step under it, each row stating its threat, the element it
  is on, and its state.

### What a person does

| Control | What it writes |
| --- | --- |
| **Add Tree** | a `tree` block with a goal the person picks from the threats the model raises, `raises_risk_by = 0` and one `any_of` root |
| **Delete Tree** | the `tree` block, and nothing else in the file |
| the tree's name and description fields | `name` and `description` |
| **Raises risk by** | `raises_risk_by`, 0 to 100 |
| **Add Step** | a `step` under the chosen node, with a threat the person picks and the element that threat is raised on |
| **Add All Of** / **Add Any Of** | an `all_of` or an `any_of` node under the chosen node |
| **Delete** on a row | that step or that node, and everything under it |
| the step's note field | `note` |

A threat is chosen from the threats the model raises, never typed: a step
naming a threat the model does not raise binds to nothing, and the language
already states that fault. The element comes with the threat, because the
assessment raises a threat *on* an element.

### The score, while it is written

The sheet states the bound score beside each tree, read from
`AssessThreatModelResponse.attackTrees`, the way `CompensatingControlSheet`
states a projected score beside a form. A tree that binds to nothing states
so, with the reason the binding gives.

### What writes the file

New use cases in `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/`,
each reading the file, changing one thing and writing it again through
`AttackTreeSourceGateway` and `ProjectSourceGateway`:

| Use case | What it does |
| --- | --- |
| `ListAttackTreeSources` | the trees one system's file states, for the sheet |
| `WriteAttackTree` | writes one tree: a new one, or one a person changed |
| `RemoveAttackTree` | deletes one tree from the file |

`RemoveStaleAnswer` is the precedent: read the source, change one part of it,
write every other part back unchanged. A person changing one tree is not
deciding anything about the rest.

The window calls these use cases and never `AttackTreeWriter` itself, so one
writer states the canonical shape and `threatmodeller format` and the window
write the same bytes. A round-trip test states that.

### What the sheet refuses

- A tree with no goal. A tree states what it reaches.
- A tree whose id another tree in the file already holds.
- A `raises_risk_by` outside 0 to 100.
- Deleting the root node: a tree body holds exactly one root.

Each refusal is the parser's own rule, stated by the use case, so the window
and a hand-written file refuse the same things.

## What this changes in the model

Nothing scores differently. A tree written in the window is the same tree the
file states, and `AttackTreeBinding` and `AttackTreeScoring` read it as they
read a tree a person typed.
