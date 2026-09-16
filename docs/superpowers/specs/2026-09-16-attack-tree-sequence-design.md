# A tree states that one step comes after another

**Status:** decided, 16 September 2026.

## What this replaces

`2026-09-16-tree-edge-selection-design.md` states the join rule as "a step
holds nothing under it except the goal". This design replaces that line: a
step takes one feeder, the node that comes before it. Everything else in
that design stands.

## The problem

Issue #137. The attack tree language holds two junctions, `all_of` and
`any_of`, and neither states an order. A person who wants to write "steal X,
then use X to break Y, then with Y obtain Z" writes an `all_of` of three
steps, and a reader cannot tell which step comes first. The report prints the
three as a bag, and the Attack Trees stage draws every child of an `all_of`
side by side under one junction, so a chain looks like a fan.

## The two shapes

Two shapes were open.

**A step body holds the node that comes before it.**

```hcl
step "break-y" on component "y" {
  step "steal-x" on component "x"
}
```

**A `then` junction beside `all_of` and `any_of`, whose children are in
order.**

```hcl
then {
  step "steal-x" on component "x"
  step "break-y" on component "y"
}
```

## The decision: `then`

The language gains one junction, `then`. Its children are the links of a
chain, first link first.

```hcl
tree "obtain-z" {
  raises_risk_by = 40

  goal "obtain-z" on component "z"

  then {
    step "steal-x" on component "x"
    step "break-y" on component "y"
  }
}
```

Why `then` and not a step body:

- A chain reads top to bottom in the order the attacker walks it. A step
  body nests the first link innermost, so a route of five steps reads
  inside out and five braces deep.
- A `then` is the third word of one family. The grammar changes in one
  rule, `NodeBlock`, and every reader of a node gains one case beside
  `all_of` and `any_of`. A step body would give `StepBlock` a second
  meaning, a note and a prior node in one body.
- The score rule is the rule `all_of` has, so a chain belongs beside
  `all_of` in the node table of the language guide, not inside a step.

### What a link may be

The first link of a chain is any node: a step, an `all_of`, an `any_of` or
a `then`. Every later link is a step. The canvas draws a chain as one node
feeding the next, and a junction takes what feeds it as its children, so a
junction in the middle of a chain would have two meanings for one edge. A
person who wants "a, then both b and c" writes the branch as the first link
of a chain that follows it:

```hcl
all_of {
  then {
    step "a" on component "a"
    step "b" on component "b"
  }

  then {
    step "a" on component "a"
    step "c" on component "c"
  }
}
```

A `then` with one link is a chain of one and states no order. A `then` with
no link is refused the way an empty `all_of` is.

### The score

| Node | Open while | Factor |
| --- | --- | --- |
| `then` | every link is open | the **weakest** link |

A chain is open while every link is open, because a closed link stops the
attacker before the next one. It takes the weakest link's factor, the way
`all_of` takes the weakest child, because the attacker needs every one of
them. The order changes no number today: three steps under `then` score
what the same three steps under `all_of` score.

### What binds, and what is stale

A chain binds the way an `all_of` binds. One link that does not bind makes
the whole tree stale, and `threatmodeller check` exits 1 while it remains.

### The canonical order

The writer writes the links in the order the source states them, because
that order is the chain. `then` writes the way `all_of` writes: the word,
a brace, each link indented two spaces, a blank line between two links when
either one is a block, and the closing brace. A file that uses only `all_of`
and `any_of` reads and writes unchanged.

### The compiled stanza

Each `step` in a `tree` stanza of the `.controls` file states its position
in its chain, so a reader of the compiled file sees the order without the
`.attacktree` file:

```hcl
step "steal-x@component:x" {
  state    = "open"
  position = 1
}

step "break-y@component:y" {
  state    = "open"
  position = 2
}
```

A step outside every chain states no `position`. A step inside a branch
that is the first link of a chain states position 1, the way every step of
that branch does. A step inside a nested chain states its position in the
innermost chain.

### The report

The attack tree section prints the step table it prints today. A tree that
holds a chain prints one more block after the table, one line per link
with its position:

```markdown
The chain, in order:

1. Steal X on Component X, open
2. Break Y on Component Y, open
```

A tree with two chains prints "Chain 1, in order:" and "Chain 2, in order:".
A link that is a branch prints the steps of that branch on one line, one
after another, separated by semicolons.

## The canvas

### A step takes one feeder

`TreeGraph` gains one rule: a step takes one feeder, and that feeder is the
node that comes before it. The goal is a step, so the rule the goal had,
one root feeds it, is the same rule. A junction takes many feeders, as it
did.

The conversion reads a step with a feeder as a chain. The feeder's subtree
comes first and the step comes last; a feeder that is itself a chain
flattens into one `then`, so `a` feeding `b` feeding `c` writes as
`then { a b c }`, not as a chain of chains. The refusal `feedsAStep` is
replaced by `feedsAFedStep`: a node that feeds a step another node feeds is
refused with `"<node>" feeds a step that comes after another node`.

Reading a file back grows a `then` from its last link: the last link feeds
the parent, and each earlier link feeds the link after it.

### A chain is a line, `all_of` is a fan

`TreeGraph.positions` does not change. A node sits one column left of the
node it feeds, and siblings under one junction stack in one column. A chain
of three steps feeding the goal takes four columns and one row: a line. An
`all_of` of three steps takes one column of three rows beside the junction:
a fan.

### The menus and the panel

- **Join to…** on a node names each node this node may feed by its title,
  and each node that may feed this node as `From <title>`. A step with no
  feeder is offered the nodes that may feed it, because a step now takes
  one. A drag from a step's handle to a step joins them the way a drag to a
  junction does, and one drag is one undoable change.
- **The selection panel** on a step in a chain states its position and its
  neighbours: `Link 2 of 3, after Steal X, before Obtain Z`. The first link
  states no `after` and the last link states no `before`.

### The language server

The attributes offered inside a `tree` block are `name`, `description`,
`raises_risk_by`, `goal`, `all_of`, `any_of`, `then` and `step`. Inside an
`all_of`, an `any_of` or a `then` they are `step`, `all_of`, `any_of` and
`then`. `then` is an identifier, so the server colours it a keyword the way
it colours `all_of`.

## Tests

- `AttackTreeParserTests`: a three-link chain reads in order; an empty
  `then` is refused; a `then` with a branch after its first link is refused.
- `AttackTreeWriterTests`: a three-link chain writes back in the same order;
  the golden `Goldens/chain.attacktree` reads and writes byte for byte.
- `AttackTreeScoreTests`: a three-link chain with one closed link gives no
  boost; with every link open it gives the weakest link's factor, equal to
  the same three steps under `all_of`.
- `CheckToleranceTests`: a chain with one unbound link is a stale tree.
- `CompileControlsTests`: the stanza states each link's position.
- `MarkdownAttackTreesTests`: the links print numbered in order.
- `TreeGraphTests`: a step feeding a step converts to a `then`; a `then`
  becomes a graph and back; a chain lays out in a line and an `all_of` as
  a fan.
- `ViewRenderTests`: a chain and a fan both draw.
- `AttackTreeEditorFlowTests`: a step joined to a step on the stage writes a
  file holding `then`.
- `LanguageServerTests`: `then` is offered inside a `tree` and coloured.
- `scripts/cli-smoke.sh`: a chain runs through `check`, `compile` and
  `report`.
