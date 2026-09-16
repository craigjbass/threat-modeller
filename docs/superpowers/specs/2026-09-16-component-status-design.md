# The status a component states

**Status:** decided, 16 September 2026.

## The problem

A `component` stanza states technology, name, data, privilege, provider and
zone. Nothing states whether the component runs in Production today or is a
change a team plans. A threat model for a planned change draws both kinds on
one canvas, and a reader cannot tell one from the other.

## The decision

### The attribute

A `component` states `status`, with two values.

| Value | What it means |
| --- | --- |
| `live` | the component is deployed to Production |
| `proposed` | the team plans the component and has not deployed it |

A component that states no `status` is `live`. The writer writes no `status`
line for a live component, so every file written before the attribute reads
and writes byte for byte.

A value outside the two is a parse error that names the field, the value and
the two words the application holds, the way `runs_as` and `shape` do.

### What the status does not change

The status changes no score. A proposed component raises the threats it will
raise once a team deploys it, because a threat model of a planned change is
written to find those threats before the change ships. `AssessThreatModel`
never reads the status.

### The canvas mark

The canvas draws a proposed component with a broken outline, 3 points on and
3 points off, and a Proposed chip in the chip row under the shape.

An out-of-scope component already draws a broken outline, 6 points on and 4
points off, at 0.45 opacity. The two dashes differ, so a reader tells the two
apart, and an out-of-scope component keeps its own dash when it is also
proposed: a component that raises nothing is what a reader must see first.

### The control

`ComponentPanel` holds a Status picker with the two words, between the shape
picker and the sensitivity picker. The picker writes through
`SetComponentProperties`, the same path every other control on that bar uses,
so the `.arch` file holds the attribute on the next save.

### The report and the exports

| Where | What it states |
| --- | --- |
| the Markdown report, Appendix B | a Status column in the component table, `Live` or `Proposed` |
| `--format json` | `components[].status`, `Live` or `Proposed` |
| `--format otm` | a fourth entry in `components[].tags`, after the privilege |

`docs/threatmodel-export.schema.json` states the JSON key and the two values.
`docs/OTM-MAPPING.md` states the fourth tag.

## The open question: the threat list

The issue asks whether the threat list labels a threat on a proposed
component, and whether the list gains a status filter.

**The decision is no, for this milestone.** The threat list does not label a
threat by the status of what raised it, and it gains no status filter.

Three reasons.

1. The list is a work queue, ordered worst first. A team works the queue to
   answer every threat before the change ships, and a proposed component's
   threats are the reason the team wrote the model. A label that marks those
   rows says nothing a reader acts on.
2. A status filter hides rows the summary counts. The summary above the list
   states the total and the open count, and those numbers come from the whole
   assessment. A filter that removes rows would put a visible list beside a
   total it does not add up to. The tag filter on the canvas has the same
   shape and states plainly that it changes no score; a second filter over
   the same rows, on a second axis, doubles the rule a reader holds.
3. The canvas already answers "which of these is proposed" at a glance, and
   the component panel answers it for one component. The report's Status
   column answers it for a reader outside the window.

**What would change the decision.** A model where most components are
proposed, and a team that must report only the Production risk to a board.
The report, not the window, is where that reader looks, so the answer then is
a report section that splits the findings by status, not a filter on the
canvas window's list.
