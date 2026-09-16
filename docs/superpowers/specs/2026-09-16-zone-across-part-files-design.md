# A zone declared in another part file

**Status:** decided, 16 September 2026.

## The problem

A component sits in a zone by nesting: a `component` block inside a `zone`
block. In a split system each part file holds its own blocks, so a component
in `arch/ledger.arch` cannot sit in a zone declared in `arch/edge.arch`. The
ledger team either declares the zone again, which the merge refuses as
declared twice, or leaves the component outside every zone.

## The decision

### The attribute

A top-level `component` block states `zone = "<id>"`, the identifier of a
zone any file of the system declares.

```hcl
component "api" {
  technology = "aws-ec2"
  zone       = "edge"
}
```

The component sits in that zone the way a nested component does: the same
score, the same picture, the same threat set. Nothing else about the
component changes.

`SourceComponent` gains `zoneId: String?`, what the block states or nil.

### When the attribute resolves

The attribute resolves after every part file of the system is read, in the
merge that joins the parts (`MergedArchitecture.merge`, which the gateway's
`read(_ parts:named:)` calls from `ImportArchitecture`). A part file on its
own cannot tell whether a zone exists: another file may declare it.

The resolution moves each top-level component that states a zone into that
zone's `components`, so every reader downstream, `ImportArchitecture`,
`LayOutModel` and the controls mirror, reads membership from nesting the way
it does today. The component keeps the origin of the file its block is in.

A flat system reads through the one-part path. The same resolution runs
there, so a flat file that states the attribute places the component too.

### The errors

| Fault | Message | Where |
| --- | --- | --- |
| a nested component states a different zone | `the component "<id>" sits in the zone "<outer>" and states zone "<stated>"` | the parser, in the file that holds the block |
| a top-level component states a zone no file declares | `the component "<id>" states zone "<id>", which this system does not declare` | the merge |
| the same, in a flat file | `the component "<id>" states zone "<id>", which this file does not declare` | the parser's whole-file check |

A nested component that states the zone it nests in is not an error. The
writer drops the line, so the next format writes the nesting alone.

### What the writer chooses

`ArchitectureWriter` writes a nested component with no `zone` line, and a
top-level component with the line when `zoneId` is set. The line sits after
`name` and before `data`.

The choice between nesting and the attribute is made where the files are
split, in `ArchitectureSourceSplit.parts`:

| The component's file | The zone's file | Written as |
| --- | --- | --- |
| the same file | the same file | nested inside the zone block |
| `arch/ledger.arch` | `arch/edge.arch` | a top-level block in `arch/ledger.arch` with `zone = "edge"` |
| unknown, added in the application | any | a top-level block in the header file with `zone = "<id>"`, unless the zone is in the header file, which nests |

A flat system splits nothing and nests every component, so every file
written before the attribute reads and writes byte for byte. A split system
whose components sit in the files their zones sit in also writes byte for
byte.

Inside one part file the writer puts the components that state no zone
first, then the components that state a zone, in zone order. A file written
in that order reads and writes byte for byte. A file written in another
order is put in that order by the next format, the way a component written
above a zone is.

### The window's zone drag

The drag changes nothing in the window's code. `MoveComponents` sets the
component's zone from the geometry it lands on, the save runs
`SaveSystem`'s split path, and `ArchitectureSourceSplit.parts` writes the
attribute into the component's own file when the zone sits in another file.
The component stays in the file it came from, so its answers stay in the
controls file that mirrors that file.

### What does not change

- `everyComponent` still lists every component, wherever it sits.
- The controls mirror keys on the component's origin file, which the
  attribute does not move.
- The language server offers `zone` in a component block's completions.
