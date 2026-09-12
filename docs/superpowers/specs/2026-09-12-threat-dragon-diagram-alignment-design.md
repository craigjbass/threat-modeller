# Threat Dragon diagram alignment: design

Date: 2026-09-12. Status: approved in conversation, ready for an implementation
plan.

Scope: the canvas notation and the element state colouring. File interop with
OWASP Threat Dragon, several diagrams per model, and the LINDDUN, PLOT4ai, CIA
and DIE diagram kinds are out of scope and get their own spec if anybody wants
them.

## 1. What this fixes

The canvas draws one shape for everything. A component is a 160 by 72 rounded
rectangle whatever it is, so a reader cannot tell a database from a person from
a Lambda function without reading the label. The diagram also says nothing
about risk: a node with four critical threats and a node with none are drawn
the same way.

OWASP Threat Dragon uses standard data flow diagram notation and paints element
state into the outline. The information a reader wants is in the picture.

| # | Fault | What a reader has to do today |
| --- | --- | --- |
| 1 | Every component is the same rectangle | Read every label to find the data stores |
| 2 | The diagram states no risk | Open the sidebar and match names by eye |
| 3 | A node with threats turned off looks normal | Click it and read the panel |
| 4 | A flow states nothing about itself | Click it and read the panel |
| 5 | A zone's dashed outline states public against private, and nothing else can use the dash | Nothing: this one works, but the dash is spent |

## 2. The decisions this design fixes

1. **A component draws as one of three data flow diagram shapes.** An actor is
   a rectangle. A process is a circle. A store is two horizontal lines with no
   side walls.

2. **The shape derives from the catalogue, and the user can override it.** The
   derivation map is application-owned, because `scripts/update-catalogue.sh`
   overwrites `Resources/Library` and a vendored file cannot carry an
   application concept.

3. **Each shape has its own footprint. The centre never moves.** The centre
   stays at `position + (80, 36)`, so no saved model moves and `ZoneContainment`
   needs no change.

4. **The outline states risk, not the Threat Dragon two-state rule.** The
   outline takes the `RiskPalette` colour of the highest residual risk level on
   that element. The application already grades four levels, and one colour
   language across the canvas, the sidebar and the report beats two.

5. **A badge states the open threat count.** The count sits on the shape, on
   the zone header, and beside the flow label.

6. **A component with threats turned off draws as Threat Dragon draws an
   out-of-scope element:** grey, dashed, and faded.

7. **A zone stays the one boundary object.** A Threat Dragon trust boundary
   box is a marker with a name. A `Zone` is a marker with a name, a network
   kind, a network type, a boundary kind, a risk reduction and membership by
   geometry. Adding a second, non-scoring boundary object would give the user
   two things that look alike and score differently.

8. **A flow carries a label.** The description when the user wrote one, else
   the `FlowKind` label. Every flow keeps one line style, as Threat Dragon
   draws them.

## 3. The shape

### 3.1 `DiagramShape`

A new application-owned enumeration in
`ThreatModelKit/Sources/ThreatModelKit/modelling/domain/DiagramShape.swift`,
beside `DataSensitivity`, `NetworkZone` and `ZoneBoundary`:

```swift
public enum DiagramShape: String, CaseIterable, Equatable, Sendable {
    case actor
    case process
    case store

    public var label: String {
        switch self {
        case .actor: "Actor"
        case .process: "Process"
        case .store: "Store"
        }
    }
}
```

### 3.2 The derivation map

```swift
public enum DiagramShapeMap {
    public static let actorProvider = "actor"
    public static let storeCategories: Set<String> = ["database", "storage", "secrets"]

    public static func derived(providerId: String, categoryId: String) -> DiagramShape
}
```

The rule, in order:

1. `providerId == "actor"` gives `.actor`.
2. `categoryId` in `storeCategories` gives `.store`.
3. Everything else gives `.process`.

A component whose technology the catalogue no longer holds carries an empty
provider and an empty category, so rule 3 gives it `.process`.

### 3.3 The override

`Component` gains one field:

```swift
public var shape: DiagramShape?
```

`nil` means the map decides. A value forces the shape. `Component` gains the
resolution:

```swift
public func resolvedShape(providerId: String, categoryId: String) -> DiagramShape {
    shape ?? DiagramShapeMap.derived(providerId: providerId, categoryId: categoryId)
}
```

`ViewedComponent` gains two fields:

- `shapeId: String` — the resolved shape. The canvas draws this.
- `shapeOverrideId: String?` — only the user's own choice, so the picker can
  tell **Auto** from a forced value the map would have given anyway.

`SetComponentPropertiesRequest` gains `shape: String?`. An unknown value
returns a new case, `.unknownShape`.

## 4. The footprint

### 4.1 The sizes

`Component.size` stays 160 by 72 and keeps its meaning: the slot a component
occupies in a layout, and the box whose centre the containment rule tests.
The drawn footprint is new, and it centres on that same centre point.

```swift
public static func footprint(for shape: DiagramShape) -> Size {
    switch shape {
    case .actor: Size(width: 160, height: 72)
    case .process: Size(width: 104, height: 104)
    case .store: Size(width: 160, height: 64)
    }
}
```

A process circle passes the slot by 16 points at the top and 16 at the bottom.
Nothing that is stored changes, and nothing that is scored changes.

### 4.2 What the overflow touches

`LayOutModel.rowGap` goes from 48 to 72, so a layout the application generates
never puts two circles 16 points apart. `LayOutModel` reads no catalogue and
gains no dependency: it spaces every component by the widest and tallest
footprint, whatever shape each one turns out to be.

`LayOutModel.size(ofZoneHolding:)` uses the same larger gap, so a generated
zone still holds its contents.

`CanvasHitTest.contentSize` adds the overflow, so a circle at the far right of
a diagram is never clipped.

### 4.3 Hit testing

`ComponentBox` gains the shape and returns the footprint rectangle around the
fixed centre. `ComponentBox.contains` tests the ellipse for a process and the
rectangle for the other two. Without the ellipse test the invisible corners of
the square select the node.

`AnchorGeometry.point` puts the four anchors on the footprint rectangle, which
places a circle's anchors at its four cardinal points.

## 5. The element risk rollup

`ThreatModelSession` already holds every `AssessedThreat`. The canvas needs one
value per element, and the rules that produce it belong in the core, where a
test runs them without a window.

```swift
public struct ElementRisk: Equatable, Sendable {
    /// "component:<id>", "connection:<id>" or "zone:<id>".
    public let sourceId: String
    public let openCount: Int
    public let totalCount: Int
    /// The highest residual level, or nil when the element raises nothing.
    public let highestLevelId: String?
}

public enum ElementRiskRollup {
    public static func byElement(
        _ threats: [AssessedThreat],
        severities: [AssessedSeverity]
    ) -> [String: ElementRisk]
}
```

**A threat is answered when one of its controls has status `implemented`, or
when every control it has is `not_applicable` or `accepted`.** Otherwise the
threat is open. A threat with no controls at all is open.

`highestLevelId` reads `AssessedThreat.riskLevel`, which is already residual:
the implemented controls, the pathway mitigations, the compensating controls
and the likelihood have all been applied by the time the canvas sees it. The
level ranks come from the taxonomy order the assessment already returns, so the
rollup states no severity order of its own.

An element with threats, all of them answered, keeps its highest level and
shows no badge. A reader still sees what the element carries.

## 6. Painting

### 6.1 A component

| Part | Rule |
| --- | --- |
| Outline colour | `RiskPalette.colour(forLevelId:)` of `highestLevelId`, else `Color.secondary.opacity(0.4)` |
| Outline width | 1.5, and 2.5 when selected |
| Selection | the outline turns `Color.accentColor`, so selection never reads as risk |
| Fill | `Color(nsColor: .controlBackgroundColor)` for an actor and a process. A store has no fill: it is two lines |
| Out of scope | grey, dashed `[6, 4]`, every part at 45 percent, no badge |
| Badge | the open count, top right of the footprint, a capsule filled with `RiskPalette.background(forLevelId:)`, hidden at zero |
| Label | the name, inside the shape, centred, one line |
| Chips | the provider, the sensitivity and the zone, in a row **below** the shape |

The chips move below the shape for all three kinds. A 104 point circle cannot
hold a name and three chips, and one rule for all three kinds beats three
rules.

### 6.2 A zone

The dashed trust boundary of Threat Dragon, with the tint kept:

| Part | Rule |
| --- | --- |
| Outline | dashed `[8, 6]`, width 2, width 3 when selected |
| Outline colour | green for private, orange for public, `Color.accentColor` when selected |
| Fill | the current 7 percent tint stays |
| Header | the band, the name and the reduction chip stay |
| Boundary chip | a `Privilege` chip in the header when `boundaryId == "privilege"` |
| Badge | the open count for `zone:<id>`, in the header |

The dash no longer states public against private, because every zone is dashed.
The stroke colour states it, as it partly did already.

### 6.3 A flow

| Part | Rule |
| --- | --- |
| Curve | the current bezier, unchanged |
| Colour | `RiskPalette.colour(forLevelId:)` of the highest level on `connection:<id>`, else `Color.secondary` |
| Label | the description when set, else the `FlowKind` label |
| Label ground | a pill in the canvas background colour, so the line does not cross the text |
| Badge | the open count, beside the label |
| Out of scope | grey and dashed when either endpoint has `threatsDisabled` |

## 7. The panel

`ComponentPanel` gains one picker, between the name field and the sensitivity
picker:

```
Shape  ( Auto — Process  ▾ )
         Auto
         Actor
         Process
         Store
```

**Auto** writes `nil`. The label states what **Auto** currently resolves to, so
a user who forces the value the map already gives sees no change and knows it.

Accessibility identifier: `component-shape`.

## 8. Persistence

### 8.1 The model file

`ComponentJSON` gains `let shape: String?`. Absent means derived. The format
version stays 5, the way `runsAs` and `assets` were added: an optional field a
reader ignores when it is absent.

A file the new build writes and an older build reads loses the override on the
next save by that older build. This matches the `runsAs` precedent and needs no
migration.

### 8.2 The architecture language

`SourceComponent` gains `shape: String?`. The parser takes one more attribute
in a `component` block:

```hcl
component "customer_db" {
  technology = "aws.rds"
  data       = "restricted"
  shape      = "store"
}
```

The vocabulary is `actor`, `process`, `store`. An unknown word records the
error the other vocabulary attributes record, through `expectVocabulary`.

`ArchitectureWriter.componentBlock` writes `shape` only when the source states
one, so a rewrite of an unchanged file still produces no diff.

`docs/LANGUAGE.md` gains the attribute, because that document states every word
the parsers accept.

## 9. The report

`CanvasPicture` and `CanvasImageRenderer` draw through the same shape code as
the canvas, so the diagram in the PDF and the diagram on screen are the same
picture.

## 10. What this design does not do

- It reads no Threat Dragon `.json` file and writes none.
- It adds no second diagram to a model.
- It adds no LINDDUN, PLOT4ai, CIA or DIE diagram kind.
- It adds no out-of-scope reason text. `threatsDisabled` stays a flag.
- It adds no bidirectional flow. Two directions stay two connections, as
  `ConnectComponents` already requires.
- It adds no freeform boundary curve. A curve states no inside and no outside,
  so nothing can be contained by it and nothing can be scored from it.

## 11. Testing

Test first, in this order.

Core, in `ThreatModelKit/Tests/UnitTests`:

- `DiagramShapeTests` — the map gives actor, store and process for the provider
  and the categories that select them; an unknown technology gives process; an
  override beats the map; `resolvedShape` returns the override.
- `ElementRiskRollupTests` — an element with no threats; one open threat; one
  threat answered by an implemented control; one threat whose only controls are
  `not_applicable` and `accepted`; a threat with no controls; the highest level
  across several threats; counts across components, connections and zones.
- `ComponentFootprintTests` — each shape's footprint; the centre is the same
  point for all three.
- `SetComponentPropertiesTests` — the shape writes; `nil` clears it; an unknown
  word returns `.unknownShape`.
- `LayOutModelTests` — the wider row gap; a generated zone still holds its
  contents.
- `ThreatModelCodec` round trip with a shape set and with it absent; a version 5
  file with no `shape` key reads.
- `ArchitectureParser` and `ArchitectureWriter` round trip; an unknown shape
  word records an error; an unchanged file rewrites with no diff.

Application, in `threatmodellerTests`:

- `ComponentBox` — the footprint per shape; a click in the corner of a
  process's bounding square misses; a click inside the circle hits.
- `CanvasHitTest.contentSize` includes the circle overflow.

User interface, in `threatmodellerUITests`:

- The shape picker is present, and choosing **Store** redraws the node.

## 12. Files this touches

New:

- `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/DiagramShape.swift`
- `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ElementRiskRollup.swift`
- `threatmodeller/canvas/ComponentShapePath.swift`

Changed, core:

- `modelling/domain/Component.swift`
- `modelling/usecase/SetComponentProperties.swift`
- `modelling/usecase/ViewThreatModel.swift`
- `architecture/usecase/LayOutModel.swift`
- `architecture/usecase/ImportArchitecture.swift`
- `ArchitectureDSL/ArchitectureParser.swift`, `ArchitectureWriter.swift`
- `FileGateways/DocumentJSON.swift`, `ThreatModelCodec.swift`

Changed, application:

- `canvas/ComponentBox.swift`, `ComponentNodeView.swift`, `AnchorGeometry.swift`,
  `CanvasHitTest.swift`, `ConnectionsLayer.swift`, `ZoneView.swift`,
  `ComponentPanel.swift`, `CanvasView.swift`
- `reporting/CanvasPicture.swift`, `CanvasImageRenderer.swift`
- `ThreatModelSession.swift`

Changed, documentation:

- `docs/LANGUAGE.md`
