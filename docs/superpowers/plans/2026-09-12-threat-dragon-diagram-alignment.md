# Threat Dragon diagram alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Draw each component as one of the three data flow diagram shapes OWASP Threat Dragon uses, and paint the risk each element carries into its outline and a badge.

**Architecture:** The core owns the shape, because the shape decides the footprint and the footprint is what a reader clicks. A component's centre never moves, so nothing saved moves and the zone containment rule is untouched. A pure core type turns the assessed threats into one risk value per element, and the canvas paints from that value.

**Tech Stack:** Swift 6, SwiftUI, macOS. Package `ThreatModelKit`. Tests use `swift-testing` (`import Testing`, `@Test`, `#expect`).

**Spec:** `docs/superpowers/specs/2026-09-12-threat-dragon-diagram-alignment-design.md`

## Global Constraints

- Every commit runs `cd ThreatModelKit && swift test` first. It must pass.
- After adding any file to `ThreatModelKit`, run
  `xcodebuild clean -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
  once before the application tests. `docs/TESTING.md` states why.
- Application tests:
  `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
- There are no interface journey tests on this machine. A view is proved by
  `threatmodellerTests/ViewRenderTests.swift`, which draws it and reads the
  pixels back.
- Commit with `git -c commit.gpgsign=false commit`. The signing key needs Touch
  ID and is not available to this session.
- The shape vocabulary is exactly `actor`, `process`, `store`.
- The store categories are exactly `database`, `storage`, `secrets`.
- The actor provider is exactly `actor`.
- Footprints: actor 160 by 72, process 104 by 104, store 160 by 64.
- `Component.size` stays `Size(width: 160, height: 72)`.
- The centre stays `position + (80, 36)` for every shape.
- Write every comment and commit body in the house style of the surrounding
  code: active voice, present tense, one instruction per sentence.

---

### Task 1: `DiagramShape`, the derivation map, and the footprint

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/DiagramShape.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Component.swift`
- Test: `ThreatModelKit/Tests/UnitTests/DiagramShapeTests.swift`

**Interfaces:**
- Consumes: `Size` from `modelling/domain/Rect.swift`.
- Produces: `DiagramShape`, `DiagramShapeMap.derived(providerId:categoryId:)`,
  `Component.shape`, `Component.resolvedShape(providerId:categoryId:)`,
  `Component.footprint(for:)`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/DiagramShapeTests.swift`:

```swift
import Testing
import ThreatModelKit

@Suite("What shape a component draws as")
struct DiagramShapeTests {
    @Test func drawsAnActorProviderAsAnActor() {
        #expect(DiagramShapeMap.derived(providerId: "actor", categoryId: "person") == .actor)
        #expect(DiagramShapeMap.derived(providerId: "actor", categoryId: "system") == .actor)
    }

    @Test func drawsAStoreCategoryAsAStore() {
        #expect(DiagramShapeMap.derived(providerId: "aws", categoryId: "database") == .store)
        #expect(DiagramShapeMap.derived(providerId: "aws", categoryId: "storage") == .store)
        #expect(DiagramShapeMap.derived(providerId: "aws", categoryId: "secrets") == .store)
    }

    @Test func drawsEverythingElseAsAProcess() {
        #expect(DiagramShapeMap.derived(providerId: "aws", categoryId: "compute") == .process)
        #expect(DiagramShapeMap.derived(providerId: "gcp", categoryId: "messaging") == .process)
    }

    @Test func drawsAnUnknownTechnologyAsAProcess() {
        #expect(DiagramShapeMap.derived(providerId: "", categoryId: "") == .process)
    }

    @Test func takesTheUsersOwnShapeOverTheMap() {
        let component = Component(
            id: ComponentId("c1"),
            technologyId: TechnologyId("aws-rds"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData,
            shape: .process
        )

        #expect(component.resolvedShape(providerId: "aws", categoryId: "database") == .process)
    }

    @Test func fallsBackToTheMapWhenTheUserStatesNoShape() {
        let component = Component(
            id: ComponentId("c1"),
            technologyId: TechnologyId("aws-rds"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )

        #expect(component.shape == nil)
        #expect(component.resolvedShape(providerId: "aws", categoryId: "database") == .store)
    }

    @Test func givesEachShapeItsOwnFootprint() {
        #expect(Component.footprint(for: .actor) == Size(width: 160, height: 72))
        #expect(Component.footprint(for: .process) == Size(width: 104, height: 104))
        #expect(Component.footprint(for: .store) == Size(width: 160, height: 64))
    }

    @Test func keepsTheCentreInTheSamePlaceForEveryShape() {
        let component = Component(
            id: ComponentId("c1"),
            technologyId: TechnologyId("aws-rds"),
            position: Point(x: 200, y: 100),
            sensitivity: .internalData
        )

        #expect(component.centre == Point(x: 280, y: 136))
        #expect(Component.size == Size(width: 160, height: 72))
    }

    @Test func readsEveryShapeFromItsWord() {
        #expect(DiagramShape(rawValue: "actor") == .actor)
        #expect(DiagramShape(rawValue: "process") == .process)
        #expect(DiagramShape(rawValue: "store") == .store)
        #expect(DiagramShape(rawValue: "cylinder") == nil)
        #expect(DiagramShape.allCases.count == 3)
    }
}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `cd ThreatModelKit && swift test --filter DiagramShapeTests`
Expected: FAIL. The compiler cannot find `DiagramShapeMap` or `DiagramShape`.

- [ ] **Step 3: Write the enumeration and the map**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/DiagramShape.swift`:

```swift
/// The data flow diagram shape a component draws as.
///
/// Application-owned, as `DataSensitivity` and `NetworkZone` are: the
/// catalogue carries no shape vocabulary, and `scripts/update-catalogue.sh`
/// overwrites the vendored library on every refresh.
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

/// Which shape a technology draws as when the user states none.
public enum DiagramShapeMap {
    /// The provider the actors library uses. Every technology under it is a
    /// person, a client, a device or another system.
    public static let actorProvider = "actor"

    /// The categories that hold data at rest.
    public static let storeCategories: Set<String> = ["database", "storage", "secrets"]

    /// A component whose technology the catalogue no longer holds carries an
    /// empty provider and an empty category, so it draws as a process.
    public static func derived(providerId: String, categoryId: String) -> DiagramShape {
        if providerId == actorProvider { return .actor }
        if storeCategories.contains(categoryId) { return .store }
        return .process
    }
}
```

- [ ] **Step 4: Add the field, the resolution and the footprint**

In `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Component.swift`, add
the stored property after `runsAs`:

```swift
    /// The shape the user forced, or nil to let `DiagramShapeMap` decide.
    public var shape: DiagramShape?
```

Add `shape: DiagramShape? = nil` to the initialiser parameter list after
`runsAs`, and `self.shape = shape` to its body.

Add these members to `Component`:

```swift
    /// The size each shape draws at. `size` stays the slot the component
    /// occupies in a layout; this is what the canvas paints, and it centres on
    /// the same point.
    public static func footprint(for shape: DiagramShape) -> Size {
        switch shape {
        case .actor: Size(width: 160, height: 72)
        case .process: Size(width: 104, height: 104)
        case .store: Size(width: 160, height: 64)
        }
    }

    /// The shape to draw: the user's own choice, else the map's answer.
    public func resolvedShape(providerId: String, categoryId: String) -> DiagramShape {
        shape ?? DiagramShapeMap.derived(providerId: providerId, categoryId: categoryId)
    }
```

- [ ] **Step 5: Run the test to see it pass**

Run: `cd ThreatModelKit && swift test --filter DiagramShapeTests`
Expected: PASS.

- [ ] **Step 6: Run the whole package**

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/modelling/domain/DiagramShape.swift \
        ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Component.swift \
        ThreatModelKit/Tests/UnitTests/DiagramShapeTests.swift
git -c commit.gpgsign=false commit -m "feat: a component states which data flow diagram shape it draws as"
```

---

### Task 2: The shape reaches the canvas and the panel writes it

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/ViewThreatModel.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/SetComponentProperties.swift`
- Test: `ThreatModelKit/Tests/UnitTests/SetComponentPropertiesTests.swift`

**Interfaces:**
- Consumes: `DiagramShape`, `Component.resolvedShape(providerId:categoryId:)` from Task 1.
- Produces: `ViewedComponent.shapeId: String`, `ViewedComponent.shapeOverrideId: String?`,
  `SetComponentPropertiesRequest.shape: String?`,
  `SetComponentPropertiesResponse.unknownShape`.

- [ ] **Step 1: Write the failing test**

Add to `ThreatModelKit/Tests/UnitTests/SetComponentPropertiesTests.swift`. First
extend the private `set` helper with the new argument:

```swift
    private func set(
        _ componentId: String,
        name: String? = nil,
        sensitivity: String = "internal",
        threatsDisabled: Bool = false,
        runsAs: String = "user",
        shape: String? = nil
    ) -> SetComponentPropertiesResponse {
        app.setComponentProperties().execute(
            SetComponentPropertiesRequest(
                componentId: componentId,
                name: name,
                sensitivity: sensitivity,
                threatsDisabled: threatsDisabled,
                runsAs: runsAs,
                shape: shape
            )
        )
    }
```

Then add the tests:

```swift
    @Test func forcesTheShapeTheUserPicks() {
        let componentId = aComponent()

        #expect(set(componentId, shape: "store") == .updated)

        let component = app.viewThreatModel().execute(ViewThreatModelRequest())
            .components.first { $0.id == componentId }
        #expect(component?.shapeId == "store")
        #expect(component?.shapeOverrideId == "store")
    }

    @Test func goesBackToTheDerivedShapeWhenTheUserPicksAuto() {
        let componentId = aComponent()
        _ = set(componentId, shape: "store")

        #expect(set(componentId, shape: nil) == .updated)

        let component = app.viewThreatModel().execute(ViewThreatModelRequest())
            .components.first { $0.id == componentId }
        #expect(component?.shapeId == "process")
        #expect(component?.shapeOverrideId == nil)
    }

    @Test func refusesAShapeThisApplicationDoesNotHold() {
        let componentId = aComponent()

        #expect(set(componentId, shape: "cylinder") == .unknownShape)
    }
```

The technology `aws-ec2` in `CatalogueFixture` carries provider `aws` and
category `compute`, so its derived shape is `process`.

- [ ] **Step 2: Run the test to see it fail**

Run: `cd ThreatModelKit && swift test --filter SetComponentPropertiesTests`
Expected: FAIL. `SetComponentPropertiesRequest` has no `shape` argument.

- [ ] **Step 3: Take the shape in the use case**

In `SetComponentProperties.swift`, add to `SetComponentPropertiesRequest`:

```swift
    /// The shape the user forced, or nil to let the derivation decide.
    public let shape: String?
```

Add `shape: String? = nil` to the initialiser after `runsAs`, and
`self.shape = shape` to its body.

Add the case to the response:

```swift
    case unknownShape
```

In `execute`, after the `runsAs` guard:

```swift
        var shape: DiagramShape?
        if let word = request.shape {
            guard let picked = DiagramShape(rawValue: word) else { return .unknownShape }
            shape = picked
        }
```

and inside `models.mutate`, after the `runsAs` line:

```swift
            model.components[index].shape = shape
```

- [ ] **Step 4: Show the shape on the viewed component**

In `ViewThreatModel.swift`, add to `ViewedComponent`:

```swift
    /// The shape to draw: actor, process or store. Already resolved.
    public let shapeId: String
    /// Only the shape the user forced, or nil. The panel needs to tell **Auto**
    /// from a forced value the derivation would have given anyway.
    public let shapeOverrideId: String?
```

Add them to the initialiser after `zoneId`, with
`shapeId: String = DiagramShape.process.rawValue` and
`shapeOverrideId: String? = nil` so the existing test call sites still build.

In `execute`, inside the components map, compute the resolved shape from the
provider and the category already worked out there:

```swift
                let providerId = technology?.provider.value ?? ""
                let categoryId = technology?.category.value ?? ""
```

Use those two names for the `providerId:` and `categoryId:` arguments, and pass:

```swift
                    shapeId: component.resolvedShape(
                        providerId: providerId,
                        categoryId: categoryId
                    ).rawValue,
                    shapeOverrideId: component.shape?.rawValue
```

- [ ] **Step 5: Run the test to see it pass**

Run: `cd ThreatModelKit && swift test --filter SetComponentPropertiesTests`
Expected: PASS.

- [ ] **Step 6: Run the whole package**

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/ViewThreatModel.swift \
        ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/SetComponentProperties.swift \
        ThreatModelKit/Tests/UnitTests/SetComponentPropertiesTests.swift
git -c commit.gpgsign=false commit -m "feat: the node panel writes the shape and the canvas reads it"
```

---

### Task 3: The element risk rollup

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ElementRiskRollup.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ElementRiskRollupTests.swift`

**Interfaces:**
- Consumes: `AssessedThreat`, `AssessedControl`, `AssessedThreatSource`,
  `AssessedSeverity` from `assessment/usecase/AssessThreatModel.swift`.
- Produces: `ElementRisk` with `sourceId`, `openCount`, `totalCount`,
  `highestLevelId`; `ElementRiskRollup.byElement(_:levelOrder:)`.

The taxonomy states the severity order, and the risk level ids are the severity
ids. `AssessThreatModelResponse.severities` arrives in taxonomy order, weakest
first, so the caller passes those ids and the rollup states no order of its own.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ElementRiskRollupTests.swift`:

```swift
import Testing
import ThreatModelKit

@Suite("What risk one element on the diagram carries")
struct ElementRiskRollupTests {
    private let levelOrder = ["low", "medium", "high", "critical"]

    private func control(_ status: String) -> AssessedControl {
        AssessedControl(
            description: "a control",
            isTechnologySpecific: false,
            key: "k-\(status)",
            isImplemented: status == "implemented",
            statusId: status,
            statusLabel: status
        )
    }

    private func threat(
        _ threatId: String,
        source: AssessedThreatSource,
        level: String,
        controls: [AssessedControl]
    ) -> AssessedThreat {
        AssessedThreat(
            threatId: threatId,
            name: threatId,
            description: "",
            severityId: level,
            severityLabel: level,
            stride: [],
            mitreTechniques: [],
            controls: controls,
            source: source,
            sensitivityId: "internal",
            riskScore: 10,
            riskLevel: level,
            context: nil,
            isTlsMitigated: false,
            overrideKey: "o-\(threatId)",
            overriddenSeverityId: nil
        )
    }

    private let node = AssessedThreatSource.component(
        id: "c1", name: "EC2", providerId: "aws"
    )

    @Test func statesNothingForAnElementThatRaisesNoThreat() {
        let risks = ElementRiskRollup.byElement([], levelOrder: levelOrder)

        #expect(risks.isEmpty)
    }

    @Test func countsAThreatWithNoControlAsOpen() {
        let risks = ElementRiskRollup.byElement(
            [threat("t1", source: node, level: "high", controls: [])],
            levelOrder: levelOrder
        )

        #expect(risks["component:c1"]?.openCount == 1)
        #expect(risks["component:c1"]?.totalCount == 1)
        #expect(risks["component:c1"]?.highestLevelId == "high")
    }

    @Test func countsAThreatWithAnImplementedControlAsAnswered() {
        let risks = ElementRiskRollup.byElement(
            [
                threat(
                    "t1",
                    source: node,
                    level: "medium",
                    controls: [control("not_implemented"), control("implemented")]
                )
            ],
            levelOrder: levelOrder
        )

        #expect(risks["component:c1"]?.openCount == 0)
        #expect(risks["component:c1"]?.totalCount == 1)
        #expect(risks["component:c1"]?.highestLevelId == "medium")
    }

    @Test func countsAThreatEveryControlOfWhichIsSetAsideAsAnswered() {
        let risks = ElementRiskRollup.byElement(
            [
                threat(
                    "t1",
                    source: node,
                    level: "low",
                    controls: [control("not_applicable"), control("accepted")]
                )
            ],
            levelOrder: levelOrder
        )

        #expect(risks["component:c1"]?.openCount == 0)
    }

    @Test func countsAThreatWithOneUnansweredControlAsOpen() {
        let risks = ElementRiskRollup.byElement(
            [
                threat(
                    "t1",
                    source: node,
                    level: "low",
                    controls: [control("not_applicable"), control("not_implemented")]
                )
            ],
            levelOrder: levelOrder
        )

        #expect(risks["component:c1"]?.openCount == 1)
    }

    @Test func takesTheHighestLevelOfEveryThreatOnTheElement() {
        let risks = ElementRiskRollup.byElement(
            [
                threat("t1", source: node, level: "low", controls: []),
                threat("t2", source: node, level: "critical", controls: [control("implemented")]),
                threat("t3", source: node, level: "medium", controls: [])
            ],
            levelOrder: levelOrder
        )

        #expect(risks["component:c1"]?.highestLevelId == "critical")
        #expect(risks["component:c1"]?.openCount == 2)
        #expect(risks["component:c1"]?.totalCount == 3)
    }

    @Test func keepsAConnectionAndAZoneApartFromAComponent() {
        let risks = ElementRiskRollup.byElement(
            [
                threat("t1", source: node, level: "low", controls: []),
                threat(
                    "t2",
                    source: .connection(id: "f1", sourceName: "A", targetName: "B"),
                    level: "high",
                    controls: []
                ),
                threat(
                    "t3",
                    source: .zone(id: "z1", name: "Private"),
                    level: "medium",
                    controls: []
                )
            ],
            levelOrder: levelOrder
        )

        #expect(risks.count == 3)
        #expect(risks["connection:f1"]?.highestLevelId == "high")
        #expect(risks["zone:z1"]?.highestLevelId == "medium")
    }

    @Test func keepsALevelTheOrderDoesNotNameRatherThanDroppingIt() {
        let risks = ElementRiskRollup.byElement(
            [threat("t1", source: node, level: "unrated", controls: [])],
            levelOrder: levelOrder
        )

        #expect(risks["component:c1"]?.highestLevelId == "unrated")
    }
}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `cd ThreatModelKit && swift test --filter ElementRiskRollupTests`
Expected: FAIL. The compiler cannot find `ElementRiskRollup`.

- [ ] **Step 3: Write the rollup**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ElementRiskRollup.swift`:

```swift
/// What one element on the diagram carries, in the form the canvas paints.
public struct ElementRisk: Equatable, Sendable {
    /// "component:<id>", "connection:<id>" or "zone:<id>".
    public let sourceId: String
    /// Threats on this element that no control answers.
    public let openCount: Int
    public let totalCount: Int
    /// The highest residual level on this element. `AssessedThreat.riskLevel`
    /// is already residual, so nothing here re-applies a control.
    public let highestLevelId: String?

    public init(sourceId: String, openCount: Int, totalCount: Int, highestLevelId: String?) {
        self.sourceId = sourceId
        self.openCount = openCount
        self.totalCount = totalCount
        self.highestLevelId = highestLevelId
    }
}

/// Turns the assessed threats into one value per element.
///
/// The canvas needs a colour and a count for every node, flow and zone. The
/// rule that decides them lives here, so a test runs it without a window.
public enum ElementRiskRollup {
    /// A threat is answered when one control is implemented, or when every
    /// control it has is set aside. A threat with no control at all is open.
    public static func isOpen(_ threat: AssessedThreat) -> Bool {
        if threat.controls.isEmpty { return true }
        if threat.controls.contains(where: { $0.statusId == ControlStatus.implemented.rawValue }) {
            return false
        }
        return threat.controls.contains { control in
            control.statusId != ControlStatus.notApplicable.rawValue
                && control.statusId != ControlStatus.accepted.rawValue
        }
    }

    /// `levelOrder` runs weakest first, as the taxonomy states the severities.
    /// A level the order does not name sorts below every level it does name,
    /// and is still reported rather than dropped.
    public static func byElement(
        _ threats: [AssessedThreat],
        levelOrder: [String]
    ) -> [String: ElementRisk] {
        func rank(_ levelId: String) -> Int {
            levelOrder.firstIndex(of: levelId) ?? -1
        }

        var built: [String: ElementRisk] = [:]

        for threat in threats {
            let sourceId = threat.source.id
            let held = built[sourceId]
            let highest: String?

            if let current = held?.highestLevelId, rank(current) >= rank(threat.riskLevel) {
                highest = current
            } else {
                highest = threat.riskLevel
            }

            built[sourceId] = ElementRisk(
                sourceId: sourceId,
                openCount: (held?.openCount ?? 0) + (isOpen(threat) ? 1 : 0),
                totalCount: (held?.totalCount ?? 0) + 1,
                highestLevelId: highest
            )
        }

        return built
    }
}
```

If `ControlStatus` is not `public`, use the literal words `"implemented"`,
`"not_applicable"` and `"accepted"` instead. Check with
`grep -n "enum ControlStatus" -A 12 ThreatModelKit/Sources/ThreatModelKit/assessment/domain/*.swift`.

- [ ] **Step 4: Run the test to see it pass**

Run: `cd ThreatModelKit && swift test --filter ElementRiskRollupTests`
Expected: PASS.

- [ ] **Step 5: Run the whole package**

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ElementRiskRollup.swift \
        ThreatModelKit/Tests/UnitTests/ElementRiskRollupTests.swift
git -c commit.gpgsign=false commit -m "feat: state the risk and the open threat count of one element"
```

---

### Task 4: The shape saves and reloads

**Files:**
- Modify: `ThreatModelKit/Sources/FileGateways/DocumentJSON.swift:89-99`
- Modify: `ThreatModelKit/Sources/FileGateways/ThreatModelCodec.swift:295-310`, `:360-380`
- Test: `ThreatModelKit/Tests/UnitTests/ThreatModelCodecShapeTests.swift`

**Interfaces:**
- Consumes: `Component.shape` from Task 1.
- Produces: the optional `shape` key in `ComponentJSON`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ThreatModelCodecShapeTests.swift`. Copy
the encode and decode helpers from the existing codec tests. Run
`ls ThreatModelKit/Tests/UnitTests | grep -i codec` and read the file it names
so the helper names match.

```swift
import Foundation
import Testing
import FileGateways
import ThreatModelKit

@Suite("Saving and reloading the shape a component draws as")
struct ThreatModelCodecShapeTests {
    private func model(shape: DiagramShape?) -> ThreatModel {
        var model = ThreatModel(name: "Shapes")
        model.components = [
            Component(
                id: ComponentId("c1"),
                technologyId: TechnologyId("aws-rds"),
                position: Point(x: 10, y: 20),
                sensitivity: .internalData,
                shape: shape
            )
        ]
        return model
    }

    @Test func keepsTheShapeAcrossASaveAndAReload() throws {
        let data = try ThreatModelCodec.data(from: model(shape: .store))
        let read = try ThreatModelCodec.model(from: data)

        #expect(read.components.first?.shape == .store)
    }

    @Test func writesNoShapeKeyWhenTheUserStatesNone() throws {
        let data = try ThreatModelCodec.data(from: model(shape: nil))
        let text = String(decoding: data, as: UTF8.self)

        #expect(text.contains("\"shape\"") == false)
    }

    @Test func readsAFileThatStatesNoShape() throws {
        let data = try ThreatModelCodec.data(from: model(shape: nil))
        let read = try ThreatModelCodec.model(from: data)

        #expect(read.components.first?.shape == nil)
    }

    @Test func refusesAShapeWordThisApplicationDoesNotHold() throws {
        let data = try ThreatModelCodec.data(from: model(shape: .store))
        let broken = String(decoding: data, as: UTF8.self)
            .replacingOccurrences(of: "\"store\"", with: "\"cylinder\"")

        #expect(throws: (any Error).self) {
            try ThreatModelCodec.model(from: Data(broken.utf8))
        }
    }
}
```

Correct the two static call names to whatever the existing codec test uses.

- [ ] **Step 2: Run the test to see it fail**

Run: `cd ThreatModelKit && swift test --filter ThreatModelCodecShapeTests`
Expected: FAIL. `Component` takes no `shape` in the codec, and the key is never
written.

- [ ] **Step 3: Add the key**

In `DocumentJSON.swift`, add to `ComponentJSON` after `runsAs`:

```swift
    /// The shape the user forced. Absent means the derivation decides.
    let shape: String?
```

- [ ] **Step 4: Write it and read it**

In `ThreatModelCodec.swift`, in `json(from component:)` add
`shape: component.shape?.rawValue` after `runsAs:`.

In `component(from json:)` add after `runsAs:`:

```swift
            shape: try optionalValue(
                DiagramShape.self,
                field: "shape",
                raw: json.shape,
                default: nil
            ),
```

Read the current signature of `optionalValue` first. It is used for `runsAs`
with a non-optional default. If it cannot return `nil`, write the branch
directly instead:

```swift
            shape: try Self.shape(from: json.shape),
```

with:

```swift
    private static func shape(from raw: String?) throws -> DiagramShape? {
        guard let raw else { return nil }
        guard let shape = DiagramShape(rawValue: raw) else {
            throw ThreatModelCodecError.unknownValue(field: "shape", raw: raw)
        }
        return shape
    }
```

Use the error case the file already throws for an unknown word. Find it with
`grep -n "func value" -A 12 ThreatModelKit/Sources/FileGateways/ThreatModelCodec.swift`.

The encoder must drop a `nil` key. Check the encoder settings with
`grep -n "JSONEncoder\|outputFormatting" ThreatModelKit/Sources/FileGateways/ThreatModelCodec.swift`.
Swift's `JSONEncoder` omits a `nil` optional by default, so no change should be
needed. If the test in Step 1 fails on the key being present, the file writes a
custom `encode(to:)`; follow the pattern the other optional keys use.

- [ ] **Step 5: Run the test to see it pass**

Run: `cd ThreatModelKit && swift test --filter ThreatModelCodecShapeTests`
Expected: PASS.

- [ ] **Step 6: Run the whole package**

Run: `cd ThreatModelKit && swift test`
Expected: PASS. The selection snippet path in the same file uses the same two
helpers, so a copy and a paste of a node keeps its shape with no further change.

- [ ] **Step 7: Commit**

```bash
git add ThreatModelKit/Sources/FileGateways/DocumentJSON.swift \
        ThreatModelKit/Sources/FileGateways/ThreatModelCodec.swift \
        ThreatModelKit/Tests/UnitTests/ThreatModelCodecShapeTests.swift
git -c commit.gpgsign=false commit -m "feat: the model file holds the shape a component draws as"
```

---

### Task 5: The architecture language states the shape

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ArchitectureSource.swift:107-133`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ArchitectureParser.swift:245-265`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ArchitectureWriter.swift:123-135`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ImportArchitecture.swift`
- Modify: `docs/LANGUAGE.md`
- Test: `ThreatModelKit/Tests/UnitTests/ArchitectureShapeTests.swift`

**Interfaces:**
- Consumes: `DiagramShape` from Task 1.
- Produces: `SourceComponent.shape: String?`, the `shape` attribute in a
  `component` block.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ArchitectureShapeTests.swift`:

```swift
import Testing
import ArchitectureDSL
import ThreatModelKit

@Suite("Stating the diagram shape in an architecture file")
struct ArchitectureShapeTests {
    private let text = """
    component "customer_db" {
      technology = "aws.rds"
      data       = "restricted"
      shape      = "store"
    }
    """

    @Test func readsTheShapeFromAComponentBlock() throws {
        let parsed = ArchitectureParser(text: text).parse()

        #expect(parsed.problems.isEmpty)
        #expect(parsed.source?.components.first?.shape == "store")
    }

    @Test func statesNoShapeWhenTheBlockNamesNone() throws {
        let parsed = ArchitectureParser(
            text: """
            component "web" {
              technology = "aws.ec2"
              data       = "internal"
            }
            """
        ).parse()

        #expect(parsed.source?.components.first?.shape == nil)
    }

    @Test func refusesAShapeWordTheApplicationDoesNotHold() throws {
        let parsed = ArchitectureParser(
            text: text.replacingOccurrences(of: "store", with: "cylinder")
        ).parse()

        #expect(parsed.problems.isEmpty == false)
    }

    @Test func writesTheShapeBackOnlyWhenTheSourceStatesOne() throws {
        let parsed = ArchitectureParser(text: text).parse()
        let written = ArchitectureWriter().text(for: try #require(parsed.source))

        #expect(written.contains("shape = \"store\""))

        let again = ArchitectureParser(text: written).parse()
        #expect(again.source == parsed.source)
    }
}
```

Read `ThreatModelKit/Tests/UnitTests/ControlsParserTests.swift` and any existing
architecture parser test first, and match the exact way they build a parser and
read the result. The names `ArchitectureParser(text:)`, `.parse()`,
`.problems`, `.source` and `ArchitectureWriter().text(for:)` are a guess from
the writer's shape; correct them to the real ones before writing the test.

- [ ] **Step 2: Run the test to see it fail**

Run: `cd ThreatModelKit && swift test --filter ArchitectureShapeTests`
Expected: FAIL. The parser records `a component holds technology, name, data,
threats, runs_as and asset, not "shape"`.

- [ ] **Step 3: Add the field to the source type**

In `ArchitectureSource.swift`, add to `SourceComponent`:

```swift
    /// The diagram shape the file forces, or nil to let the derivation decide.
    public let shape: String?
```

Add `shape: String? = nil` to the initialiser after `runsAs`, and
`self.shape = shape` to its body.

- [ ] **Step 4: Read it in the parser**

In `ArchitectureParser.swift`, in the component block switch, add a case beside
`"runs_as"`:

```swift
            case "shape":
                shape = parseTextAttribute()
                expectVocabulary(shape, Self.diagramShapes, field: "shape", at: token)
```

Declare `var shape: String?` beside the other locals in that function, pass
`shape: shape` to the `SourceComponent` it builds, and add the vocabulary beside
`Self.privilegeLevels`:

```swift
    static let diagramShapes = ["actor", "process", "store"]
```

Update the error text in the `default` case of that switch:

```swift
                record("a component holds technology, name, data, threats, runs_as, shape and asset, not \"\(current.text)\"")
```

- [ ] **Step 5: Write it in the writer**

In `ArchitectureWriter.componentBlock`, after the `runs_as` line:

```swift
        if let shape = component.shape { attributes.append(("shape", quoted(shape))) }
```

- [ ] **Step 6: Carry it into the model**

In `ImportArchitecture.swift`, find where it builds a `Component` from a
`SourceComponent` and pass:

```swift
                shape: source.shape.flatMap(DiagramShape.init(rawValue:)),
```

Find the line with
`grep -n "Component(" ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ImportArchitecture.swift`.

- [ ] **Step 7: Run the test to see it pass**

Run: `cd ThreatModelKit && swift test --filter ArchitectureShapeTests`
Expected: PASS.

- [ ] **Step 8: Write the attribute into the language guide**

In `docs/LANGUAGE.md`, find the `component` block section. Add a row beside
`runs_as`, in the same table and the same wording style:

```markdown
| `shape` | `actor`, `process`, `store` | The data flow diagram shape the canvas draws. Absent lets the technology's provider and category decide: the `actor` provider gives an actor, the `database`, `storage` and `secrets` categories give a store, everything else gives a process. |
```

Match the table's real column headings. Read the surrounding rows first.

- [ ] **Step 9: Run the whole package**

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ArchitectureSource.swift \
        ThreatModelKit/Sources/ArchitectureDSL/ArchitectureParser.swift \
        ThreatModelKit/Sources/ArchitectureDSL/ArchitectureWriter.swift \
        ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ImportArchitecture.swift \
        ThreatModelKit/Tests/UnitTests/ArchitectureShapeTests.swift \
        docs/LANGUAGE.md
git -c commit.gpgsign=false commit -m "feat: an architecture file states the shape a component draws as"
```

---

### Task 6: A generated layout and an exported image hold a circle

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/LayOutModel.swift:57-62`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsImage.swift:68-74`
- Test: `ThreatModelKit/Tests/UnitTests/LayOutModelTests.swift`

**Interfaces:**
- Consumes: `Component.footprint(for:)` from Task 1.
- Produces: `LayOutModel.rowGap == 72`; an export area that holds the tallest
  footprint.

A process circle passes the 160 by 72 slot by 16 points above and 16 below. A
row gap of 72 leaves 40 points between two circles in neighbouring rows. The
export area grows by the same overflow, so a circle at the edge of a diagram is
never clipped.

- [ ] **Step 1: Write the failing test**

Add to `ThreatModelKit/Tests/UnitTests/LayOutModelTests.swift`:

```swift
    @Test func leavesRoomBetweenRowsForAProcessCircle() {
        let tallest = Component.footprint(for: .process).height
        let overflow = (tallest - Component.size.height) / 2

        #expect(LayOutModel.rowGap > overflow * 2)
    }
```

Add to a new file `ThreatModelKit/Tests/UnitTests/ExportModelAsImageShapeTests.swift`,
or to the existing export test if one is present:

```swift
import Testing
import ThreatModelKit
import TestSupport

@Suite("The area an exported picture covers")
struct ExportModelAsImageShapeTests {
    @Test func holdsTheTallestFootprintAroundAComponent() {
        let app = TestDependencies()
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )

        let area = app.exportModelAsImage().execute(ExportModelAsImageRequest())
        let tallest = Component.footprint(for: .process).height

        #expect(area.height >= tallest)
    }
}
```

Correct `app.exportModelAsImage()` and `ExportModelAsImageRequest()` to the real
names. Find them with
`grep -n "exportModelAsImage" ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`.

- [ ] **Step 2: Run the tests to see them fail**

Run: `cd ThreatModelKit && swift test --filter LayOutModelTests`
Run: `cd ThreatModelKit && swift test --filter ExportModelAsImageShapeTests`
Expected: FAIL on both. `rowGap` is 48, and the export area is 72 tall.

- [ ] **Step 3: Widen the row gap**

In `LayOutModel.swift`:

```swift
    /// A row leaves room for the tallest footprint, which is the process
    /// circle. The circle passes the 160 by 72 slot by 16 points above and 16
    /// below, so a gap of 48 would leave two circles 16 points apart.
    static let rowGap = 72.0
```

- [ ] **Step 4: Grow the export area**

In `ExportModelAsImage.swift`, replace the component loop:

```swift
        // The tallest and the widest footprint, because a component's shape is
        // not known here and a circle passes the slot above and below.
        let widest = DiagramShape.allCases.map { Component.footprint(for: $0).width }.max() ?? 0
        let tallest = DiagramShape.allCases.map { Component.footprint(for: $0).height }.max() ?? 0

        for component in model.components {
            hold(
                x: component.centre.x - widest / 2,
                y: component.centre.y - tallest / 2,
                width: widest,
                height: tallest
            )
        }
```

- [ ] **Step 5: Run the tests to see them pass**

Run: `cd ThreatModelKit && swift test --filter LayOutModelTests`
Run: `cd ThreatModelKit && swift test --filter ExportModelAsImageShapeTests`
Expected: PASS.

- [ ] **Step 6: Run the whole package**

Run: `cd ThreatModelKit && swift test`
Expected: PASS. A layout test that states an exact `y` for a second row needs its
number changing from the 48 gap to the 72 gap. Read the failure and correct the
expected value; do not change the gap back.

- [ ] **Step 7: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/LayOutModel.swift \
        ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsImage.swift \
        ThreatModelKit/Tests/UnitTests/LayOutModelTests.swift \
        ThreatModelKit/Tests/UnitTests/ExportModelAsImageShapeTests.swift
git -c commit.gpgsign=false commit -m "feat: a layout and an exported picture leave room for a process circle"
```

---

### Task 7: The box, the anchors and the hit test follow the shape

**Files:**
- Modify: `threatmodeller/canvas/ComponentBox.swift`
- Modify: `threatmodeller/canvas/CanvasHitTest.swift:20-30`, `:55-58`, `:85-100`
- Test: `threatmodellerTests/canvas/ComponentBoxTests.swift`
- Test: `threatmodellerTests/canvas/CanvasHitTestTests.swift`

**Interfaces:**
- Consumes: `DiagramShape`, `Component.footprint(for:)` from Task 1;
  `ViewedComponent.shapeId` from Task 2.
- Produces: `ComponentBox(x:y:shape:)`, `ComponentBox.shape`,
  `ComponentBox.slotSize`, `ComponentBox.contains` testing the ellipse for a
  process.

`ComponentBox.size` becomes `ComponentBox.slotSize` so no reader mistakes the
slot for the drawn footprint. Every existing call site changes with it.

- [ ] **Step 1: Write the failing test**

Add to `threatmodellerTests/canvas/ComponentBoxTests.swift`:

```swift
    @Test func keepsTheCentreWhateverShapeItDrawsAs() {
        let centre = CGPoint(x: 80, y: 36)

        #expect(ComponentBox(x: 0, y: 0, shape: .actor).centre == centre)
        #expect(ComponentBox(x: 0, y: 0, shape: .process).centre == centre)
        #expect(ComponentBox(x: 0, y: 0, shape: .store).centre == centre)
    }

    @Test func drawsEachShapeAtItsOwnFootprint() {
        #expect(ComponentBox(x: 0, y: 0, shape: .actor).rect.size == CGSize(width: 160, height: 72))
        #expect(ComponentBox(x: 0, y: 0, shape: .process).rect.size == CGSize(width: 104, height: 104))
        #expect(ComponentBox(x: 0, y: 0, shape: .store).rect.size == CGSize(width: 160, height: 64))
    }

    @Test func centresAProcessCircleOnTheSlot() {
        let box = ComponentBox(x: 0, y: 0, shape: .process)

        #expect(box.rect.origin == CGPoint(x: 28, y: -16))
    }

    @Test func missesTheCornerOfAProcessCircle() {
        let box = ComponentBox(x: 0, y: 0, shape: .process)

        #expect(box.contains(box.centre))
        #expect(box.contains(CGPoint(x: box.rect.minX + 2, y: box.rect.minY + 2)) == false)
    }

    @Test func takesTheWholeRectangleForAnActor() {
        let box = ComponentBox(x: 0, y: 0, shape: .actor)

        #expect(box.contains(CGPoint(x: 1, y: 1)))
    }

    @Test func defaultsToTheSlotRectangleWhenNoShapeIsStated() {
        #expect(ComponentBox(x: 0, y: 0).rect.size == ComponentBox.slotSize)
    }
```

Add to `threatmodellerTests/canvas/CanvasHitTestTests.swift`:

```swift
    @Test func leavesRoomForTheProcessCircleAtTheEdgeOfTheDiagram() {
        let node = component("c1", x: 3800, y: 2900)
        let size = CanvasHitTest.contentSize(components: [node], zones: [])
        let box = ComponentBox(x: node.x, y: node.y, shape: .process)

        #expect(size.width >= box.rect.maxX)
        #expect(size.height >= box.rect.maxY)
    }
```

The private `component` helper in that file needs the new `shapeId` argument.
Give it `shapeId: "process"`.

- [ ] **Step 2: Run the tests to see them fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ComponentBoxTests`
Expected: FAIL. `ComponentBox` takes no `shape`.

If the build reports `Cannot find type 'DiagramShape' in scope`, run the clean
from the Global Constraints first.

- [ ] **Step 3: Rewrite `ComponentBox`**

```swift
import CoreGraphics
import ThreatModelKit

/// The area a component draws in, in model coordinates.
///
/// A component holds one slot, 160 by 72, whatever it draws as. The zone
/// containment rule tests the centre of that slot, and the core owns the size
/// because the core has to know the extent that centre comes from.
///
/// The drawn footprint is smaller or taller than the slot for a process and a
/// store, and it centres on the same point, so a shape change never moves a
/// component and never changes which zone holds it.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated struct ComponentBox: Equatable {
    /// The slot a component occupies, whatever it draws as.
    static let slotSize = CGSize(width: Component.size.width, height: Component.size.height)

    let origin: CGPoint
    let shape: DiagramShape

    init(x: Double, y: Double, shape: DiagramShape = .actor) {
        origin = CGPoint(x: x, y: y)
        self.shape = shape
    }

    /// The centre of the slot. `ZoneContainment` tests this point, and every
    /// footprint centres on it.
    var centre: CGPoint {
        CGPoint(x: origin.x + Self.slotSize.width / 2, y: origin.y + Self.slotSize.height / 2)
    }

    /// The footprint the canvas paints.
    var rect: CGRect {
        let footprint = Component.footprint(for: shape)
        return CGRect(
            x: centre.x - footprint.width / 2,
            y: centre.y - footprint.height / 2,
            width: footprint.width,
            height: footprint.height
        )
    }

    /// A process is a circle, so its bounding square's corners belong to
    /// whatever is behind it, not to the node.
    func contains(_ modelPoint: CGPoint) -> Bool {
        guard shape == .process else { return rect.contains(modelPoint) }

        let dx = (modelPoint.x - rect.midX) / (rect.width / 2)
        let dy = (modelPoint.y - rect.midY) / (rect.height / 2)
        return dx * dx + dy * dy <= 1
    }
}
```

- [ ] **Step 4: Follow the rename and the shape through the hit test**

In `CanvasHitTest.swift`:

In `boxes(for:selected:dragTranslation:)`, pass the shape:

```swift
            found[component.id] = ComponentBox(
                x: component.x + shift.width,
                y: component.y + shift.height,
                shape: DiagramShape(rawValue: component.shapeId) ?? .process
            )
```

In `component(under:components:)`:

```swift
    static func component(under modelPoint: CGPoint, components: [ViewedComponent]) -> String? {
        components.last {
            ComponentBox(
                x: $0.x,
                y: $0.y,
                shape: DiagramShape(rawValue: $0.shapeId) ?? .process
            ).contains(modelPoint)
        }?.id
    }
```

In `contentSize(components:zones:)`:

```swift
        for component in components {
            let box = ComponentBox(
                x: component.x,
                y: component.y,
                shape: DiagramShape(rawValue: component.shapeId) ?? .process
            )
            width = max(width, box.rect.maxX)
            height = max(height, box.rect.maxY)
        }
```

- [ ] **Step 5: Follow the rename everywhere else**

Run: `grep -rn "ComponentBox.size" threatmodeller threatmodellerTests`
Change each hit to `ComponentBox.slotSize`, except in `ComponentNodeView.swift`,
which Task 8 rewrites.

- [ ] **Step 6: Run the tests to see them pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add threatmodeller/canvas/ComponentBox.swift \
        threatmodeller/canvas/CanvasHitTest.swift \
        threatmodellerTests/canvas/ComponentBoxTests.swift \
        threatmodellerTests/canvas/CanvasHitTestTests.swift
git -c commit.gpgsign=false commit -m "feat: a component's footprint and its hit test follow its shape"
```

---

### Task 8: Draw the three shapes and the risk they carry

**Files:**
- Create: `threatmodeller/canvas/ComponentShapePath.swift`
- Modify: `threatmodeller/canvas/ComponentNodeView.swift`
- Modify: `threatmodeller/RiskPalette.swift`
- Test: `threatmodellerTests/ViewRenderTests.swift`

**Interfaces:**
- Consumes: `ComponentBox` from Task 7, `ElementRisk` from Task 3.
- Produces: `ComponentShapePath.path(for:in:)`,
  `ComponentNodeView(component:risk:isSelected:…)`.

`ComponentNodeView` gains one argument, `risk: ElementRisk?`. Every call site
passes it: `CanvasView` from the session's map, `CanvasPicture` from its own new
argument.

- [ ] **Step 1: Write the failing test**

Add to `threatmodellerTests/ViewRenderTests.swift`, beside the other view tests:

```swift
    @Test func drawsEachDiagramShape() {
        for shape in ["actor", "process", "store"] {
            expectDrawn(
                ComponentNodeView(
                    component: aViewedComponent(shapeId: shape),
                    risk: ElementRisk(
                        sourceId: "component:c1",
                        openCount: 3,
                        totalCount: 4,
                        highestLevelId: "high"
                    ),
                    isSelected: false,
                    onSelect: { _ in },
                    onDragChanged: { _ in },
                    onDragEnded: { _ in },
                    onAnchorDragChanged: { _ in },
                    onAnchorDragEnded: { _ in },
                    zoneName: "Private Zone"
                ),
                width: 200,
                height: 160,
                "the \(shape) node"
            )
        }
    }

    @Test func drawsANodeThatRaisesNoThreat() {
        expectDrawn(
            ComponentNodeView(
                component: aViewedComponent(shapeId: "process"),
                risk: nil,
                isSelected: false,
                onSelect: { _ in },
                onDragChanged: { _ in },
                onDragEnded: { _ in },
                onAnchorDragChanged: { _ in },
                onAnchorDragEnded: { _ in },
                zoneName: nil
            ),
            width: 200,
            height: 160,
            "a node with no threats"
        )
    }
```

Add the builder beside the other private helpers in that file:

```swift
    private func aViewedComponent(shapeId: String) -> ViewedComponent {
        ViewedComponent(
            id: "c1",
            technologyId: "aws-ec2",
            name: "Web Server",
            customName: nil,
            providerId: "aws",
            categoryId: "compute",
            x: 0,
            y: 0,
            sensitivityId: "confidential",
            threatsDisabled: false,
            isUnknownTechnology: false,
            zoneId: nil,
            runsAsId: "user",
            shapeId: shapeId,
            shapeOverrideId: nil
        )
    }
```

- [ ] **Step 2: Run the test to see it fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ViewRenderTests`
Expected: FAIL. `ComponentNodeView` takes no `risk`.

- [ ] **Step 3: Write the shape path**

Create `threatmodeller/canvas/ComponentShapePath.swift`:

```swift
import SwiftUI
import ThreatModelKit

/// The outline each data flow diagram shape draws.
///
/// An actor is a rectangle. A process is a circle. A store is two horizontal
/// lines with no side walls, so a path for a store is two subpaths and nothing
/// closes.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated enum ComponentShapePath {
    /// The outline to stroke, in the view's own coordinates.
    static func path(for shape: DiagramShape, in rect: CGRect) -> Path {
        switch shape {
        case .actor:
            Path(roundedRect: rect, cornerRadius: 4)
        case .process:
            Path(ellipseIn: rect)
        case .store:
            store(in: rect)
        }
    }

    /// The area to fill. A store has none: it is two lines, and what is behind
    /// it shows through.
    static func fill(for shape: DiagramShape, in rect: CGRect) -> Path? {
        switch shape {
        case .actor: Path(roundedRect: rect, cornerRadius: 4)
        case .process: Path(ellipseIn: rect)
        case .store: nil
        }
    }

    private static func store(in rect: CGRect) -> Path {
        var path = Path()
        path.move(to: CGPoint(x: rect.minX, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY))
        path.move(to: CGPoint(x: rect.minX, y: rect.maxY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY))
        return path
    }
}
```

- [ ] **Step 4: Rewrite the node view**

Replace `threatmodeller/canvas/ComponentNodeView.swift`:

```swift
import SwiftUI
import ThreatModelKit

/// One component on the canvas: its data flow diagram shape, the risk it
/// carries, its chips, and the four anchor handles a connection drag starts
/// from.
///
/// The outline states the highest residual risk level on the component. The
/// badge states how many threats no control answers. A component that raises
/// no threats draws in the quiet secondary colour, and a component the user
/// turned threats off for draws grey and dashed, as an out-of-scope element
/// does.
struct ComponentNodeView: View {
    let component: ViewedComponent
    /// What the component carries, or nil when it raises nothing.
    let risk: ElementRisk?
    let isSelected: Bool
    let onSelect: (_ addingToSelection: Bool) -> Void
    let onDragChanged: (CGSize) -> Void
    let onDragEnded: (CGSize) -> Void
    let onAnchorDragChanged: (CGPoint) -> Void
    let onAnchorDragEnded: (CGPoint) -> Void
    /// The display name of the zone holding this component, or nil. The rule
    /// is the component's centre inside the zone below its header, which is
    /// invisible without this badge.
    let zoneName: String?

    @State private var isHovering = false

    private var shape: DiagramShape {
        DiagramShape(rawValue: component.shapeId) ?? .process
    }

    private var box: ComponentBox {
        ComponentBox(x: 0, y: 0, shape: shape)
    }

    /// The footprint, moved to the view's own origin.
    private var footprint: CGRect {
        CGRect(origin: .zero, size: box.rect.size)
    }

    private var isOutOfScope: Bool { component.threatsDisabled }

    private var outlineColour: Color {
        if isOutOfScope { return .secondary }
        if isSelected { return .accentColor }
        guard let levelId = risk?.highestLevelId else { return .secondary.opacity(0.4) }
        return RiskPalette.colour(forLevelId: levelId)
    }

    private var outlineStyle: StrokeStyle {
        StrokeStyle(
            lineWidth: isSelected ? 2.5 : 1.5,
            dash: isOutOfScope ? [6, 4] : []
        )
    }

    private var openCount: Int { isOutOfScope ? 0 : (risk?.openCount ?? 0) }

    var body: some View {
        VStack(spacing: 4) {
            drawnShape
            chips
        }
        .opacity(isOutOfScope ? 0.45 : 1)
        .frame(width: max(footprint.width, 160), alignment: .center)
        .contentShape(Rectangle())
        .onHover { isHovering = $0 }
        // Without an explicit element SwiftUI reports the node's texts
        // separately, and the identifier lands on each of them instead of the
        // node. A user interface test queries this identifier.
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("node-\(component.technologyId)")
        .gesture(
            SpatialTapGesture().modifiers(.shift).onEnded { _ in onSelect(true) }
                .exclusively(before: SpatialTapGesture().onEnded { _ in onSelect(false) })
        )
        .gesture(
            DragGesture(minimumDistance: 3, coordinateSpace: .named("canvas"))
                .onChanged { onDragChanged($0.translation) }
                .onEnded { onDragEnded($0.translation) }
        )
    }

    private var drawnShape: some View {
        ZStack {
            if let fill = ComponentShapePath.fill(for: shape, in: footprint) {
                fill.fill(Color(nsColor: .controlBackgroundColor))
            }

            ComponentShapePath.path(for: shape, in: footprint)
                .stroke(outlineColour, style: outlineStyle)

            Text(component.name)
                .font(.headline)
                .lineLimit(2)
                .multilineTextAlignment(.center)
                .frame(width: footprint.width - 16)

            if openCount > 0 {
                badge
            }

            if isHovering || isSelected {
                ForEach(ConnectionAnchor.allCases, id: \.self) { anchor in
                    anchorHandle(anchor)
                }
            }
        }
        .frame(width: footprint.width, height: footprint.height)
    }

    private var badge: some View {
        Text("\(openCount)")
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(
                Capsule().fill(
                    RiskPalette.background(forLevelId: risk?.highestLevelId ?? "")
                )
            )
            .overlay(
                Capsule().strokeBorder(outlineColour, lineWidth: 1)
            )
            .position(x: footprint.maxX, y: footprint.minY)
            .accessibilityIdentifier("node-open-threats-\(component.id)")
    }

    private var chips: some View {
        HStack(spacing: 6) {
            Text(component.providerId.isEmpty ? "unknown" : component.providerId.uppercased())
                .font(.caption2)
                .foregroundStyle(.secondary)
            Text(component.sensitivityId.capitalized)
                .font(.caption2)
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .background(Capsule().fill(Color.secondary.opacity(0.15)))
            if let zoneName {
                Text(zoneName)
                    .font(.caption2)
                    .lineLimit(1)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(Color.green.opacity(0.18)))
            }
        }
    }

    private func anchorHandle(_ anchor: ConnectionAnchor) -> some View {
        let point = AnchorGeometry.point(anchor, of: box)
        let origin = box.rect.origin

        return Circle()
            .fill(Color.accentColor)
            .frame(width: 9, height: 9)
            .position(x: point.x - origin.x, y: point.y - origin.y)
            .gesture(
                DragGesture(minimumDistance: 1, coordinateSpace: .named("canvas"))
                    .onChanged { onAnchorDragChanged($0.location) }
                    .onEnded { onAnchorDragEnded($0.location) }
            )
    }
}
```

The chips row sits below the footprint, so the view is taller than the
footprint. `CanvasView` positions a node by `componentBox.centre`, which centres
the whole view, not the shape. Correct that in Task 10.

- [ ] **Step 5: Give the palette a quiet background for no level**

In `threatmodeller/RiskPalette.swift`, `background(forLevelId:)` already returns
`colour(forLevelId:).opacity(0.18)`, and `colour` returns `.secondary` for an
unknown id. No change is needed. Read the file and confirm it.

- [ ] **Step 6: Run the test to see it pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ViewRenderTests`
Expected: FAIL to build, because `CanvasView` and `CanvasPicture` still call
`ComponentNodeView` without `risk:`. Task 9 and Task 10 fix those. To keep this
task independently testable, pass `risk: nil` at both call sites now, in one
line each, and leave the real value to those tasks.

Run it again.
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add threatmodeller/canvas/ComponentShapePath.swift \
        threatmodeller/canvas/ComponentNodeView.swift \
        threatmodeller/canvas/CanvasView.swift \
        threatmodeller/reporting/CanvasPicture.swift \
        threatmodellerTests/ViewRenderTests.swift
git -c commit.gpgsign=false commit -m "feat: a node draws its data flow diagram shape and the risk it carries"
```

---

### Task 9: A flow states what it is and what it carries

**Files:**
- Modify: `threatmodeller/canvas/ConnectionsLayer.swift`
- Test: `threatmodellerTests/ViewRenderTests.swift`

**Interfaces:**
- Consumes: `ElementRisk` from Task 3.
- Produces: `ConnectionsLayer(connections:boxes:risks:outOfScopeComponentIds:selectedConnectionIds:preview:)`.

- [ ] **Step 1: Write the failing test**

Add to `threatmodellerTests/ViewRenderTests.swift`:

```swift
    @Test func drawsAFlowWithItsLabelAndItsOpenThreatCount() {
        let boxes = [
            "a": ComponentBox(x: 0, y: 0, shape: .process),
            "b": ComponentBox(x: 400, y: 200, shape: .store)
        ]

        expectDrawn(
            ConnectionsLayer(
                connections: [
                    ViewedConnection(
                        id: "f1",
                        sourceComponentId: "a",
                        targetComponentId: "b",
                        kindId: "network",
                        description: "HTTPS"
                    )
                ],
                boxes: boxes,
                risks: [
                    "connection:f1": ElementRisk(
                        sourceId: "connection:f1",
                        openCount: 2,
                        totalCount: 3,
                        highestLevelId: "critical"
                    )
                ],
                outOfScopeComponentIds: [],
                selectedConnectionIds: [],
                preview: nil
            ),
            width: 600,
            height: 400,
            "a flow with a label"
        )
    }
```

- [ ] **Step 2: Run the test to see it fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ViewRenderTests`
Expected: FAIL. `ConnectionsLayer` takes no `risks`.

- [ ] **Step 3: Rewrite the layer**

Replace `threatmodeller/canvas/ConnectionsLayer.swift`:

```swift
import SwiftUI
import ThreatModelKit

/// Every link drawn in one `Canvas` pass, plus the preview line while a
/// connection drag is in flight. Spec section 9 sets this painting order.
///
/// A link takes the colour of the highest residual risk level it carries, and
/// states its description, or its flow kind when the user wrote none. A link
/// either end of which is out of scope draws grey and dashed.
struct ConnectionsLayer: View {
    let connections: [ViewedConnection]
    let boxes: [String: ComponentBox]
    /// The risk of every element, by source id. A link reads
    /// "connection:<id>".
    let risks: [String: ElementRisk]
    /// The components the user turned threats off for.
    let outOfScopeComponentIds: Set<String>
    let selectedConnectionIds: Set<String>
    let preview: (start: CGPoint, end: CGPoint)?

    var body: some View {
        Canvas { context, _ in
            for connection in connections {
                guard let source = boxes[connection.sourceComponentId],
                      let target = boxes[connection.targetComponentId] else { continue }

                let anchors = AnchorGeometry.nearestPair(from: source, to: target)
                let path = ConnectionPath(
                    from: AnchorGeometry.point(anchors.source, of: source),
                    to: AnchorGeometry.point(anchors.target, of: target)
                )
                draw(connection, along: path, in: &context)
            }

            if let preview {
                stroke(
                    ConnectionPath(from: preview.start, to: preview.end),
                    in: &context,
                    colour: .accentColor,
                    width: 2.5,
                    dashed: true
                )
            }
        }
        .allowsHitTesting(false)
    }

    // MARK: what one link looks like

    private func isOutOfScope(_ connection: ViewedConnection) -> Bool {
        outOfScopeComponentIds.contains(connection.sourceComponentId)
            || outOfScopeComponentIds.contains(connection.targetComponentId)
    }

    private func risk(of connection: ViewedConnection) -> ElementRisk? {
        risks["connection:\(connection.id)"]
    }

    private func colour(of connection: ViewedConnection) -> Color {
        if isOutOfScope(connection) { return .secondary }
        if selectedConnectionIds.contains(connection.id) { return .accentColor }
        guard let levelId = risk(of: connection)?.highestLevelId else { return .secondary }
        return RiskPalette.colour(forLevelId: levelId)
    }

    /// The description when the user wrote one, else the flow kind.
    private func label(of connection: ViewedConnection) -> String {
        let described = connection.description?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if described.isEmpty == false { return described }
        return FlowKind(rawValue: connection.kindId)?.label ?? connection.kindId
    }

    private func draw(
        _ connection: ViewedConnection,
        along path: ConnectionPath,
        in context: inout GraphicsContext
    ) {
        let selected = selectedConnectionIds.contains(connection.id)
        let colour = colour(of: connection)

        stroke(
            path,
            in: &context,
            colour: colour,
            width: selected ? 2.5 : 1.5,
            dashed: isOutOfScope(connection)
        )

        let head = path.arrowhead()
        var arrow = Path()
        arrow.move(to: head[0])
        arrow.addLine(to: head[1])
        arrow.addLine(to: head[2])
        arrow.closeSubpath()
        context.fill(arrow, with: .color(colour))

        write(connection, at: path.point(at: 0.5), colour: colour, in: &context)
    }

    private func stroke(
        _ path: ConnectionPath,
        in context: inout GraphicsContext,
        colour: Color,
        width: CGFloat,
        dashed: Bool
    ) {
        var curve = Path()
        curve.move(to: path.start)
        curve.addCurve(to: path.end, control1: path.control1, control2: path.control2)

        context.stroke(
            curve,
            with: .color(colour),
            style: StrokeStyle(lineWidth: width, dash: dashed ? [6, 4] : [])
        )
    }

    /// The label sits on a pill in the canvas colour, so the curve does not run
    /// through the text.
    private func write(
        _ connection: ViewedConnection,
        at point: CGPoint,
        colour: Color,
        in context: inout GraphicsContext
    ) {
        let open = isOutOfScope(connection) ? 0 : (risk(of: connection)?.openCount ?? 0)
        let text = open > 0 ? "\(label(of: connection))  ·  \(open)" : label(of: connection)

        let resolved = context.resolve(
            Text(text).font(.caption2).foregroundStyle(colour)
        )
        let size = resolved.measure(in: CGSize(width: 220, height: 40))
        let pill = CGRect(
            x: point.x - size.width / 2 - 5,
            y: point.y - size.height / 2 - 2,
            width: size.width + 10,
            height: size.height + 4
        )

        context.fill(
            Path(roundedRect: pill, cornerRadius: 4),
            with: .color(Color(nsColor: .textBackgroundColor))
        )
        context.draw(resolved, at: point, anchor: .center)
    }
}
```

- [ ] **Step 4: Pass the new arguments at both call sites**

In `threatmodeller/canvas/CanvasView.swift` and
`threatmodeller/reporting/CanvasPicture.swift`, add `risks: [:]` and
`outOfScopeComponentIds: []` to the `ConnectionsLayer` call. Task 10 replaces
those two empty values with the real ones.

- [ ] **Step 5: Run the test to see it pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ViewRenderTests`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add threatmodeller/canvas/ConnectionsLayer.swift \
        threatmodeller/canvas/CanvasView.swift \
        threatmodeller/reporting/CanvasPicture.swift \
        threatmodellerTests/ViewRenderTests.swift
git -c commit.gpgsign=false commit -m "feat: a flow states its label and the risk it carries"
```

---

### Task 10: A zone takes the dashed boundary stroke and its own badge

**Files:**
- Modify: `threatmodeller/canvas/ZoneView.swift`
- Test: `threatmodellerTests/ViewRenderTests.swift`

**Interfaces:**
- Consumes: `ElementRisk` from Task 3.
- Produces: `ZoneView(zone:risk:size:isSelected:…)`.

- [ ] **Step 1: Write the failing test**

Add to `threatmodellerTests/ViewRenderTests.swift`:

```swift
    @Test func drawsAPrivilegeZoneWithItsChipAndItsCount() {
        expectDrawn(
            ZoneView(
                zone: ViewedZone(
                    id: "z1",
                    name: "Kernel",
                    customName: "Kernel",
                    networkZoneId: "private",
                    networkTypeId: "generic",
                    riskReductionEnabled: true,
                    riskReductionPercent: 20,
                    x: 0,
                    y: 0,
                    width: 400,
                    height: 300,
                    boundaryId: "privilege"
                ),
                risk: ElementRisk(
                    sourceId: "zone:z1",
                    openCount: 4,
                    totalCount: 6,
                    highestLevelId: "critical"
                ),
                size: CGSize(width: 400, height: 300),
                isSelected: false,
                onSelect: {},
                onDragChanged: { _, _ in },
                onDragEnded: { _, _ in }
            ),
            width: 400,
            height: 300,
            "a privilege zone"
        )
    }
```

- [ ] **Step 2: Run the test to see it fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ViewRenderTests`
Expected: FAIL. `ZoneView` takes no `risk`.

- [ ] **Step 3: Change the zone view**

In `threatmodeller/canvas/ZoneView.swift`:

Replace the doc comment above the type:

```swift
/// One zone: its dashed boundary, its header, and its resize grips when
/// selected.
///
/// Every zone draws dashed, the way a trust boundary does. The stroke colour
/// states public against private, because the dash no longer can. The header
/// states the name, the risk reduction, whether the zone is a privilege
/// boundary, and how many threats on the zone no control answers.
```

Add the property after `zone`:

```swift
    /// What the zone itself carries, or nil when it raises nothing.
    let risk: ElementRisk?
```

Replace `body`'s outline:

```swift
            RoundedRectangle(cornerRadius: 12)
                .fill(tint.opacity(0.07))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .strokeBorder(
                            isSelected ? Color.accentColor : tint.opacity(0.7),
                            style: StrokeStyle(
                                lineWidth: isSelected ? 3 : 2,
                                dash: [8, 6]
                            )
                        )
                )
```

Replace `header`:

```swift
    private var header: some View {
        HStack(spacing: 8) {
            Text(zone.name)
                .font(.headline)
                .lineLimit(1)
            if isPrivate && zone.riskReductionEnabled {
                Text("\u{2212}\(zone.riskReductionPercent)%")
                    .font(.caption2)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(tint.opacity(0.2)))
            }
            if zone.boundaryId == "privilege" {
                Text("Privilege")
                    .font(.caption2)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(Color.purple.opacity(0.2)))
            }
            if let risk, risk.openCount > 0 {
                Text("\(risk.openCount)")
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(
                        Capsule().fill(
                            RiskPalette.background(forLevelId: risk.highestLevelId ?? "")
                        )
                    )
                    .accessibilityIdentifier("zone-open-threats-\(zone.id)")
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .frame(width: size.width, height: ZoneBox.headerHeight, alignment: .leading)
        .contentShape(Rectangle())
        .onTapGesture { onSelect() }
        .gesture(
            DragGesture(minimumDistance: 3, coordinateSpace: .named("canvas"))
                .onChanged { onDragChanged(nil, $0.translation) }
                .onEnded { onDragEnded(nil, $0.translation) }
        )
    }
```

- [ ] **Step 4: Pass the new argument at both call sites**

In `CanvasView.swift` and `CanvasPicture.swift`, add `risk: nil` to the
`ZoneView` call. Task 11 replaces it with the real value.

- [ ] **Step 5: Run the test to see it pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ViewRenderTests`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add threatmodeller/canvas/ZoneView.swift \
        threatmodeller/canvas/CanvasView.swift \
        threatmodeller/reporting/CanvasPicture.swift \
        threatmodellerTests/ViewRenderTests.swift
git -c commit.gpgsign=false commit -m "feat: a zone draws as a dashed boundary and states what it carries"
```

---

### Task 11: The session supplies the risk, and the panel picks the shape

**Files:**
- Modify: `threatmodeller/ThreatModelSession.swift`
- Modify: `threatmodeller/canvas/CanvasView.swift`
- Modify: `threatmodeller/canvas/ComponentPanel.swift`
- Modify: `threatmodeller/reporting/CanvasPicture.swift`
- Test: `threatmodellerTests/threatmodellerTests.swift`

**Interfaces:**
- Consumes: `ElementRiskRollup.byElement(_:levelOrder:)` from Task 3;
  `SetComponentPropertiesRequest.shape` from Task 2.
- Produces: `ThreatModelSession.elementRisks: [String: ElementRisk]`;
  `ThreatModelSession.setComponentProperties(componentId:name:sensitivityId:threatsDisabled:runsAsId:shapeId:)`.

- [ ] **Step 1: Write the failing test**

Read `threatmodellerTests/threatmodellerTests.swift` and find the session tests
that already state what a control does. Add beside them:

```swift
    @MainActor
    @Test func statesTheRiskOfEveryElementForTheCanvas() {
        let session = aSessionWithOneNode()

        let componentId = session.canvas.components.first?.id ?? ""
        #expect(session.elementRisks["component:\(componentId)"] != nil)
    }

    @MainActor
    @Test func writesTheShapeThePanelPicks() {
        let session = aSessionWithOneNode()
        let componentId = session.canvas.components.first?.id ?? ""

        session.setComponentProperties(
            componentId: componentId,
            name: nil,
            sensitivityId: "internal",
            threatsDisabled: false,
            runsAsId: "user",
            shapeId: "store"
        )

        #expect(session.canvas.components.first?.shapeId == "store")
        #expect(session.errorMessage == nil)
    }

    @MainActor
    @Test func saysSoWhenTheShapeIsNotOneThisApplicationHolds() {
        let session = aSessionWithOneNode()
        let componentId = session.canvas.components.first?.id ?? ""

        session.setComponentProperties(
            componentId: componentId,
            name: nil,
            sensitivityId: "internal",
            threatsDisabled: false,
            runsAsId: "user",
            shapeId: "cylinder"
        )

        #expect(session.errorMessage != nil)
    }
```

Reuse whatever helper that file already has for building a session with a node.
If it has none, copy the one in `ViewRenderTests.swift` (`aModel()`).

- [ ] **Step 2: Run the test to see it fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests`
Expected: FAIL. `elementRisks` does not exist.

- [ ] **Step 3: Hold the risk on the session**

In `threatmodeller/ThreatModelSession.swift`, beside `threats`:

```swift
    /// The risk of every element on the diagram, by source id. The canvas
    /// paints from this, so the picture and the threat list never disagree.
    private(set) var elementRisks: [String: ElementRisk] = [:]
```

In the method that reads the assessment — the one holding
`let assessment = useCases.assessThreatModel().execute(...)` at about line 668 —
add after `severityChoices = assessment.severities`:

```swift
        elementRisks = ElementRiskRollup.byElement(
            assessment.threats,
            levelOrder: assessment.severities.map(\.id)
        )
```

- [ ] **Step 4: Take the shape in the session writer**

Change `setComponentProperties` to take `shapeId: String?` after `runsAsId`,
pass `shape: shapeId` into the request, and add the case:

```swift
        case .unknownShape:
            errorMessage = "That shape is not one this application holds."
```

- [ ] **Step 5: Add the picker to the panel**

In `threatmodeller/canvas/ComponentPanel.swift`, add the list beside the others:

```swift
    /// The empty tag is **Auto**: the derivation decides.
    private static let shapes = [
        ("", "Auto"),
        ("actor", "Actor"),
        ("process", "Process"),
        ("store", "Store")
    ]
```

Add the control between the name field and the sensitivity picker:

```swift
            Picker("Shape", selection: shape) {
                ForEach(Self.shapes, id: \.0) { Text(label(forShape: $0.0, $0.1)).tag($0.0) }
            }
            .labelsHidden()
            .frame(width: 170)
            .accessibilityIdentifier("component-shape")
```

Add the binding and the label:

```swift
    private var shape: Binding<String> {
        Binding(
            get: { component.shapeOverrideId ?? "" },
            set: { write(shape: $0) }
        )
    }

    /// **Auto** states what the derivation currently gives, so a user who
    /// forces that same value sees no change and knows it.
    private func label(forShape id: String, _ name: String) -> String {
        guard id.isEmpty else { return name }
        let derived = DiagramShape(rawValue: component.shapeId)?.label ?? component.shapeId
        return "Auto — \(derived)"
    }
```

Add `shape` to `write`:

```swift
    private func write(
        name newName: String? = nil,
        sensitivity newSensitivity: String? = nil,
        threatsDisabled newThreatsDisabled: Bool? = nil,
        runsAs newRunsAs: String? = nil,
        shape newShape: String? = nil
    ) {
        let picked = newShape ?? component.shapeOverrideId ?? ""

        session.setComponentProperties(
            componentId: component.id,
            name: newName ?? component.customName,
            sensitivityId: newSensitivity ?? component.sensitivityId,
            threatsDisabled: newThreatsDisabled ?? component.threatsDisabled,
            runsAsId: newRunsAs ?? component.runsAsId,
            shapeId: picked.isEmpty ? nil : picked
        )
    }
```

- [ ] **Step 6: Give the canvas the real values**

In `CanvasView.swift`:

- `ZoneView(zone: zone, risk: session.elementRisks["zone:\(zone.id)"], size: rect.size, …)`
- `ConnectionsLayer(connections:…, risks: session.elementRisks, outOfScopeComponentIds: outOfScopeComponentIds, …)`
- `ComponentNodeView(component: component, risk: session.elementRisks["component:\(component.id)"], …)`
- the node position becomes the centre of the whole view, which is taller than
  the footprint. Position by the slot centre and let the chips hang below:

```swift
                .position(x: componentBox.centre.x, y: componentBox.centre.y)
```

  stays as it is. The chips row adds height below the shape, so a node's chips
  overlap the row below it by about 20 points. The row gap in a generated layout
  is 72, so they do not collide. Leave it.

Add the private helper:

```swift
    /// The components the user turned threats off for. A flow either end of
    /// which is one of these is out of scope too.
    private var outOfScopeComponentIds: Set<String> {
        Set(session.canvas.components.filter(\.threatsDisabled).map(\.id))
    }
```

In `CanvasPicture.swift`, add one property and use it at the three call sites:

```swift
    /// The risk of every element, by source id. Empty draws the diagram with no
    /// risk colour, which is what an export from a model with no threats shows.
    let risks: [String: ElementRisk]
```

Pass `risks: risks` to `ConnectionsLayer`,
`risk: risks["component:\(component.id)"]` to `ComponentNodeView`,
`risk: risks["zone:\(zone.id)"]` to `ZoneView`, and
`outOfScopeComponentIds: Set(components.filter(\.threatsDisabled).map(\.id))` to
`ConnectionsLayer`.

Also change the node's position, which reads `Component.size` directly:

```swift
        .position(
            x: component.x + Component.size.width / 2,
            y: component.y + Component.size.height / 2
        )
```

That is the slot centre and stays correct. Leave it.

In `threatmodeller/reporting/CanvasImageRenderer.swift`, `png(of:area:)` builds
the picture. Add a `risks` argument to that method and pass it through:

```swift
    func png(
        of canvas: ViewThreatModelResponse,
        risks: [String: ElementRisk],
        area: ExportModelAsImageResponse
    ) throws -> Data {
```

Find its caller with `grep -rn "\.png(of:" threatmodeller` and pass
`session.elementRisks`.

- [ ] **Step 7: Run the tests to see them pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add threatmodeller/ThreatModelSession.swift \
        threatmodeller/canvas/CanvasView.swift \
        threatmodeller/canvas/ComponentPanel.swift \
        threatmodeller/reporting/CanvasPicture.swift \
        threatmodeller/reporting/CanvasImageRenderer.swift \
        threatmodellerTests/threatmodellerTests.swift
git -c commit.gpgsign=false commit -m "feat: the canvas paints the risk the assessment states"
```

---

### Task 12: Prove the whole thing draws, and refresh the screenshot

**Files:**
- Modify: `threatmodellerTests/ViewRenderTests.swift`
- Modify: `threatmodellerTests/ReportRendererTests.swift`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the failing test**

Add to `threatmodellerTests/ViewRenderTests.swift`:

```swift
    @Test func drawsAWholeDiagramWithEveryShapeOnIt() {
        let session = aModel()

        expectDrawn(
            CanvasPicture(
                components: session.canvas.components,
                connections: session.canvas.connections,
                zones: session.canvas.zones,
                risks: session.elementRisks,
                origin: .zero,
                size: CGSize(width: 900, height: 700)
            ),
            "the whole diagram"
        )
    }
```

- [ ] **Step 2: Run it**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ViewRenderTests`
Expected: PASS if Task 11 is complete. If it fails to build, the `risks`
argument name in `CanvasPicture` differs; correct the test.

- [ ] **Step 3: Run everything**

Run: `cd ThreatModelKit && swift test`
Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: PASS on both.

- [ ] **Step 4: Commit**

```bash
git add threatmodellerTests/ViewRenderTests.swift
git -c commit.gpgsign=false commit -m "test: the whole diagram draws with every shape on it"
```

---

## Self-review of this plan

**Spec coverage.**

| Spec section | Task |
| --- | --- |
| 3.1 `DiagramShape` | 1 |
| 3.2 the derivation map | 1 |
| 3.3 the override, the viewed fields, the use case | 1, 2 |
| 4.1 the footprints | 1 |
| 4.2 the row gap, the export area, the content size | 6, 7 |
| 4.3 hit testing and the anchors | 7 |
| 5 the element risk rollup | 3 |
| 6.1 painting a component | 8 |
| 6.2 painting a zone | 10 |
| 6.3 painting a flow | 9 |
| 7 the panel | 11 |
| 8.1 the model file | 4 |
| 8.2 the architecture language and `docs/LANGUAGE.md` | 5 |
| 9 the report image | 11 |
| 11 testing | every task |

**Names used across tasks.** `DiagramShape`, `DiagramShapeMap.derived(providerId:categoryId:)`,
`Component.footprint(for:)`, `Component.resolvedShape(providerId:categoryId:)`,
`Component.shape`, `ViewedComponent.shapeId`, `ViewedComponent.shapeOverrideId`,
`SetComponentPropertiesRequest.shape`, `SetComponentPropertiesResponse.unknownShape`,
`ElementRisk`, `ElementRiskRollup.byElement(_:levelOrder:)`,
`ComponentBox(x:y:shape:)`, `ComponentBox.slotSize`,
`ComponentShapePath.path(for:in:)`, `ComponentShapePath.fill(for:in:)`,
`ThreatModelSession.elementRisks`. Each is defined once and spelled the same
way in every later task.

**Known guesses to correct while working.** The parser and writer entry points
in Task 5, the codec's static method names and its unknown-value error in
Task 4, the export use case factory name in Task 6, and the session test helper
in Task 11. Each step says to read the real file first.
