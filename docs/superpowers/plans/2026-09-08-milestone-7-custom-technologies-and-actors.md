# Milestone 7: Custom Technologies and External Actors — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The diagram can hold the things the catalogue does not: the people and systems outside the boundary, and the in-house service that has no entry in anybody's library. Both raise and carry threats like everything else.

**Architecture:** External actors are application-owned data the catalogue gateway merges into what it offers, so they reach the palette with no new port. A custom technology lives on the **model**, because it belongs to one diagram and travels in its file. Everything that asks "what is this technology?" asks `TechnologyLookup`, which answers from the model first and the catalogue second.

**Tech Stack:** Swift 6.3, Swift Package Manager, Swift Testing, SwiftUI, macOS 26.

**Spec:** `docs/superpowers/specs/2026-09-07-native-macos-threat-modeller-design.md`

**Carry-forward:** `docs/superpowers/specs/MILESTONE-7-CARRY-FORWARD.md`

**Read Task 6 before starting Task 1.** Task 6 is the acceptance test — the outer loop.

## Global Constraints

- Everything in the Milestone 6B plan's Global Constraints still holds.
- WARNING: two source files in one module may not share a basename.
- WARNING: a key path passed to a `rethrows` method inside `#expect` fails to compile; use a closure, and never nest one `#require` inside another.
- WARNING: the app saves its split-view arrangement. If the interface suite fails at its first assertion with no window, run `osascript -e 'tell application "threatmodeller" to quit'` then `defaults delete uk.craigbass.threatmodeller`.
- WARNING: the interface journey must ask for a new document and scope every query to one window.
- `actors.json` lives in `Resources/Actors/`, **outside** `Library/`. It has no lock entry and no checksum: `scripts/update-catalogue.sh` must never touch it.
- An actor raises no threats of its own. A link to or from one raises the connection threats like any other link.
- A custom technology lives on the model and travels in its file. It may name threats the catalogue defines; it defines none of its own.
- Catalogue pinned at `v1.0.1`.
- Commit after every task. Never commit a red suite.

## Out of scope for this milestone

Exports, samples, the About window, theming and the app icon: Milestones 8 and 9.

The zone-drag undo defect (`MILESTONE-7-CARRY-FORWARD.md` item 1) is **not** fixed here; it is its own piece of work and this milestone does not touch the zone gestures.

`RenameComponent`, `SetComponentSensitivity` and `DisableComponentThreats` stay unwritten, so the fixed `internal` sensitivity remains the largest gap.

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `ThreatModelKit/Sources/CatalogueGateways/Resources/Actors/actors.json` | The people and systems outside the boundary |
| `.../CatalogueGateways/ActorsJSON.swift` | Its `Codable` shape |
| `.../modelling/domain/CustomTechnology.swift` | A technology a model defines |
| `.../modelling/domain/TechnologyLookup.swift` | Model first, catalogue second |
| `.../modelling/usecase/CreateCustomTechnology.swift` | and its Request/Response |
| `.../modelling/usecase/EditCustomTechnology.swift` | and its Request/Response |
| `.../modelling/usecase/DeleteCustomTechnology.swift` | and its Request/Response |
| `.../catalogue/usecase/ListThreatChoices.swift` | What the editor offers to attach |
| `ThreatModelKit/Tests/UnitTests/TechnologyLookupTests.swift` | The lookup rule |
| `.../UnitTests/CustomTechnologyUseCaseTests.swift` | The three use cases |
| `.../AcceptanceTests/ModellingWhatIsNotInTheCatalogueTests.swift` | The milestone's outer loop |
| `threatmodeller/sidebar/CustomTechnologyEditor.swift` | The sheet |

**Modified:**

- `.../CatalogueGateways/BundledTechnologyCatalogue.swift` — merges the actors
- `.../TestSupport/CatalogueFixture.swift` — an actor of its own
- `.../modelling/domain/ThreatModel.swift` — gains `customTechnologies`
- `.../modelling/usecase/ViewThreatModel.swift`, `AddComponent.swift` — use the lookup
- `.../assessment/domain/ThreatResolver.swift` — uses the lookup
- `.../catalogue/usecase/ListTechnologies.swift` — offers the model's own too
- `ThreatModelKit/Sources/FileGateways/` — `customTechnologies` in the file
- `.../UseCaseFactory.swift`, `.../TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- `threatmodeller/ThreatModelSession.swift`, `ContentView.swift` — the editor

---

### Task 1: The people and systems outside the boundary

**Files:**
- Create: `ThreatModelKit/Sources/CatalogueGateways/Resources/Actors/actors.json`
- Create: `ThreatModelKit/Sources/CatalogueGateways/ActorsJSON.swift`
- Modify: `ThreatModelKit/Package.swift` — the second resource directory
- Modify: `.../CatalogueGateways/LibraryResources.swift`, `BundledTechnologyCatalogue.swift`
- Modify: `ThreatModelKit/Tests/GatewayIntegrationTests/BundledTechnologyCatalogueTests.swift`

**Interfaces:**
- Produces: nothing new on the boundary. `all()`, `findById(_:)`, `providers()` and `taxonomy()` simply hold more.

The actors are ours, so the file is ours: no lock entry, no checksum, and outside the directory the vendoring script rewrites.

WARNING: the shared contract asserts every technology's provider is one `providers()` returns and every category is one the taxonomy holds. Merging the actors means merging their provider and their categories too, or the contract fails — which is the contract doing its job.

- [ ] **Step 1: Write the failing test**

Add to `BundledTechnologyCatalogueTests`:

```swift
    @Test func offersThePeopleAndSystemsOutsideTheBoundary() throws {
        let catalogue = try BundledTechnologyCatalogue()

        let actors = catalogue.all().filter { $0.provider == ProviderId("actor") }
        #expect(actors.map(\.id.value).sorted() == [
            "actor-admin",
            "actor-api-client",
            "actor-attacker",
            "actor-browser",
            "actor-desktop",
            "actor-iot",
            "actor-mobile",
            "actor-partner",
            "actor-user"
        ])

        // An actor raises no threats of its own. A link to one raises the
        // connection threats like any other link.
        #expect(actors.allSatisfy { $0.threatIds.isEmpty })
        #expect(actors.allSatisfy { catalogue.threatsFor(technologyId: $0.id).isEmpty })

        let user = try #require(catalogue.findById(TechnologyId("actor-user")))
        #expect(user.name.isEmpty == false)
        #expect(user.description.isEmpty == false)
    }

    @Test func widensTheProviderAndCategoryVocabularies() throws {
        let catalogue = try BundledTechnologyCatalogue()

        let actor = try #require(catalogue.providers().first { $0.id == ProviderId("actor") })
        #expect(actor.displayName == "External Actors")

        let categories = catalogue.taxonomy().categories.map(\.id.value)
        for expected in ["person", "client", "device", "system"] {
            #expect(categories.contains(expected))
        }
    }

    @Test func keepsTheActorsOutOfTheVendoredLibrary() throws {
        // The catalogue update script rewrites Library/. App-owned data must
        // not live where a script overwrites it.
        #expect(throws: (any Error).self) {
            try LibraryResources.data(named: "actors.json")
        }
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter BundledTechnologyCatalogueTests 2>&1 | grep -E '✘' | head -3
```

Expected: FAIL — no actor is in the catalogue.

- [ ] **Step 3: Write the actors**

Create `ThreatModelKit/Sources/CatalogueGateways/Resources/Actors/actors.json`:

```json
{
  "provider": "actor",
  "displayName": "External Actors",
  "categories": [
    { "id": "person", "label": "People" },
    { "id": "client", "label": "Client Software" },
    { "id": "device", "label": "Devices" },
    { "id": "system", "label": "Other Systems" }
  ],
  "actors": [
    { "id": "actor-user", "name": "End User", "category": "person",
      "description": "A person using the system for its intended purpose" },
    { "id": "actor-admin", "name": "Administrator", "category": "person",
      "description": "A person with privileged access to operate or configure the system" },
    { "id": "actor-attacker", "name": "External Attacker", "category": "person",
      "description": "A person outside the boundary trying to reach what is inside it" },
    { "id": "actor-browser", "name": "Web Browser", "category": "client",
      "description": "A browser running the system's own front end" },
    { "id": "actor-mobile", "name": "Mobile App", "category": "client",
      "description": "An application on a phone or tablet" },
    { "id": "actor-desktop", "name": "Desktop App", "category": "client",
      "description": "An application installed on a workstation" },
    { "id": "actor-api-client", "name": "API Client", "category": "client",
      "description": "A program calling the system's interface directly" },
    { "id": "actor-iot", "name": "IoT Device", "category": "device",
      "description": "A device in the field reporting to or driven by the system" },
    { "id": "actor-partner", "name": "Partner System", "category": "system",
      "description": "A system run by another organisation that exchanges data with this one" }
  ]
}
```

Create `.../CatalogueGateways/ActorsJSON.swift`:

```swift
import Foundation

// Application-owned, not vendored. Mirrors `Resources/Actors/actors.json`.

struct ActorsFileJSON: Decodable {
    let provider: String
    let displayName: String
    let categories: [ActorCategoryJSON]
    let actors: [ActorJSON]
}

struct ActorCategoryJSON: Decodable {
    let id: String
    let label: String
}

struct ActorJSON: Decodable {
    let id: String
    let name: String
    let category: String
    let description: String
}
```

- [ ] **Step 4: Ship the directory and read it**

In `Package.swift`, add the second resource to the `CatalogueGateways` target:

```swift
            resources: [.copy("Resources/Library"), .copy("Resources/Actors")]
```

In `LibraryResources.swift`, add a reader for the app-owned directory beside the vendored one — the same shape, a different subdirectory. Name it so the difference is obvious:

```swift
    /// Application-owned data, outside the vendored library. No checksum, no
    /// lock entry: it is ours.
    static func appOwnedData(named name: String) throws -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Actors")
        else { throw LibraryResourceError.missing(name) }
        return try Data(contentsOf: url)
    }
```

Follow whatever shape `LibraryResources.data(named:)` already uses; read that file first and match it.

In `BundledTechnologyCatalogue.init`, after the providers are loaded, decode the actors and merge them:

```swift
        let actorsJSON = try decoder.decode(
            ActorsFileJSON.self,
            from: try LibraryResources.appOwnedData(named: "actors.json")
        )
        let actorProvider = ProviderId(actorsJSON.provider)
        loaded.append(contentsOf: actorsJSON.actors.map {
            Technology(
                id: TechnologyId($0.id),
                name: $0.name,
                provider: actorProvider,
                category: CategoryId($0.category),
                description: $0.description,
                threatIds: []
            )
        })
        providers.append(
            Provider(id: actorProvider, displayName: actorsJSON.displayName)
        )
```

and widen the taxonomy where it is built, so the contract's category check holds:

```swift
            categories: taxonomyJSON.categories.map { … } + actorsJSON.categories.map {
                ServiceCategory(id: CategoryId($0.id), label: $0.label, presetThreatIds: [])
            }
```

WARNING: the taxonomy is built before the actors are decoded. Decode the actors file first, above the taxonomy, so both can use it.

- [ ] **Step 5: Give the fixture an actor**

Add to `CatalogueFixture`, so the fast tests can draw one:

```swift
    /// An actor: no threats of its own, and a provider and category of its own.
    public static func user() -> Technology {
        Technology(
            id: TechnologyId("actor-user"),
            name: "End User",
            provider: ProviderId("actor"),
            category: CategoryId("person"),
            description: "A person using the system for its intended purpose",
            threatIds: []
        )
    }
```

Add `user()` to `catalogue()`'s technologies, `Provider(id: ProviderId("actor"), displayName: "External Actors")` to `providers()`, and `ServiceCategory(id: CategoryId("person"), label: "People", presetThreatIds: [])` to the taxonomy's categories.

WARNING: that changes what `ListTechnologies` returns, so `BuildingAThreatModelTests.offersTheCatalogueGroupedForBrowsing` grows a provider. Update its expectation to `["Amazon Web Services", "External Actors", "Google Cloud Platform"]` — or whatever the provider order actually produces; read the failure rather than guessing.

- [ ] **Step 6: Run every suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -5
```

Expected: PASS, including the shared contract against both the fake and the real gateway.

- [ ] **Step 7: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: put the people and systems outside the boundary in the palette

Nine actors, application-owned, in a directory the catalogue update script
never touches. An actor raises no threats of its own; a link to one raises
the connection threats like any other link, which is the whole point of
drawing one."
```

---

### Task 2: A technology a model defines, and one rule for finding it

**Files:**
- Create: `.../modelling/domain/CustomTechnology.swift`
- Create: `.../modelling/domain/TechnologyLookup.swift`
- Modify: `.../modelling/domain/ThreatModel.swift`
- Create: `ThreatModelKit/Tests/UnitTests/TechnologyLookupTests.swift`

**Interfaces:**
- Produces: `CustomTechnology(id:name:provider:category:description:threatIds:enforcesEncryption:)` with `.asTechnology`; `ThreatModel.customTechnologies`, `.customTechnology(_:)`; `TechnologyLookup(model:catalogue:)` with `.findById(_:)`, `.threatsFor(technologyId:)`, `.all()`.

A custom technology is a `Technology` the model carries. It reuses the catalogue's threats: a user naming their in-house service can say it carries credential theft, but cannot invent a threat the rest of the application knows nothing about.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/TechnologyLookupTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct TechnologyLookupTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func custom(
        _ id: String = "own-billing",
        name: String = "Billing",
        threatIds: [String] = ["credential-theft"]
    ) -> CustomTechnology {
        CustomTechnology(
            id: TechnologyId(id),
            name: name,
            provider: ProviderId("custom"),
            category: CategoryId("compute"),
            description: "Our own billing service",
            threatIds: threatIds.map(ThreatId.init)
        )
    }

    private func lookup(_ model: ThreatModel) -> TechnologyLookup {
        TechnologyLookup(model: model, catalogue: catalogue)
    }

    @Test func findsWhatTheCatalogueHolds() throws {
        let found = try #require(lookup(ThreatModel()).findById(TechnologyId("aws-ec2")))

        #expect(found.name == "EC2")
    }

    @Test func findsWhatTheModelDefines() throws {
        let model = ThreatModel(customTechnologies: [custom()])

        let found = try #require(lookup(model).findById(TechnologyId("own-billing")))
        #expect(found.name == "Billing")
        #expect(found.provider == ProviderId("custom"))
    }

    @Test func findsNothingForAnIdNeitherHolds() {
        #expect(lookup(ThreatModel()).findById(TechnologyId("own-billing")) == nil)
    }

    @Test func letsTheModelWinOverTheCatalogue() throws {
        // A user who names their own technology `aws-ec2` means theirs. The
        // model is the document in front of them; the catalogue is a library.
        let model = ThreatModel(customTechnologies: [custom("aws-ec2", name: "Our EC2")])

        #expect(try #require(lookup(model).findById(TechnologyId("aws-ec2"))).name == "Our EC2")
    }

    @Test func givesACustomTechnologyTheThreatsItNamed() {
        let model = ThreatModel(customTechnologies: [custom()])

        let threats = lookup(model).threatsFor(technologyId: TechnologyId("own-billing"))
        #expect(threats.map(\.id.value) == ["credential-theft"])
    }

    @Test func ignoresAThreatTheCatalogueDoesNotHold() {
        let model = ThreatModel(customTechnologies: [custom(threatIds: ["credential-theft", "invented"])])

        let threats = lookup(model).threatsFor(technologyId: TechnologyId("own-billing"))
        #expect(threats.map(\.id.value) == ["credential-theft"])
    }

    @Test func offersBothWhenAskedForEverything() {
        let model = ThreatModel(customTechnologies: [custom()])

        let all = lookup(model).all().map(\.id.value)
        #expect(all.contains("aws-ec2"))
        #expect(all.contains("own-billing"))
        // The model's own come first, so a user's own work is at hand.
        #expect(all.first == "own-billing")
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter TechnologyLookupTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'CustomTechnology' in scope`.

- [ ] **Step 3: Write both**

Create `.../modelling/domain/CustomTechnology.swift`:

```swift
/// A technology a model defines for itself.
///
/// It belongs to one diagram and travels in its file: an in-house service has
/// no entry in anybody's library. It reuses the catalogue's threats — a user can
/// say their service carries credential theft, but cannot invent a threat the
/// rest of the application knows nothing about.
public struct CustomTechnology: Equatable, Sendable {
    /// The provider every custom technology belongs to, so the palette can
    /// group them together.
    public static let provider = ProviderId("custom")

    public let id: TechnologyId
    public var name: String
    public var provider: ProviderId
    public var category: CategoryId
    public var description: String
    public var threatIds: [ThreatId]
    public var enforcesEncryption: Bool

    public init(
        id: TechnologyId,
        name: String,
        provider: ProviderId = CustomTechnology.provider,
        category: CategoryId,
        description: String,
        threatIds: [ThreatId],
        enforcesEncryption: Bool = false
    ) {
        self.id = id
        self.name = name
        self.provider = provider
        self.category = category
        self.description = description
        self.threatIds = threatIds
        self.enforcesEncryption = enforcesEncryption
    }

    /// The same thing, said the way the rest of the application says it.
    public var asTechnology: Technology {
        Technology(
            id: id,
            name: name,
            provider: provider,
            category: category,
            description: description,
            threatIds: threatIds,
            enforcesEncryption: enforcesEncryption
        )
    }
}
```

Create `.../modelling/domain/TechnologyLookup.swift`:

```swift
/// Answers "what is this technology?" from the model first and the catalogue
/// second.
///
/// A user who names their own technology after one in the catalogue means
/// theirs: the model is the document in front of them, and the catalogue is a
/// library. One rule, in one place, so every reader agrees.
public struct TechnologyLookup {
    private let custom: [TechnologyId: CustomTechnology]
    private let customOrder: [CustomTechnology]
    private let catalogue: TechnologyCatalogue

    public init(model: ThreatModel, catalogue: TechnologyCatalogue) {
        customOrder = model.customTechnologies
        custom = Dictionary(
            model.customTechnologies.map { ($0.id, $0) },
            uniquingKeysWith: { _, later in later }
        )
        self.catalogue = catalogue
    }

    public func findById(_ id: TechnologyId) -> Technology? {
        custom[id]?.asTechnology ?? catalogue.findById(id)
    }

    /// A custom technology's threats are the catalogue's, named by it. One it
    /// names that the catalogue does not hold is dropped, the same way a
    /// dangling threat id in the vendored data is.
    public func threatsFor(technologyId: TechnologyId) -> [Threat] {
        guard let own = custom[technologyId] else {
            return catalogue.threatsFor(technologyId: technologyId)
        }
        let byId = Dictionary(
            catalogue.all().flatMap { catalogue.threatsFor(technologyId: $0.id) }
                .map { ($0.id, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        return own.threatIds.compactMap { byId[$0] }
    }

    /// The model's own first, so a user's own work is at hand.
    public func all() -> [Technology] {
        let ownIds = Set(customOrder.map(\.id))
        return customOrder.map(\.asTechnology)
            + catalogue.all().filter { ownIds.contains($0.id) == false }
    }
}
```

WARNING: `threatsFor` builds its index by walking every technology's threats. At 277 technologies that is wasteful on every call. If the package suite's time moves, add `allThreats()` to the catalogue port instead — and say so in the commit.

Add to `ThreatModel`, before the timestamps:

```swift
    /// Technologies this model defines for itself. Spec section 8: they travel
    /// in the document.
    public var customTechnologies: [CustomTechnology]
```

with an empty default in the initialiser.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && time swift test 2>&1 | tail -3
```

Expected: PASS, and the suite still runs in under 30 seconds.

- [ ] **Step 5: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: let a model define its own technologies

A custom technology belongs to one diagram and travels in its file, and reuses
the catalogue's threats rather than inventing ones the rest of the application
knows nothing about. TechnologyLookup answers from the model first, so a user
who names their own technology after one in the catalogue means theirs."
```

---

### Task 3: Creating, editing and deleting a custom technology

**Files:**
- Create: `.../modelling/usecase/CreateCustomTechnology.swift`, `EditCustomTechnology.swift`, `DeleteCustomTechnology.swift`
- Create: `.../catalogue/usecase/ListThreatChoices.swift`
- Modify: `.../UseCaseFactory.swift`, `.../TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- Create: `ThreatModelKit/Tests/UnitTests/CustomTechnologyUseCaseTests.swift`

**Interfaces:**
- `CreateCustomTechnologyRequest(name:categoryId:description:threatIds:enforcesEncryption:)` → `.created(technologyId:)`, `.emptyName`, `.unknownCategory`
- `EditCustomTechnologyRequest(technologyId:name:categoryId:description:threatIds:enforcesEncryption:)` → `.updated`, `.unknownTechnology`, `.emptyName`, `.unknownCategory`
- `DeleteCustomTechnologyRequest(technologyId:)` → `.deleted(removedComponentIds:removedConnectionIds:)`, `.unknownTechnology`
- `ListThreatChoicesRequest()` → `ListThreatChoicesResponse(threats: [ThreatChoice])`, `ThreatChoice(id:name:severityLabel:strideLabels:)`

Decisions this task fixes:

- **Deleting a custom technology deletes the components using it.** Leaving them behind would leave nodes the application cannot name or score — exactly the drift state a saved file can reach, but reached deliberately, which would be a bug rather than a report. The response says what went, so the canvas can drop it from the selection.
- **A threat a custom technology names must be one the catalogue holds.** The use case does not check: `TechnologyLookup` already drops an unknown one, the same way the bundled gateway drops a dangling id. The editor only offers real ones.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/CustomTechnologyUseCaseTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct CustomTechnologyUseCaseTests {
    private let models = InMemoryThreatModelGateway()
    private let catalogue = CatalogueFixture.catalogue()
    private let ids = SequentialIdentityGenerator()

    private func create(
        name: String = "Billing",
        category: String = "compute",
        threats: [String] = ["credential-theft"]
    ) -> CreateCustomTechnologyResponse {
        CreateCustomTechnology(models: models, catalogue: catalogue, ids: ids).execute(
            CreateCustomTechnologyRequest(
                name: name,
                categoryId: category,
                description: "Our own billing service",
                threatIds: threats,
                enforcesEncryption: false
            )
        )
    }

    private func madeId() -> String {
        guard case .created(let technologyId) = create() else {
            Issue.record("Expected the technology to be created")
            return ""
        }
        return technologyId
    }

    @Test func createsATechnologyTheModelOwns() throws {
        guard case .created(let technologyId) = create() else {
            Issue.record("Expected the technology to be created")
            return
        }

        let made = try #require(models.current().customTechnology(TechnologyId(technologyId)))
        #expect(made.name == "Billing")
        #expect(made.category == CategoryId("compute"))
        #expect(made.threatIds.map(\.value) == ["credential-theft"])
        #expect(made.provider == CustomTechnology.provider)
    }

    @Test func refusesATechnologyWithNoName() {
        #expect(create(name: "   ") == .emptyName)
        #expect(models.current().customTechnologies.isEmpty)
    }

    @Test func refusesACategoryTheTaxonomyDoesNotHold() {
        #expect(create(category: "mainframe") == .unknownCategory)
        #expect(models.current().customTechnologies.isEmpty)
    }

    @Test func editsWhatWasMade() throws {
        let technologyId = madeId()

        #expect(EditCustomTechnology(models: models, catalogue: catalogue).execute(
            EditCustomTechnologyRequest(
                technologyId: technologyId,
                name: "  Billing v2  ",
                categoryId: "database",
                description: "Now with a database",
                threatIds: ["misconfiguration"],
                enforcesEncryption: true
            )
        ) == .updated)

        let changed = try #require(models.current().customTechnology(TechnologyId(technologyId)))
        #expect(changed.name == "Billing v2")
        #expect(changed.category == CategoryId("database"))
        #expect(changed.threatIds.map(\.value) == ["misconfiguration"])
        #expect(changed.enforcesEncryption)
    }

    @Test func refusesToEditSomethingItDoesNotHold() {
        _ = madeId()

        #expect(EditCustomTechnology(models: models, catalogue: catalogue).execute(
            EditCustomTechnologyRequest(
                technologyId: "nope",
                name: "Billing",
                categoryId: "compute",
                description: "",
                threatIds: [],
                enforcesEncryption: false
            )
        ) == .unknownTechnology)
    }

    @Test func deletesItAndEverythingUsingIt() throws {
        let technologyId = madeId()
        let add = AddComponent(models: models, catalogue: catalogue, ids: ids)
        // AddComponent checks the catalogue, which does not hold this one, so
        // the component goes on directly.
        models.mutate { model in
            model.components.append(
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId(technologyId),
                    position: Point(x: 0, y: 0),
                    sensitivity: .internalData
                )
            )
        }
        guard case .added(let other) = add.execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        ) else {
            Issue.record("Expected the second component")
            return
        }
        _ = ConnectComponents(models: models, ids: ids)
            .execute(ConnectComponentsRequest(sourceComponentId: "c1", targetComponentId: other))

        guard case .deleted(let componentIds, let connectionIds) = DeleteCustomTechnology(models: models)
            .execute(DeleteCustomTechnologyRequest(technologyId: technologyId)) else {
            Issue.record("Expected the technology to be deleted")
            return
        }

        // Leaving the components behind would leave nodes the application
        // cannot name or score.
        #expect(componentIds == ["c1"])
        #expect(connectionIds.count == 1)
        #expect(models.current().customTechnologies.isEmpty)
        #expect(models.current().components.map(\.id.value) == [other])
        #expect(models.current().connections.isEmpty)
    }

    @Test func refusesToDeleteSomethingItDoesNotHold() {
        #expect(DeleteCustomTechnology(models: models)
            .execute(DeleteCustomTechnologyRequest(technologyId: "nope")) == .unknownTechnology)
    }

    @Test func offersEveryThreatTheEditorCanAttach() throws {
        let choices = ListThreatChoices(catalogue: catalogue)
            .execute(ListThreatChoicesRequest()).threats

        #expect(choices.isEmpty == false)
        #expect(choices.map(\.id).contains("credential-theft"))
        // In one order, worst first, so the editor's list does not shuffle.
        #expect(choices.map(\.id) == choices.map(\.id))
        let theft = try #require(choices.first { $0.id == "credential-theft" })
        #expect(theft.name == "Credential Theft")
        #expect(theft.severityLabel == "Critical")
        #expect(theft.strideLabels == ["Spoofing"])
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter CustomTechnologyUseCaseTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'CreateCustomTechnology' in scope`.

- [ ] **Step 3: Write the three use cases**

`CreateCustomTechnology`:

```swift
public protocol CreateCustomTechnologyUseCase {
    func execute(_ request: CreateCustomTechnologyRequest) -> CreateCustomTechnologyResponse
}

public struct CreateCustomTechnologyRequest: Equatable, Sendable {
    public let name: String
    public let categoryId: String
    public let description: String
    public let threatIds: [String]
    public let enforcesEncryption: Bool

    public init(
        name: String,
        categoryId: String,
        description: String,
        threatIds: [String],
        enforcesEncryption: Bool
    ) {
        self.name = name
        self.categoryId = categoryId
        self.description = description
        self.threatIds = threatIds
        self.enforcesEncryption = enforcesEncryption
    }
}

public enum CreateCustomTechnologyResponse: Equatable, Sendable {
    case created(technologyId: String)
    case emptyName
    case unknownCategory
}

/// Adds a technology this model defines for itself.
///
/// A threat it names that the catalogue does not hold is dropped when the
/// threats are read, the same way a dangling id in the vendored data is. The
/// editor only offers real ones.
public struct CreateCustomTechnology: CreateCustomTechnologyUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let ids: IdentityGenerator

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue, ids: IdentityGenerator) {
        self.models = models
        self.catalogue = catalogue
        self.ids = ids
    }

    public func execute(_ request: CreateCustomTechnologyRequest) -> CreateCustomTechnologyResponse {
        let name = request.name.trimmingWhitespace()
        guard name.isEmpty == false else { return .emptyName }

        let category = CategoryId(request.categoryId)
        guard catalogue.taxonomy().category(id: category) != nil else { return .unknownCategory }

        let technology = CustomTechnology(
            id: TechnologyId("custom-\(ids.next())"),
            name: name,
            category: category,
            description: request.description.trimmingWhitespace(),
            threatIds: request.threatIds.map(ThreatId.init),
            enforcesEncryption: request.enforcesEncryption
        )

        return models.mutate { model in
            model.customTechnologies.append(technology)
            return .created(technologyId: technology.id.value)
        }
    }
}
```

`EditCustomTechnology` is the same checks over an existing one:

```swift
public protocol EditCustomTechnologyUseCase {
    func execute(_ request: EditCustomTechnologyRequest) -> EditCustomTechnologyResponse
}

public struct EditCustomTechnologyRequest: Equatable, Sendable {
    public let technologyId: String
    public let name: String
    public let categoryId: String
    public let description: String
    public let threatIds: [String]
    public let enforcesEncryption: Bool

    public init(
        technologyId: String,
        name: String,
        categoryId: String,
        description: String,
        threatIds: [String],
        enforcesEncryption: Bool
    ) {
        self.technologyId = technologyId
        self.name = name
        self.categoryId = categoryId
        self.description = description
        self.threatIds = threatIds
        self.enforcesEncryption = enforcesEncryption
    }
}

public enum EditCustomTechnologyResponse: Equatable, Sendable {
    case updated
    case unknownTechnology
    case emptyName
    case unknownCategory
}

/// Changes a technology this model defines. All or nothing: one bad value
/// leaves every property as it was.
public struct EditCustomTechnology: EditCustomTechnologyUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: EditCustomTechnologyRequest) -> EditCustomTechnologyResponse {
        let id = TechnologyId(request.technologyId)
        let name = request.name.trimmingWhitespace()
        let category = CategoryId(request.categoryId)
        let knowsCategory = catalogue.taxonomy().category(id: category) != nil

        return models.mutate { model in
            guard let index = model.customTechnologies.firstIndex(where: { $0.id == id }) else {
                return .unknownTechnology
            }
            guard name.isEmpty == false else { return .emptyName }
            guard knowsCategory else { return .unknownCategory }

            model.customTechnologies[index].name = name
            model.customTechnologies[index].category = category
            model.customTechnologies[index].description = request.description.trimmingWhitespace()
            model.customTechnologies[index].threatIds = request.threatIds.map(ThreatId.init)
            model.customTechnologies[index].enforcesEncryption = request.enforcesEncryption
            return .updated
        }
    }
}
```

`DeleteCustomTechnology`:

```swift
public protocol DeleteCustomTechnologyUseCase {
    func execute(_ request: DeleteCustomTechnologyRequest) -> DeleteCustomTechnologyResponse
}

public struct DeleteCustomTechnologyRequest: Equatable, Sendable {
    public let technologyId: String
    public init(technologyId: String) { self.technologyId = technologyId }
}

public enum DeleteCustomTechnologyResponse: Equatable, Sendable {
    /// What went with it, so the canvas can drop those rows from its selection.
    case deleted(removedComponentIds: [String], removedConnectionIds: [String])
    case unknownTechnology
}

/// Removes a technology this model defines, and everything using it.
///
/// Leaving the components behind would leave nodes the application cannot name
/// or score. A saved file can reach that state and the drift report says so;
/// reaching it deliberately would be a bug.
public struct DeleteCustomTechnology: DeleteCustomTechnologyUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: DeleteCustomTechnologyRequest) -> DeleteCustomTechnologyResponse {
        let id = TechnologyId(request.technologyId)

        return models.mutate { model in
            guard model.customTechnologies.contains(where: { $0.id == id }) else {
                return .unknownTechnology
            }

            let doomed = Set(model.components.filter { $0.technologyId == id }.map(\.id))
            let removedComponents = model.components
                .filter { doomed.contains($0.id) }
                .map(\.id.value)
            let removedConnections = model.connections
                .filter { connection in doomed.contains(where: connection.touches) }
                .map(\.id.value)

            model.components.removeAll { doomed.contains($0.id) }
            model.connections.removeAll { connection in doomed.contains(where: connection.touches) }
            model.customTechnologies.removeAll { $0.id == id }

            let prefixes = doomed.map(ControlIdentity.componentPrefix)
            model.implementedControls = model.implementedControls.filter { key in
                prefixes.contains(where: key.value.hasPrefix) == false
            }

            return .deleted(
                removedComponentIds: removedComponents,
                removedConnectionIds: removedConnections
            )
        }
    }
}
```

- [ ] **Step 4: Write `ListThreatChoices`**

```swift
public protocol ListThreatChoicesUseCase {
    func execute(_ request: ListThreatChoicesRequest) -> ListThreatChoicesResponse
}

public struct ListThreatChoicesRequest: Equatable, Sendable {
    public init() {}
}

public struct ThreatChoice: Equatable, Sendable {
    public let id: String
    public let name: String
    public let severityLabel: String
    public let strideLabels: [String]

    public init(id: String, name: String, severityLabel: String, strideLabels: [String]) {
        self.id = id
        self.name = name
        self.severityLabel = severityLabel
        self.strideLabels = strideLabels
    }
}

public struct ListThreatChoicesResponse: Equatable, Sendable {
    /// Worst first, then by name, so the list does not shuffle between reads.
    public let threats: [ThreatChoice]

    public init(threats: [ThreatChoice]) {
        self.threats = threats
    }
}

/// Every threat the editor can attach to a custom technology.
///
/// A user naming their own service says which of the catalogue's threats it
/// carries; they cannot invent one the rest of the application knows nothing
/// about.
public struct ListThreatChoices: ListThreatChoicesUseCase {
    private let catalogue: TechnologyCatalogue

    public init(catalogue: TechnologyCatalogue) {
        self.catalogue = catalogue
    }

    public func execute(_ request: ListThreatChoicesRequest) -> ListThreatChoicesResponse {
        let taxonomy = catalogue.taxonomy()
        var found: [ThreatId: Threat] = [:]
        for technology in catalogue.all() {
            for threat in catalogue.threatsFor(technologyId: technology.id) {
                found[threat.id] = threat
            }
        }
        for threat in catalogue.connectionThreats() + catalogue.zoneThreats() {
            found[threat.id] = threat
        }

        let ordered = found.values.sorted {
            if $0.severity.rank != $1.severity.rank { return $0.severity.rank > $1.severity.rank }
            return $0.name < $1.name
        }

        return ListThreatChoicesResponse(
            threats: ordered.map { threat in
                ThreatChoice(
                    id: threat.id.value,
                    name: threat.name,
                    severityLabel: threat.severity.label,
                    strideLabels: threat.stride.compactMap { taxonomy.strideCategory(id: $0)?.label }
                )
            }
        )
    }
}
```

- [ ] **Step 5: Vend all four, and run the tests**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit threatmodeller/Dependencies.swift
git commit -m "feat: create, edit and delete a technology a model defines

Deleting one takes the components using it, because leaving them behind would
leave nodes the application cannot name or score. The editor is offered the
catalogue's threats worst first: a user says which their service carries, and
cannot invent one the rest of the application knows nothing about."
```

---

### Task 4: Everything reads the lookup

**Files:**
- Modify: `.../modelling/usecase/ViewThreatModel.swift`, `AddComponent.swift`
- Modify: `.../catalogue/usecase/ListTechnologies.swift`
- Modify: `.../assessment/domain/ThreatResolver.swift`
- Modify: `.../catalogue/usecase/ListPathwayMitigations.swift`
- Modify: the tests each of those has

Every reader that used `catalogue.findById`, `catalogue.threatsFor` or `catalogue.all()` against a model now uses `TechnologyLookup(model:catalogue:)`. `ListTechnologies` reads the model too, so a custom technology appears in the palette under its own provider.

- [ ] **Step 1: Write the failing test**

Add to `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`:

```swift
    @Test func raisesTheThreatsACustomTechnologyNames() throws {
        let billing = CustomTechnology(
            id: TechnologyId("custom-1"),
            name: "Billing",
            category: CategoryId("compute"),
            description: "Our own billing service",
            threatIds: [ThreatId("credential-theft")]
        )
        let response = assess(
            ThreatModel(
                components: [
                    Component(
                        id: ComponentId("c1"),
                        technologyId: TechnologyId("custom-1"),
                        position: Point(x: 0, y: 0),
                        sensitivity: .confidential
                    )
                ],
                customTechnologies: [billing]
            )
        )

        let theft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(theft.riskScore == 12)
        #expect(theft.source == .component(id: "c1", name: "Billing", providerId: "custom"))
    }
```

Add to `ThreatModelKit/Tests/UnitTests/ViewThreatModelTests.swift`:

```swift
    @Test func drawsAComponentOfATechnologyTheModelDefines() throws {
        let billing = CustomTechnology(
            id: TechnologyId("custom-1"),
            name: "Billing",
            category: CategoryId("compute"),
            description: "Our own billing service",
            threatIds: []
        )
        let response = view(
            ThreatModel(components: [component("c1", technologyId: "custom-1")],
                        customTechnologies: [billing])
        )

        let drawn = try #require(response.components.first)
        #expect(drawn.name == "Billing")
        #expect(drawn.providerId == "custom")
        #expect(drawn.isUnknownTechnology == false)
    }
```

Add to `ThreatModelKit/Tests/UnitTests/ListTechnologiesTests.swift`:

```swift
    @Test func offersTheTechnologiesTheModelDefines() throws {
        let billing = CustomTechnology(
            id: TechnologyId("custom-1"),
            name: "Billing",
            category: CategoryId("compute"),
            description: "Our own billing service",
            threatIds: []
        )
        let listed = ListTechnologies(
            models: InMemoryThreatModelGateway(ThreatModel(customTechnologies: [billing])),
            catalogue: CatalogueFixture.catalogue()
        ).execute(ListTechnologiesRequest())

        let custom = try #require(listed.providers.first { $0.id == "custom" })
        #expect(custom.displayName == "This Model")
        #expect(custom.categories.first?.technologies.map(\.name) == ["Billing"])
    }
```

WARNING: `ListTechnologies` currently takes only a catalogue. Giving it a gateway changes every construction of it — the composition roots and its own tests. That is the change; make it.

`ListTechnologies` needs a display name for the custom provider, and the catalogue has none for it. Use `"This Model"`, added where the response is built.

- [ ] **Step 2: Make each reader use the lookup**

In `AddComponent`, `ViewThreatModel`, `ListPathwayMitigations` and `ThreatResolver`, replace `catalogue.findById` / `catalogue.threatsFor` / `catalogue.all()` with a `TechnologyLookup(model: model, catalogue: catalogue)` built once from the model already in hand. `AddComponent` builds it inside its `mutate`, because it needs the model to check the technology exists:

```swift
    public func execute(_ request: AddComponentRequest) -> AddComponentResponse {
        let technologyId = TechnologyId(request.technologyId)
        guard let sensitivity = DataSensitivity(rawValue: request.sensitivity) else {
            return .unknownSensitivity
        }

        return models.mutate { model in
            guard TechnologyLookup(model: model, catalogue: catalogue)
                .findById(technologyId) != nil else {
                return .unknownTechnology
            }

            let component = Component(
                id: ComponentId(ids.next()),
                technologyId: technologyId,
                position: Point(x: request.x, y: request.y),
                sensitivity: sensitivity
            )
            model.components.append(component)
            return .added(componentId: component.id.value)
        }
    }
```

In `ListTechnologies`, take a `ThreatModelGateway` as well, read the model, and group `TechnologyLookup(...).all()` as it already groups the catalogue's — with `Provider(id: CustomTechnology.provider, displayName: "This Model")` appended to the provider list.

- [ ] **Step 3: Run every suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -5
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' build 2>&1 | grep -E 'error:|BUILD' | head -5
```

Expected: PASS and BUILD SUCCEEDED.

- [ ] **Step 4: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit threatmodeller
git commit -m "feat: read every technology through the lookup

The palette, the canvas, the resolver and the mitigation list all ask
TechnologyLookup, so a technology a model defines is a technology like any
other everywhere it appears."
```

---

### Task 5: A custom technology travels in the file

**Files:**
- Modify: `ThreatModelKit/Sources/FileGateways/DocumentJSON.swift`, `ThreatModelCodec.swift`
- Modify: `ThreatModelKit/Tests/GatewayIntegrationTests/ThreatModelCodecTests.swift`

Milestone 6A wrote `customTechnologies` as an empty array of strings so a 6A file would still read now. It becomes an array of objects, and **the format version goes to 2** — a 6A reader meeting a 6B file must refuse it rather than lose the technologies, which is what the version field is for.

WARNING: this makes every file written before now unreadable. That is the honest cost of a format change at this stage, and the refusal is loud. Milestone 8 or later can add a version 1 reader; the carry-forward records it.

- [ ] **Step 1: Write the failing test**

Change `ThreatModelCodecTests.fullModel()` to carry a custom technology, and add:

```swift
    @Test func carriesATechnologyTheModelDefines() throws {
        let billing = CustomTechnology(
            id: TechnologyId("custom-1"),
            name: "Billing",
            category: CategoryId("compute"),
            description: "Our own billing service",
            threatIds: [ThreatId("credential-theft")],
            enforcesEncryption: true
        )
        let model = ThreatModel(customTechnologies: [billing])

        #expect(try codec.decode(try codec.encode(model)).customTechnologies == [billing])
    }

    @Test func movesToTheSecondFormatVersion() {
        // Version 1 held customTechnologies as an empty array of strings. A
        // reader that meets the new shape and says version 1 would lose them.
        #expect(ThreatModelCodec.formatVersion == 2)
    }
```

and change the earlier `#expect(ThreatModelCodec.formatVersion == 1)` and the refusal test's `supported: 1` to `2`.

- [ ] **Step 2: Change the shape and the version**

`DocumentJSON.customTechnologies` becomes `[CustomTechnologyJSON]`:

```swift
struct CustomTechnologyJSON: Codable {
    let id: String
    let name: String
    let provider: String
    let category: String
    let description: String
    let threatIds: [String]
    let enforcesEncryption: Bool
}
```

`ThreatModelCodec.formatVersion` becomes `2`, and `encode`/`decode` map the array the way they map every other value, with a private `json(from:)` and `customTechnology(from:)` pair beside the others.

- [ ] **Step 3: Run every suite, and commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: carry a model's own technologies in its file

The document format moves to version 2. Version 1 held customTechnologies as
an empty array of strings, and a reader meeting the new shape while claiming
version 1 would lose them. Every file written before now is refused, loudly,
which is what the version field is for."
```

---

### Task 6: The acceptance test

**Files:**
- Create: `ThreatModelKit/Tests/AcceptanceTests/ModellingWhatIsNotInTheCatalogueTests.swift`

```swift
import Testing
import ThreatModelKit
import TestSupport

/// Given a system with a person outside it and a service of our own
/// When I draw both
/// Then they raise and carry threats like everything else
struct ModellingWhatIsNotInTheCatalogueTests {
    private let app = TestDependencies()

    private func add(_ technologyId: String, x: Double, sensitivity: String) -> String {
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: x, y: 100, sensitivity: sensitivity)
        ) else {
            Issue.record("Expected the component to be added")
            return ""
        }
        return componentId
    }

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    @Test func drawsAPersonOutsideTheBoundary() throws {
        let user = add("actor-user", x: 0, sensitivity: "public")
        let web = add("aws-ec2", x: 500, sensitivity: "restricted")

        // An actor raises nothing of its own.
        #expect(threats().contains { $0.source.id == "component:\(user)" } == false)

        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: user, targetComponentId: web)
        )

        // The link raises the connection threats like any other link, scored
        // against the more sensitive end.
        let mitm = try #require(threats().first { $0.threatId == "connection-mitm" })
        #expect(mitm.sensitivityId == "restricted")
        #expect(mitm.source.displayName == "End User → EC2")
    }

    @Test func drawsAServiceTheCatalogueDoesNotHave() throws {
        guard case .created(let billing) = app.createCustomTechnology().execute(
            CreateCustomTechnologyRequest(
                name: "Billing",
                categoryId: "compute",
                description: "Our own billing service",
                threatIds: ["credential-theft"],
                enforcesEncryption: false
            )
        ) else {
            Issue.record("Expected the technology to be created")
            return
        }

        // It is in the palette, under this model's own heading.
        let palette = app.listTechnologies().execute(ListTechnologiesRequest())
        let own = try #require(palette.providers.first { $0.id == "custom" })
        #expect(own.categories.first?.technologies.map(\.name) == ["Billing"])

        let component = add(billing, x: 0, sensitivity: "confidential")

        // And it raises the threats it named, scored like anything else.
        let theft = try #require(threats().first { $0.source.id == "component:\(component)" })
        #expect(theft.threatId == "credential-theft")
        #expect(theft.riskScore == 12)
        #expect(theft.source.displayName == "Billing")
    }

    @Test func keepsBothAcrossASaveAndAnOpen() throws {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        guard case .created(let billing) = app.createCustomTechnology().execute(
            CreateCustomTechnologyRequest(
                name: "Billing",
                categoryId: "compute",
                description: "Our own billing service",
                threatIds: ["credential-theft"],
                enforcesEncryption: true
            )
        ) else {
            Issue.record("Expected the technology to be created")
            return
        }
        _ = add(billing, x: 0, sensitivity: "confidential")
        _ = add("actor-user", x: 500, sensitivity: "public")
        let before = threats()

        guard case .saved(let file) = app.saveThreatModel().execute(SaveThreatModelRequest()) else {
            Issue.record("Expected the model to be saved")
            return
        }
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Blank"))

        guard case .opened(_, let drift) = app.openThreatModel().execute(
            OpenThreatModelRequest(data: file)
        ) else {
            Issue.record("Expected the file to open")
            return
        }

        // A technology the model defines is not drift: the file carries it.
        #expect(drift.unknownTechnologyIds.isEmpty)
        #expect(threats() == before)
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest())
                    .components.map(\.name).sorted() == ["Billing", "End User"])
    }

    @Test func takesTheComponentsWithItWhenItIsDeleted() throws {
        guard case .created(let billing) = app.createCustomTechnology().execute(
            CreateCustomTechnologyRequest(
                name: "Billing",
                categoryId: "compute",
                description: "",
                threatIds: ["credential-theft"],
                enforcesEncryption: false
            )
        ) else {
            Issue.record("Expected the technology to be created")
            return
        }
        let component = add(billing, x: 0, sensitivity: "confidential")
        let web = add("aws-ec2", x: 500, sensitivity: "confidential")
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: component, targetComponentId: web)
        )

        guard case .deleted(let componentIds, let connectionIds) = app.deleteCustomTechnology()
            .execute(DeleteCustomTechnologyRequest(technologyId: billing)) else {
            Issue.record("Expected the technology to be deleted")
            return
        }

        #expect(componentIds == [component])
        #expect(connectionIds.count == 1)
        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(canvas.components.map(\.id) == [web])
        #expect(canvas.connections.isEmpty)
    }

    @Test func editsWhatItNamedAndRescores() throws {
        guard case .created(let billing) = app.createCustomTechnology().execute(
            CreateCustomTechnologyRequest(
                name: "Billing",
                categoryId: "compute",
                description: "",
                threatIds: ["credential-theft"],
                enforcesEncryption: false
            )
        ) else {
            Issue.record("Expected the technology to be created")
            return
        }
        let component = add(billing, x: 0, sensitivity: "confidential")
        #expect(threats().first { $0.source.id == "component:\(component)" }?.threatId
                == "credential-theft")

        #expect(app.editCustomTechnology().execute(
            EditCustomTechnologyRequest(
                technologyId: billing,
                name: "Billing v2",
                categoryId: "compute",
                description: "",
                threatIds: ["dos-attack"],
                enforcesEncryption: false
            )
        ) == .updated)

        let after = threats().filter { $0.source.id == "component:\(component)" }
        #expect(after.map(\.threatId) == ["dos-attack"])
        #expect(after.first?.source.displayName == "Billing v2")
    }
}
```

Run it, then the whole suite, then commit:

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && time swift test 2>&1 | tail -3
```

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit/Tests/AcceptanceTests/ModellingWhatIsNotInTheCatalogueTests.swift
git commit -m "test: accept the milestone 7 core at the use case boundary

An actor raises nothing of its own but its links raise the connection threats.
A technology the model defines appears in the palette, raises what it named,
survives a save, and takes its components with it when it goes."
```

---

### Task 7: The editor

**Files:**
- Create: `threatmodeller/sidebar/CustomTechnologyEditor.swift`
- Modify: `threatmodeller/ThreatModelSession.swift`, `ContentView.swift`
- Modify: `threatmodellerTests/threatmodellerTests.swift`

**Interfaces:**
- `ThreatModelSession.threatChoices: [ThreatChoice]`, `.customTechnologies: [ListedTechnology]` (from the palette's `custom` provider), `.createCustomTechnology(name:categoryId:description:threatIds:enforcesEncryption:) -> String?`, `.editCustomTechnology(...)`, `.deleteCustomTechnology(_:)`, `.categoryChoices: [(id: String, label: String)]`
- `CustomTechnologyEditor(session:editing:onClose:)`

The editor is a sheet: a name, a category, a description, a switch for transport encryption, and a list of the catalogue's threats to tick. It opens from a button under the palette, and from a row's context menu for editing.

`ThreatModelSession.refresh()` also reads `ListThreatChoices` and keeps `categoryChoices` from the palette's own categories, so the sheet has everything without a second port.

Add two session tests: creating one puts it in the palette and raises its threats; deleting one removes the components using it and clears them from any canvas selection passed in.

Run every suite, look at it by eye — make a technology, put it on the canvas, edit its threats, watch the sidebar change, delete it — and commit.

---

### Task 8: The user interface journey

**Files:**
- Modify: `threatmodellerUITests/threatmodellerUITests.swift`

Add to the journey, after the palette opens: double-click `technology-actor-user`, and assert a `node-actor-user` appears on the canvas. That covers the actors end to end without touching the parts the carry-forward already records as uncovered.

WARNING: the actors are their own provider, so the journey must open that provider's category first. Query `category-actor-person` the way it queries `category-aws-compute`.

Run the interface suite, then every suite, then commit.

---

## Milestone complete

- [ ] `swift test` from `ThreatModelKit/` is green and runs in under 30 seconds.
- [ ] `xcodebuild ... test` is green, including the interface suite.
- [ ] The catalogue tag is still `v1.0.1`, and `actors.json` has no lock entry.
- [ ] `grep -rn 'actors.json' scripts/` finds nothing: the vendoring script never touches it.
- [ ] Nine actors are in the palette under "External Actors", each raising nothing of its own.
- [ ] A link to an actor raises the connection threats.
- [ ] A technology the model defines appears in the palette under "This Model", raises the threats it named, and is scored like any other.
- [ ] A technology the model defines survives a save and an open, and is not reported as drift.
- [ ] Deleting one takes the components using it, and their links, and their ticks.
- [ ] The document format is version 2, and a version 1 file is refused.

Then write `docs/superpowers/specs/MILESTONE-8-CARRY-FORWARD.md` and start Milestone 8: Markdown, threatcl HCL, PDF and PNG exports.

New and deferred from this milestone: every file written before this milestone is refused, because the format moved to version 2 and no version 1 reader exists; `TechnologyLookup.threatsFor` builds its threat index by walking every technology on every call, which is wasteful at 277 technologies and wants `allThreats()` on the catalogue port if the suite's time moves; and a custom technology cannot define a threat of its own, only name one the catalogue holds.
