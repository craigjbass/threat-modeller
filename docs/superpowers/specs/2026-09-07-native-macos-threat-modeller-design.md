# Native macOS Threat Modeller — Design

Date: 2026-09-07
Status: Approved for planning

## 1. Purpose

Build a native macOS application that reproduces the full functionality of
[threatmodelling.io](https://github.com/jib1337/threatmodelling.io), using the
technology and threat catalogue published by
[threat-model-library](https://github.com/jib1337/threat-model-library).

The user builds a diagram of technologies, connects them, groups them into
network trust zones, and the application continuously derives the threats that
apply, scores their risk, and lets the user record which mitigating controls are
in place. Models are saved as documents and exported as reports.

### Explicitly out of scope

The application does not integrate with threatmodelling.io in any way. It does
not read or write that application's model format, does not call its APIs, and
does not fetch anything from its release channel at build time or run time. The
catalogue data is vendored as read-only reference data and nothing else is
shared.

## 2. Constraints and decisions taken

| Decision | Choice |
|---|---|
| Fidelity | Full feature parity with threatmodelling.io, delivered in sequenced milestones |
| Platform | Native macOS, Swift, minimum deployment target macOS 26 Tahoe |
| Architecture | Made Tech flavour Clean Architecture (Use Case / Domain / Gateway / Delivery Mechanism) |
| Diagram canvas | Pure SwiftUI, hand-rolled node graph |
| Catalogue | Vendored JSON committed to this repo, refreshed by a pinned script |
| Persistence | Document-based app, own file format, no interoperability with the web app |
| Undo/redo | Core use cases over a history gateway, not NSUndoManager |
| Assessment refresh | Delivery mechanism calls `AssessThreatModel` explicitly after each mutation |
| Dependency wiring | One `Dependencies` graph per open document |

## 3. Architecture

### 3.1 Vocabulary

Follows https://github.com/madetech/clean-architecture:

- **Use Case** — one per file, one public method `execute`, request and response
  are simple data structures. Collaborators are injected via the initialiser;
  the request is passed to `execute`.
- **Domain** — objects that model the problem in a storage-agnostic way. Anemic
  by default; behaviour moves into the domain only once a rule is provably valid
  across more than one use case.
- **Gateway** — adapts an IO mechanism. Accepts and returns Domain objects. The
  only non-Domain values crossing a gateway boundary are identifiers used to
  locate data.
- **Delivery Mechanism** — SwiftUI/AppKit. Translates user events into use case
  calls and use case responses into presentation. No business rules, no gateway
  knowledge.

Domain objects never cross the use case boundary. Responses are plain values.

### 3.2 Module layout

```
ThreatModelKit/                       local Swift package
  Sources/
    ThreatModelKit/                   the core; no AppKit, no SwiftUI
      catalogue/{domain,usecase,gateway}
      modelling/{domain,usecase,gateway}
      assessment/{domain,usecase,gateway}
      reporting/{domain,usecase,gateway}
    CatalogueGateways/                real gateway over the vendored JSON
    FileGateways/                     real gateway over the document file
    CatalogueGateways/Resources/      vendored catalogue (see §7)
  Tests/
    AcceptanceTests/
    UnitTests/
    GatewayContractTests/
    GatewayIntegrationTests/
threatmodeller/                       delivery mechanism (Xcode app target)
threatmodellerTests/                  canvas geometry unit tests
threatmodellerUITests/                smoke tests only
```

`swift test` on the package runs acceptance, unit, contract and integration
suites without building the app target.

### 3.3 Bounded contexts

Four implicit bounded contexts, expressed as directories and namespacing only:

- **catalogue** — the read-only technology and threat library
- **modelling** — the diagram: components, connections, zones, custom
  technologies
- **assessment** — threat resolution, risk scoring, pathway mitigations,
  overrides, implemented controls
- **reporting** — exports

Fan-out across a context boundary goes through a gateway protocol owned by the
consuming context. `assessment` declares its own `TechnologyCatalogue` port
rather than depending on `catalogue`'s internals.

### 3.4 Swift shape of a use case

```swift
// modelling/usecase/AddComponent.swift

public protocol AddComponentUseCase {
    func execute(_ request: AddComponentRequest) -> AddComponentResponse
}

public struct AddComponentRequest {
    public let technologyId: String
    public let x: Double
    public let y: Double
    public let sensitivity: String
}

public enum AddComponentResponse {
    case added(componentId: String)
    case unknownTechnology
}

public struct AddComponent: AddComponentUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let ids: IdentityGenerator

    public init(models: ThreatModelGateway,
                catalogue: TechnologyCatalogue,
                ids: IdentityGenerator) { ... }

    public func execute(_ request: AddComponentRequest) -> AddComponentResponse { ... }
}
```

Conventions:

- Protocol named `<UseCase>UseCase`, concrete type named `<UseCase>`.
- `Request` and `Response` are top-level types named `<UseCase>Request` /
  `<UseCase>Response`, flat and greppable.
- A use case with a single outcome returns a struct. A use case with several
  distinct outcomes returns an `enum`, which gives compiler-enforced exhaustive
  handling at every call site — the typed-language equivalent of the presenter
  pattern's polymorphism.
- Presenters (self-shunting view models) are reserved for the small number of
  cases where two delivery paths genuinely handle the same outcomes differently.

### 3.5 Composition root

`Dependencies` in the app target constructs gateways and vends use cases.
`TestDependencies` in the acceptance suite vends the same use cases wired to
fakes. Views never name a gateway type.

One `Dependencies` graph is constructed per open document. Each document owns an
in-memory `ThreatModelGateway` seeded from its file; saving writes that
gateway's model back out. The core has no concept of documents or windows.

### 3.6 What is and is not a use case call

An interactive canvas cannot route per-frame interaction through the core.

- **Delivery mechanism only:** pan, zoom, selection state, drag in flight,
  marquee rectangle, hover, connection preview line, theme.
- **Use case:** anything that changes the model and therefore the threat output —
  a completed drag (`MoveComponents`), a completed zone resize (`ResizeZone`), a
  dropped connection (`ConnectComponents`), a deletion, a property change.

## 4. Use cases

One actor: the threat modeller.

### catalogue

- `ListTechnologies` — palette contents, grouped by provider and category
- `SearchTechnologies`
- `ViewTechnology`
- `ListPathwayMitigations`

### modelling

- `CreateThreatModel`
- `OpenThreatModel`
- `SaveThreatModel`
- `RenameThreatModel`
- `ViewThreatModel` — the components and connections the canvas draws, as plain
  values. This is the `CanvasSnapshot` of section 9. The canvas never reads a
  gateway, so a read use case supplies it.
- `AddComponent`
- `MoveComponents`
- `RemoveComponents`
- `RenameComponent`
- `SetComponentSensitivity`
- `DisableComponentThreats`
- `ConnectComponents`
- `LabelConnection`
- `RemoveConnection`
- `AddZone`
- `ResizeZone`
- `SetZoneProperties`
- `RemoveZone`
- `CopySelection`
- `PasteSelection`
- `DuplicateSelection`
- `UndoLastChange`
- `RedoChange`
- `CreateCustomTechnology`
- `EditCustomTechnology`
- `DeleteCustomTechnology`
- `LoadSampleModel`

### assessment

- `AssessThreatModel` — the full resolution: component threats, connection
  threats, zone threats, risk scores, escalation, pathway mitigation
- `OverrideThreatSeverity`
- `ClearSeverityOverride`
- `RecordControlImplemented`
- `RecordControlNotImplemented`
- `ConfigurePathwayMitigations`
- `SummariseRisk` — counts by risk level and STRIDE category

### reporting

- `ExportModelAsMarkdown`
- `ExportModelAsThreatcl`
- `BuildThreatModelReport` — returns a pure document description; a gateway
  renders it to PDF
- `ExportModelAsImage` — supplies metadata; the canvas bitmap itself is produced
  by a delivery-mechanism gateway

## 5. Domain

### 5.1 Plain values

**catalogue:** `Technology`, `Threat`, `Control`, `MitreTechnique`,
`StrideCategory`, `ThreatSeverity`, `ServiceCategory`, `Provider`,
`PathwayMitigationDefinition`, `Taxonomy`, `ConnectionSecurity`

**modelling:** `ThreatModel` (aggregate root), `Component`, `Connection`, `Zone`,
`Point`, `Size`, `Rect`, `DataSensitivity`, `NetworkZone`, `ZoneNetworkType`

`NetworkZone` and `ZoneNetworkType` are application-owned, as `DataSensitivity`
is. The catalogue carries no zone vocabulary.

- `NetworkZone`: `public` ("Public Zone"), `private` ("Private Zone").
- `ZoneNetworkType`: `generic` ("Generic Network"), `vpc` ("VPC"), `subnet`
  ("Subnet"), `onPremises` ("On-Premises"), `dmz` ("DMZ"), `management`
  ("Management Network"), `data` ("Data Network").

**assessment:** `ActiveThreat`, `RiskLevel`, `PathwayMitigationSettings`,
`PathwayMitigationConfig`

### 5.2 Domain objects with behaviour from day one

Each of these owns a rule that is already valid across more than one use case.

| Domain object | Rule | Used by |
|---|---|---|
| `RiskScore` | severity(1–4) × sensitivity(1–4) → 1–16; thresholds ≥12 critical, ≥8 high, ≥4 medium, else low | `AssessThreatModel`, `SummariseRisk` |
| `ZoneContainment` | a component belongs to a zone when its centre lies within the zone rect, offset by 40pt of header padding; later zones win over earlier ones | `AssessThreatModel`, `ViewThreatModel` |
| `UpstreamGraph` | reverse breadth-first traversal of connections to the set of components upstream of a given component | `AssessThreatModel`, pathway settings preview |
| `SensitivityLadder` | higher-of two sensitivities; maximum sensitivity across directly downstream components | `AssessThreatModel` |
| `ControlIdentity` | djb2 hash of the whitespace-normalised control description, scoped by owner; pruning a component's keys on delete | `RecordControlImplemented`, `RemoveComponents`, `SaveThreatModel` |

### 5.3 Scoring rules to reproduce exactly

These are behavioural requirements, not implementation notes. Every one is
covered by a test ported from the original suite.

**Base score**

- `severityValue × sensitivityValue`, both ranked 1–4 in taxonomy order,
  producing 1–16.
- Risk level: `>= 12` critical, `>= 8` high, `>= 4` medium, otherwise low.

**Zone multiplier**

- Public zone, or no zone: `1.0`.
- Private zone with risk reduction disabled: `1.0`.
- Private zone otherwise: `(100 − reductionPercent) / 100`, default reduction
  20%.
- Applied to the base score with `round()`.

**Connection threats and zones**

- A connection receives a zone multiplier only when *both* endpoints sit in
  private zones.
- When both do, the **lower** of the two reduction percentages is used.
- A connection's sensitivity is the higher of its two endpoints' sensitivities.

**Zone threats**

- Scored against a fixed `internal` base sensitivity.
- Raised once per private zone, for each threat flagged `isZoneThreat`.
- The zone's own multiplier applies to its zone threats. The multiplier rule
  above states no exception, and the reduction models controls at the zone
  boundary, which are the controls those threats are about.
- Zone display name: custom name, else the network type label when it is not
  `generic`, else the zone type label.

**Pathway threats and escalation**

- A threat flagged `isPathwayThreat` escalates its sensitivity to the maximum
  sensitivity among directly downstream components, when that is higher.

**Pathway mitigation**

- Applies when the master toggle is on, the specific mitigation is enabled, an
  upstream component provides that mitigation, and the mitigation lists the
  threat id.
- Mode `remove`: the threat is dropped entirely.
- Mode `reduce`: `max(1, floor(score − score × percent / 100))`. A reduced threat
  never reaches zero.
- Connection threats use the *source* component's upstream mitigations.

**Connection encryption**

- Threats `connection-mitm` and `connection-data-exposure` are flagged as
  TLS-mitigated when either endpoint technology declares
  `connectionSecurity.enforcesEncryption`.
- This is a display flag only. **It does not change the risk score.**

**Severity overrides**

Keyed as:

- component threat: `{technologyId}::{threatId}`
- connection threat: `connection::{threatId}`
- zone threat: `zone::{threatId}`

**Control identity**

djb2 (`hash = 5381`, `hash = hash*33 + byte`, unsigned 32-bit, 8 hex digits) over
the description trimmed and with runs of whitespace collapsed to a single space.
Scoped keys:

- `node:{componentId}:{threatId}::{fingerprint}` — generic threat controls
- `node:{componentId}:{threatId}:tech::{fingerprint}` — technology-specific
  mitigations
- `connection:{threatId}::{fingerprint}` — consolidated across connections
- `zone:{threatId}::{fingerprint}` — consolidated across zones

Removing a component prunes every `node:{componentId}:` key.

**Other**

- A component with threats disabled contributes no component threats, and
  suppresses connection threats on any connection touching it.
- Technology-specific `threatMitigations` supersede a threat's generic
  `controls` for that technology. Connection and zone threats always use the
  generic controls.
- Duplicate `(threat, source)` pairs are raised once.
- Any threat scoring 0 is filtered from the result.

**Connection rules**

- A connection is directed. It has a source component and a target component,
  and the canvas draws an arrowhead at the target.
- A component cannot connect to itself.
- A second connection with the same source and the same target is refused.
- A connection from B to A is a separate connection from one from A to B, and
  both may exist.
- Removing a component also removes every connection that touches it.

## 6. Gateways

| Port | Responsibility |
|---|---|
| `TechnologyCatalogue` | `all()`, `findById(_:)`, `threatsFor(technologyId:)`, `connectionThreats()`, `zoneThreats()`, `taxonomy()`, `pathwayMitigations()` |
| `ThreatModelGateway` | `current()`, `save(_:)`, `pushHistory()`, `undo()`, `redo()` |
| `SampleModelGateway` | list and load bundled sample models |
| `ReportRenderer` | accept a `Report` value tree, write PDF |
| `CanvasImageRenderer` | produce a PNG of the current canvas (delivery-mechanism gateway) |
| `IdentityGenerator` | component, connection and zone ids |
| `Clock` | created/updated timestamps |

Every port has a fake and a real implementation, and a single shared contract
test suite that both must pass. Contracts are written entirely in Domain
objects.

## 7. Catalogue vendoring

Source: `jib1337/threat-model-library`, raw `data/` directory at a pinned release
tag.

```
ThreatModelKit/Sources/CatalogueGateways/Resources/Library/
  taxonomy.json
  technologies/{aws,azure,gcp,saas,self-hosted}.json
  threats/common-threats.json
  mitigations/pathway-mitigations.json
  actors.json                        app-owned; external actor components
  library.lock.json                  pinned tag + SHA-256 of each file
```

The directory is declared as an SPM resource bundle on the `CatalogueGateways`
target, so the real gateway loads it from `Bundle.module` and the core stays
free of any resource dependency.

`scripts/update-catalogue.sh` downloads the pinned tag, verifies checksums,
rewrites the files and updates `library.lock.json`. Catalogue updates arrive as a
reviewable diff. Builds are offline and reproducible.

No manifest file is vendored: provider display names come from each provider
file's own `displayName`, and mitigation provider names are resolved against the
technologies at load time.

Current catalogue content, for sizing: 5 providers (AWS 57, Azure 54, GCP 48,
SaaS 30, self-hosted 88 services), 55 threats of which 5 are connection threats,
6 are zone threats and 17 are pathway threats, 14 service categories, 4
severities, 6 STRIDE categories, 4 pathway mitigation types.

External actors (`actor-mobile`, `actor-desktop`, `actor-iot`,
`actor-api-client`, and the rest) are application-owned, not part of the
catalogue. They carry no threats of their own and widen the provider and
category vocabularies on the application's side.

### Licensing obligations

The catalogue is © 2026 Jack Nelson, licensed CC BY 4.0, and includes MITRE
ATT&CK® content reproduced with the permission of The MITRE Corporation. The
application must:

- ship a `NOTICE` file recording both attributions
- surface the attribution in an About window
- record the vendored catalogue version and release tag in that window

The application's own code is MIT-licensed, as the original is.

## 8. Document format

- UTType `io.threatmodeller.model`, filename extension `.threatmodel`
- `FileDocument`, presented through `DocumentGroup`
- Single JSON file

Contents: model name, created/updated timestamps, components, connections,
zones, custom technologies, severity overrides, implemented controls, pathway
mitigation settings, and the catalogue version the model was last assessed
against.

The catalogue version stamp lets the application report drift when a model is
opened against a newer catalogue — for example a technology or threat that no
longer exists.

This format shares no lineage with threatmodelling.io's export format.

## 9. Delivery mechanism

One `ThreatModelSession` (`@Observable`) per open document. It holds that
document's `Dependencies`, calls use cases, and publishes the latest
`AssessThreatModelResponse` and a `CanvasSnapshot`. It contains no business
rules and names no gateway.

### Canvas

- Transform layer: `.scaleEffect(zoom, anchor: .topLeading).offset(pan)`
- Painting order: zones, then a single `Canvas { GraphicsContext }` layer
  drawing every connection (bezier plus arrowhead) in one pass, then component
  views positioned with `.position`
- Component drag updates a local offset only; `.onEnded` calls `MoveComponents`
- Connection drawing: drag from an anchor handle renders a live preview path;
  the drop calls `ConnectComponents`
- Marquee selection: drag on empty canvas, rectangle intersection
- Zone drawing and resizing: handles on the zone view, commit on release

Canvas geometry — anchor point placement, connection hit-testing, marquee
intersection, zone hit-testing — lives in plain testable structs in the app
target, never inside a `View` body.

### Chrome

Sidebar of threat cards grouped by source, with STRIDE tags, MITRE techniques,
controls and implementation checkboxes; technology palette with search and
provider/category grouping; node and zone property panels; toolbar; settings;
samples browser; custom technology editor; shortcuts reference; about window.
Dark and light themes. Menu commands and keyboard shortcuts map to the same use
cases as the toolbar.

Keyboard parity: select all, shift-click add/remove from selection, escape to
deselect or cancel zone drawing, copy, cut, paste, duplicate, delete, arrow
nudge 10pt, shift-arrow nudge 1pt, double-click a palette item to add and a
connection to edit its label, undo, redo.

## 10. Testing

Acceptance-test-driven outer loop, test-driven inner loop.

| Suite | May depend on | Runs against |
|---|---|---|
| `AcceptanceTests` | the use case boundary only — never a Domain object, never a gateway | `TestDependencies` (fakes) |
| `UnitTests` | use cases and domain objects | fakes |
| `GatewayContractTests` | one shared contract per port | fake **and** real |
| `GatewayIntegrationTests` | real vendored JSON, real files in temp directories | real only |
| `CanvasGeometryTests` | app-target geometry structs | pure |
| UI tests | smoke only: the app launches and shows a window | — |

Framework: Swift Testing.

Four Vitest suites of the original describe behaviour this application must
reproduce exactly, and are ported to Swift as the parity specification:
`riskCalculator.test.ts`, `threatResolver.test.ts`,
`pathwayMitigations.test.ts` and `controlFingerprint.test.ts`. Equivalence is
demonstrated rather than asserted.

`threatclExport.test.ts` is also ported, because threatcl HCL is a third-party
format with its own shape to honour.

`pdfExport.test.ts` and `importExport.integration.test.ts` are **not** ported.
The PDF report structure and the document format are this application's own, so
their tests are written fresh — including a document round-trip test against the
format defined in §8.

Target: the package suite runs in under 30 seconds. Gateway integration tests
stay in a separate suite so the inner loop stays fast.

## 11. Milestones

Each milestone gets its own implementation plan, written when the previous one
is complete.

1. **Walking skeleton** — package skeleton, vendoring script, real catalogue
   gateway and its contract, `ListTechnologies`, `AddComponent`,
   `AssessThreatModel` limited to component threats. Acceptance test: add EC2,
   see EC2's threats with correct scores. Minimal window listing palette and
   threats.
2. **Canvas** — component views, drag, connections, selection, pan/zoom,
   marquee, delete; connection threats and their encryption flag.
3. **Zones** — draw, move, resize, containment, zone threats, risk reduction.
4. **Threat sidebar** — threat cards, STRIDE, MITRE, controls, implementation
   checkboxes, severity overrides, risk summary.
5. **Pathway mitigations** — upstream graph, per-mitigation configuration UI.
6. **Documents** — UTType, `DocumentGroup`, save and open, undo/redo,
   copy/paste/duplicate, menu commands and keyboard shortcuts.
7. **Custom technologies and external actors.**
8. **Reporting** — Markdown, threatcl HCL, PDF, PNG.
9. **Samples, About and attribution, theming, app icon, polish.**

## 12. Risks

- **Canvas effort.** React Flow supplies roughly ten thousand lines of
  interaction behaviour that must be rebuilt. Milestones 2 and 3 are the bulk of
  the project's risk and should be planned in more detail than the rest.
- **Scoring fidelity.** The original's rules contain several asymmetries that
  read like bugs but are the specification. §5.3 pins them; the ported tests
  enforce them.
- **Catalogue drift.** The upstream library evolves. The lock file and the
  version stamp in saved documents keep drift visible rather than silent.
- **PDF layout.** Report content is testable as a value tree, but the rendered
  page layout is only verifiable by eye and is excluded from TDD.
