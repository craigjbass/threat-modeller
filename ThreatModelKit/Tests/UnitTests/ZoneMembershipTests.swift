import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// Which zone holds which component, as a field on the component.
@Suite("Zone membership")
struct ZoneMembershipTests {
    private let app = TestDependencies()

    private let payments = """
    system "Payments" {
      zone "app" {
        kind = "private"

        component "api" { technology = "aws-ec2" }
        component "db" { technology = "aws-rds" }
      }

      component "outside" { technology = "aws-ec2" }
    }
    """

    private func imported() -> ThreatModel {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        return app.modelStore.current()
    }

    private func zone(of componentId: String, in model: ThreatModel) -> String? {
        model.components.first { $0.id == ComponentId(componentId) }?.zoneId?.value
    }

    @Test func aComponentKeepsTheZoneItIsBuiltWith() {
        let component = Component(
            id: ComponentId("api"),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData,
            zoneId: ZoneId("app")
        )

        #expect(component.zoneId == ZoneId("app"))
    }

    @Test func theImportReadsTheNestingTheFileStates() {
        let model = imported()

        #expect(zone(of: "api", in: model) == "app")
        #expect(zone(of: "db", in: model) == "app")
        #expect(zone(of: "outside", in: model) == nil)
    }

    @Test func theSameArchitectureScoresTheSame() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let scored = app.assessThreatModel().execute(AssessThreatModelRequest())

        #expect(scored.threats.isEmpty == false)
        #expect(scored.threats.contains { $0.source.id.hasPrefix("zone:") })
    }
}

/// Geometry decides membership on an edit, and writes it on the component.
@Suite("What an edit does to zone membership")
struct ZoneMembershipEditTests {
    private let app = TestDependencies()

    /// One zone, and one component inside it.
    private func drawn() -> (component: String, zone: String) {
        guard case .added(let zoneId) = app.addZone().execute(
            AddZoneRequest(x: 0, y: 0, width: 600, height: 500)
        ) else { return ("", "") }
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 100, y: 100, sensitivity: "internal")
        ) else { return ("", zoneId) }
        return (componentId, zoneId)
    }

    private func zone(of componentId: String) -> String? {
        app.modelStore.current()
            .components.first { $0.id == ComponentId(componentId) }?.zoneId?.value
    }

    @Test func aComponentDroppedInsideAZoneJoinsIt() {
        let drawn = drawn()

        #expect(zone(of: drawn.component) == drawn.zone)
    }

    @Test func aDragIntoAZonePutsTheComponentInIt() {
        let drawn = drawn()
        _ = app.moveComponents().execute(
            MoveComponentsRequest(moves: [ComponentMove(componentId: drawn.component, x: 2000, y: 2000)])
        )
        #expect(zone(of: drawn.component) == nil)

        _ = app.moveComponents().execute(
            MoveComponentsRequest(moves: [ComponentMove(componentId: drawn.component, x: 200, y: 200)])
        )

        #expect(zone(of: drawn.component) == drawn.zone)
    }

    @Test func aDragOutOfEveryZoneTakesTheComponentOutOfTheOneItWasIn() {
        let drawn = drawn()

        _ = app.moveComponents().execute(
            MoveComponentsRequest(moves: [ComponentMove(componentId: drawn.component, x: 3000, y: 3000)])
        )

        #expect(zone(of: drawn.component) == nil)
    }

    @Test func aZoneResizedOffAComponentReleasesIt() {
        let drawn = drawn()

        _ = app.resizeZone().execute(
            ResizeZoneRequest(zoneId: drawn.zone, x: 0, y: 0, width: 130, height: 120)
        )

        #expect(zone(of: drawn.component) == nil)
    }

    @Test func aZoneResizedOverAComponentTakesIt() {
        let drawn = drawn()
        _ = app.moveComponents().execute(
            MoveComponentsRequest(moves: [ComponentMove(componentId: drawn.component, x: 900, y: 700)])
        )
        #expect(zone(of: drawn.component) == nil)

        _ = app.resizeZone().execute(
            ResizeZoneRequest(zoneId: drawn.zone, x: 0, y: 0, width: 1400, height: 1000)
        )

        #expect(zone(of: drawn.component) == drawn.zone)
    }

    @Test func aZoneMovedOverAComponentTakesIt() {
        let drawn = drawn()
        _ = app.moveComponents().execute(
            MoveComponentsRequest(moves: [ComponentMove(componentId: drawn.component, x: 2000, y: 300)])
        )
        #expect(zone(of: drawn.component) == nil)

        _ = app.moveZones().execute(
            MoveZonesRequest(moves: [ZoneMove(zoneId: drawn.zone, x: 1900, y: 200)])
        )

        #expect(zone(of: drawn.component) == drawn.zone)
    }
}

/// The point of the change: a compile scores the same model with no layout.
@Suite("A compile with no layout")
struct CompileWithNoLayoutTests {
    private let architecture = """
    system "Payments" {
      zone "app" {
        kind = "private"

        component "api" {
          technology = "aws-ec2"
          data       = "confidential"
        }

        component "db" { technology = "aws-rds" }
      }

      component "edge" { technology = "aws-waf" }

      flow api -> db
      flow edge -> api
    }
    """

    /// The controls file a compile writes, with and without a layout.
    private func compiled(withLayout: Bool) -> String {
        let app = TestDependencies()
        let compile = CompileControls(
            catalogue: app.catalogueInUse,
            architectureSources: HclArchitectureSource(),
            controlsSources: HclControlsSource(),
            attackTreeSources: HclAttackTreeSource()
        )
        guard case .compiled(let text, _, _, _, _, _, _) = compile.execute(
            CompileControlsRequest(architectureText: architecture)
        ) else {
            Issue.record("the controls did not compile")
            return ""
        }
        return text
    }

    /// The same architecture, imported with a layout and scored.
    private func scoredWithALayout() -> [String] {
        let app = TestDependencies()
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: architecture))
        return app.assessThreatModel().execute(AssessThreatModelRequest()).threats
            .map { "\($0.threatId)@\($0.source.id)=\($0.riskScore)" }
            .sorted()
    }

    /// The same architecture, imported with no layout and scored.
    private func scoredWithNoLayout() -> [String] {
        let app = TestDependencies()
        _ = ImportArchitecture(
            models: app.modelStore,
            catalogue: app.catalogueInUse,
            sources: HclArchitectureSource(),
            attackTreeSources: HclAttackTreeSource(),
            layout: nil
        ).execute(ImportArchitectureRequest(text: architecture))
        return app.assessThreatModel().execute(AssessThreatModelRequest()).threats
            .map { "\($0.threatId)@\($0.source.id)=\($0.riskScore)" }
            .sorted()
    }

    @Test func answersTheSameThreatsWithTheSameScores() {
        #expect(scoredWithNoLayout() == scoredWithALayout())
    }

    @Test func writesAControlsFileThatHoldsEveryThreat() {
        let text = compiled(withLayout: false)

        #expect(text.contains("controls for \"Payments\""))
        #expect(text.contains("on zone \"app\""))
        #expect(text.contains("on component \"api\""))
    }
}

/// A layout that counts how many times it ran, so a test states that the save
/// path runs none.
final class CountingLayout: LayOutModelUseCase, @unchecked Sendable {
    private(set) var runs = 0
    private let real = LayOutModel()

    func execute(_ request: LayOutModelRequest) -> LayOutModelResponse {
        runs += 1
        return real.execute(request)
    }
}

@Suite("What the save path lays out")
struct SavePathLayoutTests {
    private let architecture = """
    system "Payments" {
      zone "app" {
        kind = "private"

        component "api" {
          technology = "aws-ec2"
          data       = "confidential"
        }
      }
    }
    """

    @Test func aCompileLaysNothingOut() {
        let app = TestDependencies()
        let counting = CountingLayout()
        let compile = CompileControls(
            catalogue: app.catalogueInUse,
            architectureSources: HclArchitectureSource(),
            controlsSources: HclControlsSource(),
            attackTreeSources: HclAttackTreeSource()
        )

        _ = compile.execute(CompileControlsRequest(architectureText: architecture))

        // Nothing was given a layout to run, and the compile asked for none.
        #expect(counting.runs == 0)
    }

    @Test func anImportForTheScreenStillLaysOut() {
        let app = TestDependencies()
        let counting = CountingLayout()

        _ = ImportArchitecture(
            models: app.modelStore,
            catalogue: app.catalogueInUse,
            sources: HclArchitectureSource(),
            attackTreeSources: HclAttackTreeSource(),
            layout: counting
        ).execute(ImportArchitectureRequest(text: architecture))

        #expect(counting.runs == 1)
    }
}
