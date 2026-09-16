import ArchitectureDSL
import Foundation
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Dragging a component into a zone another part file declares, end to end:
/// what the drag writes into the component's own part file, what the zone's
/// file keeps, and what a reopened project draws.
@MainActor
@Suite("A component dragged into a zone from another part file")
struct ZoneAcrossPartFilesFlowTests {
    private let header = "system \"Payments\" { }\n"

    private let edge = """
    zone "edge" {
      kind            = "public"
      network         = "dmz"
      reduces_risk_by = 20

      component "waf" {
        technology = "aws-waf"
      }
    }

    """

    private let ledger = """
    component "api" {
      technology = "aws-ec2"
    }

    """

    private func aSplitProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(header, at: "/work/threatmodel/payments/arch/payments.arch")
        useCases.project.put(edge, at: "/work/threatmodel/payments/arch/edge.arch")
        useCases.project.put(ledger, at: "/work/threatmodel/payments/arch/ledger.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    /// The position that puts the component's centre in the middle of the
    /// zone, below the zone's header band.
    private func inside(_ zone: ViewedZone) -> (x: Double, y: Double) {
        (
            x: zone.x + zone.width / 2 - Component.size.width / 2,
            y: zone.y + zone.height / 2 - Component.size.height / 2
        )
    }

    /// One line of the file, with the spaces that line the equals signs up
    /// taken out.
    private func attributes(_ text: String?) -> [String] {
        (text ?? "").split(separator: "\n").map { String($0.filter { $0 != " " }) }
    }

    @Test func theDragWritesTheZoneAttributeIntoTheComponentsOwnPartFile() async throws {
        let (session, useCases) = await aSplitProject()
        let model = try #require(session.model)
        let zone = try #require(model.canvas.zones.first { $0.id == "edge" })
        let target = inside(zone)

        model.move([ComponentMove(componentId: "api", x: target.x, y: target.y)])
        await session.save()

        #expect(model.errorMessage == nil)
        let ledgerFile = useCases.project.text(at: "/work/threatmodel/payments/arch/ledger.arch")
        #expect(attributes(ledgerFile).contains("zone=\"edge\""))
        #expect(ledgerFile?.hasPrefix("component \"api\" {") == true)
    }

    @Test func theZonesOwnPartFileKeepsOnlyItsOwnComponent() async throws {
        let (session, useCases) = await aSplitProject()
        let model = try #require(session.model)
        let zone = try #require(model.canvas.zones.first { $0.id == "edge" })
        let target = inside(zone)

        model.move([ComponentMove(componentId: "api", x: target.x, y: target.y)])
        await session.save()

        let edgeFile = useCases.project.text(at: "/work/threatmodel/payments/arch/edge.arch")
        #expect(edgeFile == edge)
    }

    @Test func aReopenedProjectDrawsTheComponentInsideTheZone() async throws {
        let (session, useCases) = await aSplitProject()
        let model = try #require(session.model)
        let zone = try #require(model.canvas.zones.first { $0.id == "edge" })
        let target = inside(zone)
        model.move([ComponentMove(componentId: "api", x: target.x, y: target.y)])
        await session.save()

        let reopened = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await reopened.open(root: "/work")

        let drawn = try #require(reopened.model?.canvas.components.first { $0.id == "api" })
        #expect(drawn.zoneId == "edge")
    }

    /// Dragging the component back out takes the line back off.
    @Test func draggingOutOfTheZoneTakesTheAttributeBackOff() async throws {
        let (session, useCases) = await aSplitProject()
        let model = try #require(session.model)
        let zone = try #require(model.canvas.zones.first { $0.id == "edge" })
        let target = inside(zone)
        model.move([ComponentMove(componentId: "api", x: target.x, y: target.y)])
        await session.save()

        model.move([
            ComponentMove(
                componentId: "api",
                x: zone.x + zone.width + 400,
                y: zone.y + zone.height + 400
            )
        ])
        await session.save()

        let ledgerFile = useCases.project.text(at: "/work/threatmodel/payments/arch/ledger.arch")
        #expect(ledgerFile == ledger)
    }
}
