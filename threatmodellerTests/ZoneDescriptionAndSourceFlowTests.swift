import ArchitectureDSL
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// A zone's description and source in the window, end to end: what the zone
/// panel writes into the `.arch` file, and what a save keeps when nobody
/// edits the zone's source.
@MainActor
@Suite("A zone's description and source in the window")
struct ZoneDescriptionAndSourceFlowTests {
    private let plain = """
    system "Payments" {
      zone "app" {
        kind            = "private"
        network         = "generic"
        reduces_risk_by = 20
      }
    }

    """

    private let described = """
    system "Payments" {
      zone "app" {
        kind            = "private"
        network         = "generic"
        reduces_risk_by = 20
        description     = "guest wifi"
      }
    }

    """

    private let imported = """
    system "Payments" {
      zone "app" {
        kind            = "private"
        network         = "generic"
        reduces_risk_by = 20
        source          = "terraform"
      }
    }

    """

    private func aProject(_ text: String) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(text, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func architecture(_ useCases: TestDependencies) -> String? {
        useCases.project.text(at: "/work/threatmodel/payments.arch")
    }

    private func zonePanel(_ model: ThreatModelSession, zoneId: String) throws -> ZonePanel {
        let zone = try #require(model.canvas.zones.first { $0.id == zoneId })
        return ZonePanel(session: model, zone: zone)
    }

    // MARK: the description field

    @Test func thePanelShowsTheDescriptionAZoneStates() async throws {
        let (session, _) = await aProject(described)
        let model = try #require(session.model)

        #expect(try zonePanel(model, zoneId: "app").zone.description == "guest wifi")
    }

    @Test func thePanelWritesTheDescriptionIntoTheFile() async throws {
        let (session, useCases) = await aProject(plain)
        let model = try #require(session.model)

        try zonePanel(model, zoneId: "app").commitDescription("guest wifi")
        await session.save()

        #expect(model.errorMessage == nil)
        #expect(architecture(useCases) == described)
    }

    @Test func thePanelTakesTheDescriptionBackOff() async throws {
        let (session, useCases) = await aProject(described)
        let model = try #require(session.model)

        try zonePanel(model, zoneId: "app").commitDescription("")
        await session.save()

        #expect(architecture(useCases) == plain)
    }

    // MARK: source, which the window keeps and no control changes

    @Test func savingWithNoEditKeepsTheSourceAnImportWrote() async throws {
        let (session, useCases) = await aProject(imported)
        let model = try #require(session.model)
        #expect(model.errorMessage == nil)

        await session.save()

        #expect(architecture(useCases) == imported)
    }

    /// Changing a property the zone panel does offer must not drop the
    /// source an import wrote: no control shows it, and none may clear it.
    @Test func savingAfterAnUnrelatedEditKeepsTheSourceAnImportWrote() async throws {
        let (session, useCases) = await aProject(imported)
        let model = try #require(session.model)
        let before = try #require(model.canvas.zones.first { $0.id == "app" })

        model.setZoneProperties(
            zoneId: "app",
            name: "Guest network",
            networkZoneId: before.networkZoneId,
            networkTypeId: before.networkTypeId,
            riskReductionEnabled: before.riskReductionEnabled,
            riskReductionPercent: before.riskReductionPercent,
            boundaryId: before.boundaryId
        )
        await session.save()

        let file = try #require(architecture(useCases))
        #expect(file.contains("source          = \"terraform\""))
        #expect(file.contains("name            = \"Guest network\""))
    }
}
