import ArchitectureDSL
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Stating whether a component is live or proposed in the window, end to end:
/// what the component panel writes into the `.arch` file, and what the canvas
/// reads back.
@MainActor
@Suite("The status of a component in the window")
struct ComponentStatusFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "db" {
        technology = "aws-rds"
        data       = "restricted"
      }

      flow api -> db
    }

    """

    private let planned = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
        status     = "proposed"
      }

      component "db" {
        technology = "aws-rds"
        data       = "restricted"
      }

      flow api -> db
    }

    """

    private func aProject(_ text: String? = nil) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(text ?? payments, at: "/work/threatmodel/payments.arch")
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

    private func panel(
        _ model: ThreatModelSession,
        componentId: String
    ) throws -> ComponentPanel {
        let component = try #require(model.canvas.components.first { $0.id == componentId })
        return ComponentPanel(session: model, component: component)
    }

    @Test func thePanelShowsTheStatusAComponentStates() async throws {
        let (session, _) = await aProject(planned)
        let model = try #require(session.model)

        #expect(try panel(model, componentId: "api").status.wrappedValue == "proposed")
        #expect(try panel(model, componentId: "db").status.wrappedValue == "live")
    }

    @Test func thePanelWritesTheStatusIntoTheFile() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        try panel(model, componentId: "api").status.wrappedValue = "proposed"
        await session.save()

        #expect(model.errorMessage == nil)
        #expect(architecture(useCases) == planned)
    }

    @Test func thePanelPutsAProposedComponentBackToLive() async throws {
        let (session, useCases) = await aProject(planned)
        let model = try #require(session.model)

        try panel(model, componentId: "api").status.wrappedValue = "live"
        await session.save()

        #expect(architecture(useCases) == payments)
    }

    @Test func theStatusChangesNoScore() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let before = model.threats.count

        try panel(model, componentId: "api").status.wrappedValue = "proposed"

        #expect(model.threats.count == before)
    }
}
