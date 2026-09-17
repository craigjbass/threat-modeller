import ArchitectureDSL
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// A component's source in the window, end to end: what a save keeps when
/// nobody edits it, and what a save keeps when an unrelated field changes.
/// No control shows or clears a component's source.
@MainActor
@Suite("A component's source in the window")
struct ComponentSourceFlowTests {
    private let imported = """
    system "Payments" {
      component "aws-instance-api" {
        technology = "aws-ec2"
        source     = "terraform"
      }
    }

    """

    private let importedWithVersion = """
    system "Payments" {
      component "aws-instance-api" {
        technology = "aws-ec2"
        version    = "2.0"
        source     = "terraform"
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

    private func panel(
        _ model: ThreatModelSession,
        componentId: String
    ) throws -> ComponentPanel {
        let component = try #require(model.canvas.components.first { $0.id == componentId })
        return ComponentPanel(session: model, component: component)
    }

    @Test func savingWithNoEditKeepsTheSourceAnImportWrote() async throws {
        let (session, useCases) = await aProject(imported)
        let model = try #require(session.model)
        #expect(model.errorMessage == nil)

        await session.save()

        #expect(architecture(useCases) == imported)
    }

    /// Changing a property the component panel does offer must not drop the
    /// source an import wrote: no control shows it, and none may clear it.
    @Test func savingAfterAnUnrelatedEditKeepsTheSourceAnImportWrote() async throws {
        let (session, useCases) = await aProject(imported)
        let model = try #require(session.model)

        try panel(model, componentId: "aws-instance-api").commitVersion("2.0")
        await session.save()

        #expect(architecture(useCases) == importedWithVersion)
    }
}
