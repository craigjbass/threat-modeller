import ArchitectureDSL
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// A component's `holds` list in the window, end to end.
///
/// Issue #179: `Holds` used to draw a `Menu` of one `Toggle` per system
/// asset, the same fault `Uses` and `Reaches` had. `IdTokenField` replaces
/// it, so `holds` and `uses`/`reaches` share one control.
@MainActor
@Suite("A component's holds list in the window")
struct ComponentHoldsFlowTests {
    private let plain = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private let withAssets = """
    system "Payments" {
      asset "card-numbers" {
        name           = "Card numbers"
        classification = "confidential"
      }

      asset "session-tokens" {
        name           = "Session tokens"
        classification = "confidential"
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
        holds      = ["card-numbers"]
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

    private func componentPanel(_ model: ThreatModelSession) throws -> ComponentPanel {
        let component = try #require(model.canvas.components.first { $0.id == "api" })
        return ComponentPanel(session: model, component: component)
    }

    // MARK: the empty state

    @Test func theFieldShowsTheEmptyStateWhenNoAssetExists() async throws {
        let (session, _) = await aProject(plain)
        let model = try #require(session.model)
        let panel = try componentPanel(model)

        let field = panel.holdsField
        #expect(field.choices.isEmpty)
        #expect(field.emptyMessage == ComponentPanel.noAssetMessage)
    }

    // MARK: picking and removing

    @Test func picksAnAssetAndWritesItIntoTheFile() async throws {
        let (session, useCases) = await aProject(withAssets)
        let model = try #require(session.model)

        var panel = try componentPanel(model)
        let choice = try #require(panel.holdsField.rows.first { $0.id == "session-tokens" })
        panel.holdsField.pick(choice)

        panel = try componentPanel(model)
        #expect(panel.component.holds == ["card-numbers", "session-tokens"])
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("holds      = [\"card-numbers\", \"session-tokens\"]"))
    }

    @Test func aTokenComesOffAndTheFileFollows() async throws {
        let (session, useCases) = await aProject(withAssets)
        let model = try #require(session.model)

        var panel = try componentPanel(model)
        panel.holdsField.remove("card-numbers")

        panel = try componentPanel(model)
        #expect(panel.component.holds.isEmpty)
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("holds") == false)
    }
}
