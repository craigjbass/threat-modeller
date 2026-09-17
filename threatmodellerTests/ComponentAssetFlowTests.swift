import ArchitectureDSL
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// A component's own `asset` block in the window, end to end: what the
/// component panel writes into the `.arch` file, and what the panel reads
/// back from a file that already states the block.
@MainActor
@Suite("A component's own asset block in the window")
struct ComponentAssetFlowTests {
    private let plain = """
    system "Payments" {
      component "workstation" {
        technology = "aws-ec2"
        data       = "internal"
      }
    }

    """

    private let withAsset = """
    system "Payments" {
      component "workstation" {
        technology = "aws-ec2"
        data       = "internal"

        asset "ssh-keys" {
          data = "restricted"
        }
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

    private func componentPanel(
        _ model: ThreatModelSession,
        componentId: String
    ) throws -> ComponentPanel {
        let component = try #require(model.canvas.components.first { $0.id == componentId })
        return ComponentPanel(session: model, component: component)
    }

    // MARK: what the panel shows

    @Test func thePanelShowsTheAssetsAComponentStates() async throws {
        let (session, _) = await aProject(withAsset)
        let model = try #require(session.model)

        let panel = try componentPanel(model, componentId: "workstation")
        #expect(panel.component.assets.map(\.name) == ["ssh-keys"])
        #expect(panel.component.assets.map(\.classificationId) == ["restricted"])
    }

    // MARK: what the panel writes

    @Test func thePanelWritesTheAssetBlockIntoTheFile() async throws {
        let (session, useCases) = await aProject(plain)
        let model = try #require(session.model)

        try componentPanel(model, componentId: "workstation")
            .addAsset(name: "ssh-keys", classificationId: "restricted")
        await session.save()

        #expect(model.errorMessage == nil)
        #expect(architecture(useCases) == withAsset)
    }

    @Test func thePanelTakesTheAssetBlockBackOff() async throws {
        let (session, useCases) = await aProject(withAsset)
        let model = try #require(session.model)

        try componentPanel(model, componentId: "workstation").removeAsset(name: "ssh-keys")
        await session.save()

        #expect(model.errorMessage == nil)
        #expect(architecture(useCases) == plain)
    }

    @Test func thePanelChangesTheClassificationOfAnAssetThatIsThere() async throws {
        let (session, useCases) = await aProject(withAsset)
        let model = try #require(session.model)

        try componentPanel(model, componentId: "workstation")
            .addAsset(name: "ssh-keys", classificationId: "confidential")
        await session.save()

        let file = try #require(architecture(useCases))
        #expect(file.contains("asset \"ssh-keys\" {"))
        #expect(file.contains("data = \"confidential\""))
    }

    /// An asset with no name writes nothing and the window says why.
    @Test func anAssetWithNoNameIsRefusedAndTheWindowSaysSo() async throws {
        let (session, _) = await aProject(plain)
        let model = try #require(session.model)

        try componentPanel(model, componentId: "workstation")
            .addAsset(name: " ", classificationId: "restricted")

        #expect(model.errorMessage == "An asset needs a name.")
        #expect(model.canvas.components.first { $0.id == "workstation" }?.assets.isEmpty == true)
    }

    /// The Add button is off while the name field is empty, so the panel
    /// asks for a name before it writes.
    @Test func theAddButtonWaitsForAName() async throws {
        let (session, _) = await aProject(plain)
        let model = try #require(session.model)
        let panel = try componentPanel(model, componentId: "workstation")

        #expect(panel.canAddAsset(named: " ") == false)
        #expect(panel.canAddAsset(named: "ssh-keys"))
    }
}
