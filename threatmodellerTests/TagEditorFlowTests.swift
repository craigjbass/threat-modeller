import ArchitectureDSL
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Filing an element under a tag in the window, end to end: what the component
/// panel writes into the `.arch` file, and what the canvas tag filter draws
/// without touching the file or the score.
@MainActor
@Suite("Tags in the window")
struct TagEditorFlowTests {
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

    private let tagged = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
        tags       = ["payments", "pci"]
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

    // MARK: the panel

    @Test func thePanelShowsTheTagsAComponentHolds() async throws {
        let (session, _) = await aProject(tagged)
        let model = try #require(session.model)

        #expect(try panel(model, componentId: "api").tagsText == "payments, pci")
    }

    @Test func thePanelWritesTheTagsIntoTheFile() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        try panel(model, componentId: "api").commitTags("payments, pci")
        await session.save()

        #expect(model.errorMessage == nil)
        #expect(architecture(useCases) == tagged)
    }

    @Test func thePanelTakesEveryTagBackOff() async throws {
        let (session, useCases) = await aProject(tagged)
        let model = try #require(session.model)

        try panel(model, componentId: "api").commitTags("")
        await session.save()

        #expect(architecture(useCases) == payments)
    }

    // MARK: the filter

    @Test func theToolbarListsEveryTagTheSystemStates() async throws {
        let (session, _) = await aProject(tagged)
        let model = try #require(session.model)

        #expect(TagFilter.tags(in: model.canvas) == ["payments", "pci"])
    }

    @Test func theFilterDrawsOnlyTheElementsThatHoldThePickedTag() async throws {
        let (session, _) = await aProject(tagged)
        let model = try #require(session.model)
        let canvas = CanvasState()

        canvas.pick(tag: "payments")

        let drawn = canvas.tagFilter.narrow(model.canvas)
        #expect(drawn.components.map(\.id) == ["api"])
        #expect(drawn.connections.isEmpty)
    }

    @Test func theFilterChangesNoFileAndNoScore() async throws {
        let (session, useCases) = await aProject(tagged)
        let model = try #require(session.model)
        let canvas = CanvasState()
        let threatsBefore = model.threats.count
        let before = architecture(useCases)

        canvas.pick(tag: "payments")

        #expect(canvas.tagFilter.isNarrowing)
        #expect(model.threats.count == threatsBefore)
        #expect(architecture(useCases) == before)
        // The model itself still holds every element; only the drawing narrows.
        #expect(model.canvas.components.count == 2)
    }

    @Test func theNeighbourDepthChangesNoFileAndNoScore() async throws {
        let (session, useCases) = await aProject(tagged)
        let model = try #require(session.model)
        let canvas = CanvasState()
        let threatsBefore = model.threats.count
        let before = architecture(useCases)

        canvas.pick(tag: "payments")
        canvas.setNeighbourDepth(1)

        #expect(model.threats.count == threatsBefore)
        #expect(architecture(useCases) == before)
        #expect(model.canvas.components.count == 2)
        let drawn = canvas.tagFilter.narrow(model.canvas)
        #expect(drawn.components.map(\.id) == ["api", "db"])
    }

    @Test func clearFilterDrawsTheWholeModelAgain() async throws {
        let (session, _) = await aProject(tagged)
        let model = try #require(session.model)
        let canvas = CanvasState()
        canvas.pick(tag: "payments")

        canvas.clearTagFilter()

        let drawn = canvas.tagFilter.narrow(model.canvas)
        #expect(canvas.tagFilter.isNarrowing == false)
        #expect(drawn.components.map(\.id) == ["api", "db"])
        #expect(drawn.connections.map(\.id) == ["api->db"])
    }
}
