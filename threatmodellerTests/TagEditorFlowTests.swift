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

    private let zoned = """
    system "Payments" {
      zone "app" {
        kind            = "private"
        network         = "generic"
        reduces_risk_by = 20

        component "api" {
          technology = "aws-ec2"
          data       = "confidential"
        }

        component "db" {
          technology = "aws-rds"
          data       = "restricted"
        }
      }

      flow api -> db
    }

    """

    private let zonedAndTagged = """
    system "Payments" {
      zone "app" {
        kind            = "private"
        network         = "generic"
        reduces_risk_by = 20
        tags            = ["payments", "pci"]

        component "api" {
          technology = "aws-ec2"
          data       = "confidential"
        }

        component "db" {
          technology = "aws-rds"
          data       = "restricted"
        }
      }

      flow api -> db {
        kind = "network"
        tags = ["ingest"]
      }
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

    private func zonePanel(_ model: ThreatModelSession, zoneId: String) throws -> ZonePanel {
        let zone = try #require(model.canvas.zones.first { $0.id == zoneId })
        return ZonePanel(session: model, zone: zone)
    }

    private func flowPanel(
        _ model: ThreatModelSession,
        connectionId: String
    ) throws -> ConnectionPanel {
        let connection = try #require(
            model.canvas.connections.first { $0.id == connectionId }
        )
        return ConnectionPanel(session: model, connection: connection)
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

    // MARK: Focus

    @Test func focusChangesNoFileAndNoScore() async throws {
        let (session, useCases) = await aProject(tagged)
        let model = try #require(session.model)
        let canvas = CanvasState()
        let threatsBefore = model.threats.count
        let before = architecture(useCases)

        canvas.focus(componentId: "api")

        #expect(model.threats.count == threatsBefore)
        #expect(architecture(useCases) == before)
        #expect(model.canvas.components.count == 2)
    }

    /// The tag filter picks a tag `api` does not hold, so the filter hides
    /// it. Focus on `api` clears that filter, and `api` is drawn.
    @Test func focusClearsATagFilterThatHidesTheFocusedComponent() async throws {
        let (session, _) = await aProject(tagged)
        let model = try #require(session.model)
        let canvas = CanvasState()
        canvas.pick(tag: "pci")
        #expect(canvas.tagFilter.narrow(model.canvas).components.map(\.id) == ["api"])
        canvas.pick(tag: "pci")
        canvas.pick(tag: "made-up")
        #expect(canvas.tagFilter.narrow(model.canvas).components.isEmpty)

        canvas.focus(componentId: "api")

        #expect(canvas.tagFilter.isNarrowing == false)
        let drawn = TagFilter.focus(on: "api", depth: 0, in: model.canvas)
        #expect(drawn.components.map(\.id) == ["api"])
    }

    @Test func clearFilterAlsoClearsFocus() async throws {
        let (session, _) = await aProject(tagged)
        let model = try #require(session.model)
        let canvas = CanvasState()
        canvas.focus(componentId: "api")

        canvas.clearTagFilter()

        #expect(canvas.focusedComponentId == nil)
        let drawn = canvas.tagFilter.narrow(model.canvas)
        #expect(drawn.components.map(\.id) == ["api", "db"])
    }

    // MARK: the zone panel and the flow panel

    @Test func theZonePanelShowsTheTagsAZoneHolds() async throws {
        let (session, _) = await aProject(zonedAndTagged)
        let model = try #require(session.model)

        #expect(try zonePanel(model, zoneId: "app").tagsText == "payments, pci")
    }

    @Test func theFlowPanelShowsTheTagsAFlowHolds() async throws {
        let (session, _) = await aProject(zonedAndTagged)
        let model = try #require(session.model)

        #expect(try flowPanel(model, connectionId: "api->db").tagsText == "ingest")
    }

    /// The acceptance of #152: the window tags a zone and a flow, and the
    /// `.arch` file reads back with both tag lists.
    @Test func theZoneAndFlowPanelsWriteTheirTagsIntoTheFile() async throws {
        let (session, useCases) = await aProject(zoned)
        let model = try #require(session.model)

        try zonePanel(model, zoneId: "app").commitTags("payments, pci")
        try flowPanel(model, connectionId: "api->db").commitTags("ingest")
        await session.save()

        #expect(model.errorMessage == nil)
        #expect(architecture(useCases) == zonedAndTagged)
    }

    @Test func theZonePanelTakesEveryTagBackOff() async throws {
        let (session, useCases) = await aProject(zonedAndTagged)
        let model = try #require(session.model)

        try zonePanel(model, zoneId: "app").commitTags("")
        try flowPanel(model, connectionId: "api->db").commitTags("")
        await session.save()

        #expect(architecture(useCases) == zoned)
    }

    /// The zone panel writes tags and nothing else: the kind, the network and
    /// the risk reduction the file states stay as they are.
    @Test func theZonePanelChangesNoOtherZoneProperty() async throws {
        let (session, _) = await aProject(zoned)
        let model = try #require(session.model)

        try zonePanel(model, zoneId: "app").commitTags("payments")

        let zone = try #require(model.canvas.zones.first { $0.id == "app" })
        #expect(zone.tags == ["payments"])
        #expect(zone.networkZoneId == "private")
        #expect(zone.networkTypeId == "generic")
        #expect(zone.boundaryId == "network")
    }

    /// The flow panel writes tags and nothing else: the kind and the
    /// description the file states stay as they are.
    @Test func theFlowPanelChangesNoOtherFlowProperty() async throws {
        let (session, _) = await aProject(zonedAndTagged)
        let model = try #require(session.model)

        try flowPanel(model, connectionId: "api->db").commitTags("payments")

        let flow = try #require(model.canvas.connections.first { $0.id == "api->db" })
        #expect(flow.tags == ["payments"])
        #expect(flow.kindId == "network")
    }

    /// A tag on the zone alone gives a view: the toolbar offers it, and the
    /// canvas draws the zone with the components inside it.
    @Test func aTagOnTheZoneAloneDrawsTheZoneAndTheComponentsInIt() async throws {
        let (session, _) = await aProject(zoned)
        let model = try #require(session.model)
        let canvas = CanvasState()

        try zonePanel(model, zoneId: "app").commitTags("payments")

        #expect(TagFilter.tags(in: model.canvas) == ["payments"])
        canvas.pick(tag: "payments")
        let drawn = canvas.tagFilter.narrow(model.canvas)
        #expect(drawn.zones.map(\.id) == ["app"])
        #expect(drawn.components.map(\.id) == ["api", "db"])
        #expect(drawn.connections.map(\.id) == ["api->db"])
    }
}
