import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Merging two components in the window, end to end: the sheet's draft lists
/// each difference, the verb writes both files, and one Undo puts the model
/// and the files back.
@MainActor
@Suite("Merging components in the window")
struct MergeFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "api2" {
        technology = "aws-ec2"
        name       = "Payments API"
        data       = "restricted"
        runs_as    = "admin"
      }

      component "ledger" {
        technology = "aws-rds"
        data       = "restricted"
      }

      component "cdn" {
        technology = "aws-waf"
      }

      flow api -> ledger
      flow api2 -> ledger {
        kind        = "network"
        description = "writes"
      }

      flow cdn -> api2
    }

    """

    private let answered = """
    controls for "Payments" {
      threat "credential-theft" on component "api2" {
        control "Enforce IMDSv2 to block SSRF-based credential theft" {
          status    = "implemented"
          evidence  = "tested"
          reference = "ci/imdsv2"
        }
      }
    }

    """

    private let archPath = "/work/threatmodel/payments.arch"
    private let controlsPath = "/work/threatmodel/payments.controls"

    private func aProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: archPath)
        useCases.project.put(answered, at: controlsPath)
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func draft(_ model: ThreatModelSession, _ ids: [String]) -> MergeDraft {
        MergeDraft(session: model, componentIds: ids)
    }

    /// Merges `api2` into `api` the way the sheet does: the draft resolves
    /// every attribute, and the verb writes the resolved values.
    private func mergeApi2IntoApi(_ model: ThreatModelSession, picking: [MergeDraft.Attribute: String] = [:]) -> Bool {
        var draft = draft(model, ["api", "api2"])
        for (attribute, componentId) in picking { draft.pick(attribute, from: componentId) }
        return model.mergeComponents(draft.resolved)
    }

    // MARK: the draft

    @Test func theDraftListsEachDifferenceAndStartsOnTheSurvivor() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        let draft = draft(model, ["api2", "api"])

        #expect(draft.survivorId == "api")
        #expect(draft.differences.map(\.attribute) == [.name, .sensitivity, .runsAs])
        let name = try #require(draft.differences.first { $0.attribute == .name })
        #expect(name.choices.map(\.componentId) == ["api", "api2"])
        #expect(name.choices.map(\.label) == ["EC2", "Payments API"])
        #expect(draft.resolved.name == nil)
        #expect(draft.resolved.sensitivityId == "confidential")
        #expect(draft.resolved.runsAsId == "user")
    }

    @Test func aPickedValueIsTheOneResolved() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        var draft = draft(model, ["api", "api2"])
        draft.pick(.name, from: "api2")
        draft.pick(.sensitivity, from: "api2")

        #expect(draft.resolved.survivorId == "api")
        #expect(draft.resolved.sourceIds == ["api2"])
        #expect(draft.resolved.name == "Payments API")
        #expect(draft.resolved.sensitivityId == "restricted")
        #expect(draft.resolved.runsAsId == "user")
    }

    @Test func keepingAnotherComponentResetsEveryPickToIt() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        var draft = draft(model, ["api", "api2"])
        draft.pick(.sensitivity, from: "api")
        draft.keep("api2")

        #expect(draft.resolved.survivorId == "api2")
        #expect(draft.resolved.sourceIds == ["api"])
        #expect(draft.resolved.name == "Payments API")
        #expect(draft.resolved.sensitivityId == "restricted")
        #expect(draft.resolved.runsAsId == "admin")
    }

    @Test func theDraftListsEveryAttributeTheSourcesDifferIn() throws {
        let model = ThreatModelSession(useCases: TestDependencies())
        model.add(technologyId: "aws-ec2", x: 0, y: 0)
        model.add(technologyId: "aws-rds", x: 300, y: 0)
        let ids = model.canvas.components.map(\.id)
        let zoneId = try #require(model.addZone(x: 250, y: -50, width: 300, height: 200))
        model.setThirdParty(id: "acme", name: "Acme")
        model.setSystemAsset(id: "cards", name: "Cards", classificationId: "restricted")
        model.setComponentProperties(
            componentId: ids[1],
            name: "Store",
            sensitivityId: "restricted",
            threatsDisabled: false,
            runsAsId: "admin",
            shapeId: "actor",
            holds: ["cards"],
            tags: ["core"],
            status: "proposed"
        )
        model.setComponentProvider(componentId: ids[1], thirdPartyId: "acme")
        model.move([ComponentMove(componentId: ids[1], x: 300, y: 0)])

        let draft = MergeDraft(session: model, componentIds: ids)

        #expect(draft.differences.map(\.attribute) == MergeDraft.Attribute.allCases)
        let zone = try #require(draft.differences.first { $0.attribute == .zone })
        #expect(zone.choices.map(\.label) == ["No zone", model.canvas.zones.first?.name ?? ""])
        #expect(draft.differences.first { $0.attribute == .providedBy }?.choices.map(\.label) == ["Nobody", "Acme"])
        #expect(draft.differences.first { $0.attribute == .shape }?.choices.map(\.label) == ["From the technology", "Actor"])
        #expect(draft.differences.first { $0.attribute == .holds }?.choices.map(\.label) == ["Nothing", "cards"])
        #expect(draft.differences.first { $0.attribute == .tags }?.choices.map(\.label) == ["None", "core"])
        #expect(draft.differences.first { $0.attribute == .status }?.choices.map(\.label) == ["Live", "Proposed"])
        var picked = draft
        picked.keep(ids[1])
        #expect(picked.resolved.zoneId == zoneId)
        #expect(picked.resolved.providedById == "acme")
        #expect(picked.resolved.shapeId == "actor")
        #expect(picked.resolved.holds == ["cards"])
        #expect(picked.resolved.tags == ["core"])
        #expect(picked.resolved.statusId == "proposed")
        #expect(picked.resolved.technologyId == "aws-rds")
    }

    // MARK: the verb and the files

    @Test func theMergeWritesOneComponentWithEveryFlowIntoTheFiles() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        let merged = mergeApi2IntoApi(model, picking: [.name: "api2"])
        await session.save()

        #expect(merged)
        #expect(model.errorMessage == nil)
        #expect(model.canvas.components.map(\.id) == ["api", "ledger", "cdn"])
        #expect(useCases.project.text(at: archPath) == """
        system "Payments" {
          component "api" {
            technology = "aws-ec2"
            name       = "Payments API"
            data       = "confidential"
          }

          component "ledger" {
            technology = "aws-rds"
            data       = "restricted"
          }

          component "cdn" {
            technology = "aws-waf"
          }

          flow api -> ledger
          flow cdn -> api
        }

        """)
        let controls = try #require(useCases.project.text(at: controlsPath))
        #expect(controls.contains("threat \"credential-theft\" on component \"api\""))
        #expect(controls.contains("reference = \"ci/imdsv2\"") || controls.contains("reference   = \"ci/imdsv2\""))
        #expect(controls.contains("api2") == false)
        #expect(controls.contains("stale") == false)
    }

    @Test func theMergedAnswerScoresOnTheSurvivorBeforeAnySave() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        _ = mergeApi2IntoApi(model)

        let threat = try #require(
            model.threats.first { $0.threatId == "credential-theft" && $0.source.id == "component:api" }
        )
        let control = try #require(
            threat.controls.first { $0.description == "Enforce IMDSv2 to block SSRF-based credential theft" }
        )
        #expect(control.isImplemented)
        #expect(control.evidenceId == "tested")
    }

    @Test func oneUndoPutsBothComponentsEveryFlowAndTheFilesBack() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        await session.save()
        let archBefore = useCases.project.text(at: archPath)
        let controlsBefore = useCases.project.text(at: controlsPath)

        _ = mergeApi2IntoApi(model)
        await session.save()
        #expect(useCases.project.text(at: controlsPath) != controlsBefore)
        #expect(model.undoTitle == "Undo Merge Components")

        model.undo()
        await session.save()

        #expect(model.canvas.components.map(\.id) == ["api", "api2", "ledger", "cdn"])
        #expect(model.canvas.connections.count == 3)
        #expect(useCases.project.text(at: archPath) == archBefore)
        #expect(useCases.project.text(at: controlsPath) == controlsBefore)
    }

    @Test func aRedoMergesAgainAndTheFilesFollow() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        _ = mergeApi2IntoApi(model)
        await session.save()
        let controlsMerged = useCases.project.text(at: controlsPath)
        model.undo()
        await session.save()

        model.redo()
        await session.save()

        #expect(model.canvas.components.map(\.id) == ["api", "ledger", "cdn"])
        #expect(useCases.project.text(at: controlsPath) == controlsMerged)
    }

    // MARK: the sheet

    @Test func theSheetDraws() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let canvas = CanvasState()
        canvas.startMerging(componentIds: ["api", "api2"])

        let drawn = hostedDrawing(
            of: MergeSheet(session: model, canvas: canvas),
            width: 520,
            height: 480
        )

        #expect(drawn != nil)
    }
}
