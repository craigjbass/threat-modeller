import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The mitigates sheet's "Held up by" picker, end to end: what the picker
/// offers, what it opens on, and what a save writes when the model no
/// longer declares the edge's blocker.
@MainActor
@Suite("The mitigates sheet's blocker picker")
struct MitigatesSheetBlockerTests {
    private let twoComponents = """
    system "Payments" {
      component "guard" {
        technology = "aws-ec2"
        data       = "confidential"
      }
      component "store" {
        technology = "aws-rds"
        data       = "confidential"
      }
    }

    """

    private func aProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(twoComponents, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    @Test func thePickerOffersOnlyNothingAndTheDeclaredAssumptions() {
        let choices = MitigatesSheet.blockedByChoices(declaring: [
            ViewedAssumption(label: "the-budget", text: "The team has none.", owner: nil),
            ViewedAssumption(label: "the-network", text: "It is trusted.", owner: nil)
        ])

        #expect(choices.map(\.word) == ["nothing", "the-budget", "the-network"])
    }

    @Test func aBlockerTheModelStillDeclaresOpensOnThatAssumption() {
        let opening = MitigatesSheet.openingBlockedBy(
            actionBlockedBy: "the-budget",
            declaring: [ViewedAssumption(label: "the-budget", text: "The team has none.", owner: nil)]
        )

        #expect(opening == .declared("the-budget"))
    }

    @Test func aBlockerTheModelNoLongerDeclaresOpensOnNothing() {
        let opening = MitigatesSheet.openingBlockedBy(
            actionBlockedBy: "the-old-assumption",
            declaring: [ViewedAssumption(label: "the-budget", text: "The team has none.", owner: nil)]
        )

        #expect(opening == .nothing)
    }

    @Test func removingTheAssumptionUnblocksTheActionAndThePanelSaysSo() async throws {
        let (project, useCases) = await aProject()
        let model = try #require(project.model)

        model.setAssumption(label: "the-old-assumption", text: "The team has none.", owner: nil)
        model.setMitigatesEdge(
            from: "guard",
            to: "store",
            threatIds: ["credential-theft"],
            status: "proposed",
            actionLabel: "adopt-the-guard",
            actionText: "Adopt the guard",
            actionNote: "The platform team owns it.",
            blockedBy: "the-old-assumption",
            sources: ["https://example.test/plan"]
        )

        model.removeAssumption(label: "the-old-assumption")
        await project.save()

        #expect(model.errorMessage == nil)
        #expect(
            model.unblockedActionsNote
                == "One recommendation no longer waits on that assumption."
        )
        let edge = try #require(model.canvas.mitigations.first)
        #expect(edge.actionLabel == "adopt-the-guard")
        #expect(edge.actionBlockedBy == nil)
        let arch = try #require(useCases.project.text(at: "/work/threatmodel/payments.arch"))
        #expect(arch.contains("blocked_by") == false)
        #expect(arch.contains("recommendation \"adopt-the-guard\" {"))

        let renderer = ImageRenderer(
            content: AssumptionsPanel(session: model).frame(width: 400, height: 600)
        )
        renderer.scale = 1
        #expect(renderer.cgImage != nil)
    }

    /// The scenario the sheet guards against: an edge's action names an
    /// assumption a person later removes. A save that uses the picker's
    /// opening choice keeps the action and drops only the blocker, and a
    /// later parse of the file never meets a `blocked_by` naming an
    /// assumption the file does not declare.
    @Test func writingAnEdgeWhoseBlockerIsGoneKeepsTheActionAndDropsTheBlocker() async throws {
        let (project, useCases) = await aProject()
        let model = try #require(project.model)

        model.setAssumption(label: "the-old-assumption", text: "The team has none.", owner: nil)
        model.setMitigatesEdge(
            from: "guard",
            to: "store",
            threatIds: ["credential-theft"],
            status: "proposed",
            actionLabel: "adopt-the-guard",
            actionText: "Adopt the guard",
            actionNote: "The platform team owns it.",
            blockedBy: "the-old-assumption",
            sources: ["https://example.test/plan"]
        )
        model.removeAssumption(label: "the-old-assumption")
        let edge = try #require(model.canvas.mitigations.first)

        let opening = MitigatesSheet.openingBlockedBy(
            actionBlockedBy: edge.actionBlockedBy,
            declaring: model.canvas.assumptions
        )
        model.setMitigatesEdge(
            from: "guard",
            to: "store",
            threatIds: edge.threatIds,
            status: edge.status,
            actionLabel: edge.actionLabel,
            actionText: edge.actionText,
            actionNote: edge.actionNote,
            blockedBy: opening.tag.isEmpty ? nil : opening.tag,
            sources: edge.actionSources
        )
        await project.save()

        #expect(model.errorMessage == nil)
        #expect(opening == .nothing)
        let arch = try #require(useCases.project.text(at: "/work/threatmodel/payments.arch"))
        #expect(arch.contains("blocked_by") == false)
        #expect(arch.contains("recommendation \"adopt-the-guard\" {"))
        #expect(arch.contains("\"Adopt the guard\""))
    }
}
