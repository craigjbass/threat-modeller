import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Reading and writing the tier at and above which an implemented control
/// must state evidence, in the window, end to end: the picker the
/// assumptions panel draws, the `requires_evidence_above` line the save
/// writes, and what the parser reads back from it.
///
/// Issue #160: the window stated no `requires_evidence_above`, so a system
/// could not set the tier above which an implemented control needs evidence.
@MainActor
@Suite("A system's requires_evidence_above in the window")
struct RequiresEvidenceAboveFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
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

    @Test func aSystemWithNoTierSetReadsEmpty() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        #expect(model.canvas.requiresEvidenceAbove == "")
    }

    @Test func writesTheTierIntoTheFile() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setRequiresEvidenceAbove("high")
        await session.save()

        #expect(model.errorMessage == nil)
        #expect(model.canvas.requiresEvidenceAbove == "high")
        let written = try #require(architecture(useCases))
        #expect(written.contains("requires_evidence_above = \"high\""))
    }

    @Test func writesTheTierAndLeavesEveryOtherBlockWhereItWas() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        await session.save()
        let before = try #require(architecture(useCases))

        model.setRequiresEvidenceAbove("high")
        await session.save()

        let after = try #require(architecture(useCases))
        let lines = after.split(separator: "\n", omittingEmptySubsequences: true)
        let added = lines.filter { $0.contains("requires_evidence_above") }
        #expect(added.count == 1)
        #expect(
            lines.filter { $0.contains("requires_evidence_above") == false }
                == before.split(separator: "\n", omittingEmptySubsequences: true)
        )
    }

    @Test func theParserReadsTheTierBackWithTheSameValue() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setRequiresEvidenceAbove("critical")
        await session.save()

        let text = try #require(architecture(useCases))
        let source = try #require(HclArchitectureSource().read(text).source)
        #expect(source.requiresEvidenceAbove == "critical")
    }

    @Test func saysSoWhenTheApplicationHoldsNoSuchLevel() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        model.setRequiresEvidenceAbove("extreme")

        #expect(model.errorMessage == "This application holds no risk level called \"extreme\".")
    }

    @Test func thePanelDraws() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        let renderer = ImageRenderer(
            content: AssumptionsPanel(session: model).frame(width: 400, height: 600)
        )
        renderer.scale = 1

        #expect(renderer.cgImage != nil)
    }
}
