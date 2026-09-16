import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Writing a likelihood finding in the window, end to end: the block the use
/// case writes, the score that moves with it, and the finding that survives
/// the project closing and reopening.
@MainActor
@Suite("Writing a likelihood finding in the window")
struct LikelihoodFindingFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func aProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func credentialTheft(in session: ProjectSession) throws -> AssessedThreat {
        let model = try #require(session.model)
        return try #require(
            model.threats.first {
                $0.threatId == "credential-theft" && $0.source.id == "component:api"
            }
        )
    }

    @Test func writesTheFindingAndTheThreatRescoresWithIt() async throws {
        let (session, useCases) = await aProject()
        let before = try credentialTheft(in: session)

        await session.writeLikelihoodFinding(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            label: "no campaign has used this against our stack",
            tier: "research",
            prior: nil,
            rationale: "No public reporting names this technique against this platform.",
            sources: ["https://example.com/threat-report"]
        )

        #expect(session.errorMessage == nil)
        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("likelihood \"no campaign has used this against our stack\" {"))
        #expect(written.contains("tier      = \"research\""))

        // The project read the files again, so the card states the finding
        // and the score moved with it.
        let after = try credentialTheft(in: session)
        #expect(after.riskScore < before.riskScore)
        #expect(after.likelihoodId == "research")
        #expect(
            after.likelihoodRationale
                == "No public reporting names this technique against this platform."
        )
        #expect(after.likelihoodSources == ["https://example.com/threat-report"])
    }

    /// A finding a person wrote from the window has to be there after the
    /// project closes and reopens, not only after the write that wrote it.
    @Test func theFindingSurvivesTheProjectClosingAndReopening() async throws {
        let (session, useCases) = await aProject()

        await session.writeLikelihoodFinding(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            label: "no campaign has used this against our stack",
            tier: "research",
            prior: nil,
            rationale: "No public reporting names this technique against this platform.",
            sources: []
        )
        let scoredAfterWriting = try credentialTheft(in: session).riskScore

        // A fresh session over the same files, standing in for the project
        // closing and a person opening it again.
        let reopened = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await reopened.open(root: "/work")

        let reread = try credentialTheft(in: reopened)
        #expect(reread.likelihoodId == "research")
        #expect(
            reread.likelihoodRationale
                == "No public reporting names this technique against this platform."
        )
        #expect(reread.riskScore == scoredAfterWriting)
    }

    @Test func replacesTheFindingWhenAPersonEditsIt() async throws {
        let (session, useCases) = await aProject()
        await session.writeLikelihoodFinding(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            label: "no campaign has used this against our stack",
            tier: "commodity",
            prior: nil,
            rationale: "Nothing found yet.",
            sources: []
        )

        await session.writeLikelihoodFinding(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            label: "a researcher published a proof of concept",
            tier: "research",
            prior: nil,
            rationale: "A conference talk showed the technique with no known exploitation.",
            sources: []
        )

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("likelihood \"a researcher published a proof of concept\" {"))
        #expect(written.contains("likelihood \"no campaign has used this against our stack\" {") == false)
        let after = try credentialTheft(in: session)
        #expect(after.likelihoodId == "research")
    }

    @Test func saysWhyAFindingWithNoRationaleWasNotWritten() async throws {
        let (session, useCases) = await aProject()
        let controlsBefore = useCases.project.text(at: "/work/threatmodel/payments.controls")

        await session.writeLikelihoodFinding(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            label: "no campaign has used this against our stack",
            tier: "research",
            prior: nil,
            rationale: "  ",
            sources: []
        )

        #expect(
            session.errorMessage
                == "That finding was not written: a likelihood finding needs a rationale."
        )
        #expect(useCases.project.text(at: "/work/threatmodel/payments.controls") == controlsBefore)
    }

    @Test func drawsTheSheetThatWritesTheFinding() async throws {
        let (session, _) = await aProject()
        let threat = try credentialTheft(in: session)

        guard let drawn = hostedDrawing(
            of: LikelihoodSheet(
                threat: threat,
                session: session.model ?? LayoutPreview.session(),
                project: session
            ),
            width: 460,
            height: 560
        ) else {
            Issue.record("the likelihood sheet drew nothing at all")
            return
        }
        #expect(drawn.image.pixelsWide > 0)
    }
}
