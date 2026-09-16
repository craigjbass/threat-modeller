import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Writing a severity decision in the window, end to end: the block the use
/// case writes, the score that moves with it, and the removal that puts the
/// catalogue's severity back.
@MainActor
@Suite("Writing a severity decision in the window")
struct SeverityDecisionFlowTests {
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

    @Test func writesTheDecisionAndTheThreatRescoresWithIt() async throws {
        let (session, useCases) = await aProject()
        let before = try credentialTheft(in: session)
        #expect(before.severityLabel == "Critical")

        await session.writeSeverityDecision(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            decision: SeverityDecision(
                severityId: "low",
                rationale: "The credential is scoped to one read-only role.",
                sources: ["https://example.com/RSK-412"]
            )
        )

        #expect(session.errorMessage == nil)
        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("severity_override \"low\" {"))
        #expect(written.contains("rationale = \"The credential is scoped to one read-only role.\""))

        // The project read the files again, so the card states the decision
        // and the score moved with it.
        let after = try credentialTheft(in: session)
        #expect(after.severityLabel == "Low")
        #expect(after.riskScore < before.riskScore)
        #expect(after.severityDecision?.toLabel == "Low")
        #expect(after.severityDecision?.rationale == "The credential is scoped to one read-only role.")
        #expect(after.severityDecision?.sources == ["https://example.com/RSK-412"])
    }

    @Test func replacesTheDecisionWhenAPersonEditsIt() async throws {
        let (session, useCases) = await aProject()
        await session.writeSeverityDecision(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            decision: SeverityDecision(severityId: "low", rationale: "Scoped credential.")
        )

        await session.writeSeverityDecision(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            decision: SeverityDecision(severityId: "medium", rationale: "The role reads two stores.")
        )

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("severity_override \"medium\" {"))
        #expect(written.contains("severity_override \"low\" {") == false)
        let after = try credentialTheft(in: session)
        #expect(after.severityLabel == "Medium")
        #expect(after.severityDecision?.rationale == "The role reads two stores.")
    }

    @Test func removesTheDecisionAndTheCataloguesSeverityStands() async throws {
        let (session, useCases) = await aProject()
        await session.writeSeverityDecision(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            decision: SeverityDecision(severityId: "low", rationale: "Scoped credential.")
        )

        await session.removeSeverityDecision(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api"
        )

        #expect(session.errorMessage == nil)
        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("severity_override") == false)
        let after = try credentialTheft(in: session)
        #expect(after.severityLabel == "Critical")
        #expect(after.severityDecision == nil)
    }

    @Test func saysWhyADecisionWithNoRationaleWasNotWritten() async throws {
        let (session, useCases) = await aProject()
        let controlsBefore = useCases.project.text(at: "/work/threatmodel/payments.controls")

        await session.writeSeverityDecision(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            decision: SeverityDecision(severityId: "low", rationale: "  ")
        )

        #expect(
            session.errorMessage
                == "That decision was not written: a severity decision needs a rationale."
        )
        #expect(useCases.project.text(at: "/work/threatmodel/payments.controls") == controlsBefore)
    }

    @Test func drawsTheSheetThatWritesTheDecision() async throws {
        let (session, _) = await aProject()
        let threat = try credentialTheft(in: session)

        guard let drawn = hostedDrawing(
            of: SeverityDecisionSheet(
                threat: threat,
                severityChoices: session.model?.severityChoices ?? [],
                project: session
            ),
            width: 460,
            height: 500
        ) else {
            Issue.record("the severity decision sheet drew nothing at all")
            return
        }
        #expect(drawn.image.pixelsWide > 0)
    }
}
