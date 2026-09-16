import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Writing a threat's recommendations in the window, end to end: the block
/// the use case writes, the card that reads it back, and the report built
/// after the write.
@MainActor
@Suite("Writing a threat's recommendations in the window")
struct RecommendationsFlowTests {
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

    private func write(
        _ text: String,
        replacing: String? = nil,
        note: String? = nil,
        sources: [String] = [],
        in session: ProjectSession
    ) async {
        await session.writeRecommendation(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            replacing: replacing,
            text: text,
            note: note,
            sources: sources
        )
    }

    @Test func aThreatWithNoRecommendationBlockShowsNone() async throws {
        let (session, _) = await aProject()

        let threat = try credentialTheft(in: session)

        #expect(threat.recommendations.isEmpty)
    }

    @Test func writesTheBlockAndTheCardReadsItAfterTheWrite() async throws {
        let (session, useCases) = await aProject()

        await write(
            "Enforce IMDSv2 on every instance",
            note: "The launch template sets it.",
            sources: ["https://example.test/imds"],
            in: session
        )

        #expect(session.errorMessage == nil)
        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("recommendation \"Enforce IMDSv2 on every instance\" {"))
        #expect(written.contains("note    = \"The launch template sets it.\""))
        #expect(written.contains("sources = [\"https://example.test/imds\"]"))

        // The project read the files again, so the card sees the new block.
        let after = try credentialTheft(in: session)
        #expect(after.recommendations.map(\.text) == ["Enforce IMDSv2 on every instance"])
        #expect(after.recommendations.first?.note == "The launch template sets it.")
        #expect(after.recommendations.first?.sources == ["https://example.test/imds"])
    }

    @Test func listsEveryBlockTheFileHolds() async throws {
        let (session, _) = await aProject()

        await write("Enforce IMDSv2 on every instance", in: session)
        await write("Rotate the instance role every 90 days", in: session)

        let after = try credentialTheft(in: session)
        #expect(
            after.recommendations.map(\.text)
                == ["Enforce IMDSv2 on every instance", "Rotate the instance role every 90 days"]
        )
    }

    @Test func editsTheBlockTheTextNames() async throws {
        let (session, _) = await aProject()
        await write("Enforce IMDSv2 on every instance", in: session)

        await write(
            "Enforce IMDSv2 on every hosted instance",
            replacing: "Enforce IMDSv2 on every instance",
            note: "Terraform sets it.",
            in: session
        )

        let after = try credentialTheft(in: session)
        #expect(after.recommendations.map(\.text) == ["Enforce IMDSv2 on every hosted instance"])
        #expect(after.recommendations.first?.note == "Terraform sets it.")
    }

    @Test func removesTheBlockTheTextNames() async throws {
        let (session, _) = await aProject()
        await write("Enforce IMDSv2 on every instance", in: session)
        await write("Rotate the instance role every 90 days", in: session)

        await session.removeRecommendation(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            text: "Enforce IMDSv2 on every instance"
        )

        #expect(session.errorMessage == nil)
        let after = try credentialTheft(in: session)
        #expect(after.recommendations.map(\.text) == ["Rotate the instance role every 90 days"])
    }

    @Test func saysWhyTheSameTextWasNotWrittenTwice() async throws {
        let (session, useCases) = await aProject()
        await write("Enforce IMDSv2 on every instance", in: session)
        let before = useCases.project.text(at: "/work/threatmodel/payments.controls")

        await write("Enforce IMDSv2 on every instance", in: session)

        #expect(
            session.errorMessage
                == "That recommendation was not written: "
                    + "this threat already says \"Enforce IMDSv2 on every instance\"."
        )
        #expect(useCases.project.text(at: "/work/threatmodel/payments.controls") == before)
    }

    @Test func saysWhyABlockWithNoTextWasNotWritten() async throws {
        let (session, useCases) = await aProject()
        let before = useCases.project.text(at: "/work/threatmodel/payments.controls")

        await write("   ", in: session)

        #expect(
            session.errorMessage
                == "That recommendation was not written: a recommendation needs text."
        )
        #expect(useCases.project.text(at: "/work/threatmodel/payments.controls") == before)
    }

    /// The Recommendations section of the report is built from the same
    /// blocks, so a report exported after the write states what a person
    /// wrote in the window.
    @Test func theReportListsTheRecommendationAfterTheWrite() async throws {
        let (session, useCases) = await aProject()

        await write(
            "Enforce IMDSv2 on every instance",
            note: "The launch template sets it.",
            in: session
        )

        let markdown = useCases.exportModelAsMarkdown()
            .execute(ExportModelAsMarkdownRequest())
            .markdown
        #expect(markdown.contains("## Recommendations"))
        #expect(markdown.contains("- Enforce IMDSv2 on every instance"))
        #expect(markdown.contains("  - The launch template sets it."))
    }

    /// The mitigates sheet opens on what the edge holds, so the three fields
    /// the sheet now writes draw with what a person wrote before.
    @Test func theMitigatesSheetDrawsTheEdgeItOpensOn() throws {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 400, y: 0)
        let ids = session.canvas.components.map(\.id)
        let (guardId, storeId) = (try #require(ids.first), try #require(ids.last))
        session.setAssumption(label: "the-budget", text: "The team has none.", owner: nil)
        session.setMitigatesEdge(
            from: guardId,
            to: storeId,
            threatIds: ["credential-theft"],
            reducesRiskBy: 80,
            status: "assumed",
            actionLabel: "adopt-the-guard",
            actionText: "Adopt the guard",
            actionNote: "The platform team owns it.",
            blockedBy: "the-budget",
            sources: ["https://example.test/plan"]
        )

        let protector = try #require(session.canvas.components.first)
        let protected = try #require(session.canvas.components.last)
        guard let drawn = hostedDrawing(
            of: MitigatesSheet(
                session: session,
                protector: protector,
                protected: protected,
                existing: session.canvas.mitigations.first
            ),
            width: 520,
            height: 660
        ) else {
            Issue.record("the mitigates sheet drew nothing at all")
            return
        }
        #expect(drawn.image.pixelsWide > 0)
    }

    @Test func theEditorDrawsTheBlocksTheThreatHolds() async throws {
        let (session, _) = await aProject()
        await write("Enforce IMDSv2 on every instance", in: session)
        let threat = try credentialTheft(in: session)

        guard let drawn = hostedDrawing(
            of: RecommendationsSheet(threat: threat, project: session),
            width: 480,
            height: 420
        ) else {
            Issue.record("the recommendations sheet drew nothing at all")
            return
        }
        #expect(drawn.image.pixelsWide > 0)
    }
}
