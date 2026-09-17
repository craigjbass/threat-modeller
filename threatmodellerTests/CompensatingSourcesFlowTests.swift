import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Saving a compensating control in the window keeps the `sources` the file
/// states, the way it keeps the rationale and the evidence.
///
/// Issue #168: the sheet held no sources field, so `SetCompensatingControl`
/// built the record with none, and a save erased what the file stated.
@MainActor
@Suite("Saving a compensating control keeps its sources")
struct CompensatingSourcesFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private let withSources = """
    controls for "Payments" {
      threat "credential-theft" on component "api" {
        compensating "Watched by the SIEM" {
          reduces_risk_by = 50
          rationale       = "The account alerts on use."
          sources         = ["https://example.com/break-glass-runbook"]
        }
      }
    }

    """

    private let controlsPath = "/work/threatmodel/payments.controls"

    private func aProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        useCases.project.put(withSources, at: controlsPath)
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func theThreat(of session: ProjectSession) throws -> AssessedThreat {
        let model = try #require(session.model)
        return try #require(
            model.threats.first {
                $0.threatId == "credential-theft" && $0.source.id == "component:api"
            }
        )
    }

    @Test func theCardStatesTheSourcesTheFileHolds() async throws {
        let (session, _) = await aProject()

        let threat = try theThreat(of: session)
        #expect(threat.compensatingSources == ["https://example.com/break-glass-runbook"])
    }

    @Test func anUnrelatedEditKeepsTheSources() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let threat = try theThreat(of: session)

        // The sheet sends the whole record on every save, the sources on
        // screen coming from the file the same way the rationale does.
        model.setCompensatingControl(
            threatKey: threat.threatKey,
            label: "Watched by the SIEM",
            reducesRiskBy: 60,
            rationale: "The account alerts on use.",
            sources: threat.compensatingSources
        )
        await session.save()

        let written = try #require(useCases.project.text(at: controlsPath))
        #expect(written.contains("sources         = [\"https://example.com/break-glass-runbook\"]"))
    }

    @Test func aReopenKeepsTheSources() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let threat = try theThreat(of: session)

        model.setCompensatingControl(
            threatKey: threat.threatKey,
            label: "Watched by the SIEM",
            reducesRiskBy: 60,
            rationale: "The account alerts on use.",
            sources: threat.compensatingSources
        )
        await session.save()
        await session.open(root: "/work")

        let reopened = try theThreat(of: session)
        #expect(reopened.compensatingSources == ["https://example.com/break-glass-runbook"])
    }
}
