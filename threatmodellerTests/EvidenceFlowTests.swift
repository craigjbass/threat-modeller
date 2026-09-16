import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Writing evidence in the window, end to end: the card states the tier, a
/// save writes it into the controls file, a reopen reads it back, and the
/// check failure it answers clears.
@MainActor
@Suite("Writing evidence in the window")
struct EvidenceFlowTests {
    private let payments = """
    system "Payments" {
      requires_evidence_above = "low"

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private let implemented = """
    controls for "Payments" {
      threat "credential-theft" on component "api" {
        control "Enforce IMDSv2 to block SSRF-based credential theft" {
          status = "implemented"
        }
      }
    }

    """

    private let control = "Enforce IMDSv2 to block SSRF-based credential theft"
    private let controlsPath = "/work/threatmodel/payments.controls"

    private func aProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        useCases.project.put(implemented, at: controlsPath)
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func theControl(of session: ProjectSession) throws -> AssessedControl {
        let model = try #require(session.model)
        let threat = try #require(
            model.threats.first {
                $0.threatId == "credential-theft" && $0.source.id == "component:api"
            }
        )
        return try #require(threat.controls.first { $0.description == control })
    }

    private func unevidencedFindings(of session: ProjectSession) -> [String] {
        session.checkedSystems
            .flatMap(\.findings)
            .filter { $0.said.contains("no evidence") }
            .map(\.said)
    }

    @Test func settingEvidenceWritesTheFileAndTheCardStatesIt() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setControlEvidence(
            key: try theControl(of: session).key,
            evidenceId: "tested",
            reference: "ci/imdsv2-test",
            verifiedOn: "2026-09-01"
        )
        #expect(model.errorMessage == nil)

        // The card states it before any save: the model holds the proof.
        let shown = try theControl(of: session)
        #expect(shown.evidenceId == "tested")
        #expect(shown.evidenceReference == "ci/imdsv2-test")
        #expect(shown.verifiedOn == "2026-09-01")

        await session.save()

        let written = try #require(useCases.project.text(at: controlsPath))
        #expect(written.contains("evidence    = \"tested\""))
        #expect(written.contains("reference   = \"ci/imdsv2-test\""))
        #expect(written.contains("verified_on = \"2026-09-01\""))
    }

    @Test func aReopenKeepsTheEvidence() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        model.setControlEvidence(
            key: try theControl(of: session).key,
            evidenceId: "documented",
            reference: "runbook/imdsv2",
            verifiedOn: nil
        )
        await session.save()
        await session.open(root: "/work")

        let reopened = try theControl(of: session)
        #expect(reopened.evidenceId == "documented")
        #expect(reopened.evidenceReference == "runbook/imdsv2")
    }

    @Test func aWrittenTierClearsTheCheckFailure() async throws {
        let (session, _) = await aProject()
        #expect(unevidencedFindings(of: session).isEmpty == false)

        let model = try #require(session.model)
        model.setControlEvidence(
            key: try theControl(of: session).key,
            evidenceId: "tested",
            reference: "ci/imdsv2-test",
            verifiedOn: "2026-09-01"
        )
        await session.save()

        #expect(unevidencedFindings(of: session).isEmpty)
    }

    @Test func compensatingEvidenceWritesTheFileAndShows() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let threat = try #require(
            model.threats.first {
                $0.threatId == "credential-theft" && $0.source.id == "component:api"
            }
        )

        model.setCompensatingControl(
            threatKey: threat.threatKey,
            label: "Watched by the SIEM",
            reducesRiskBy: 50,
            rationale: "The account alerts on use.",
            evidenceId: "configured",
            evidenceReference: "splunk/saved-search/admin-login",
            verifiedOn: "2026-08-30"
        )
        #expect(model.errorMessage == nil)

        let shown = try #require(
            model.threats.first {
                $0.threatId == "credential-theft" && $0.source.id == "component:api"
            }
        )
        #expect(shown.compensatingEvidenceId == "configured")
        #expect(shown.compensatingEvidenceReference == "splunk/saved-search/admin-login")
        #expect(shown.compensatingVerifiedOn == "2026-08-30")

        await session.save()

        let written = try #require(useCases.project.text(at: controlsPath))
        #expect(written.contains("compensating \"Watched by the SIEM\" {"))
        #expect(written.contains("evidence        = \"configured\""))
        #expect(written.contains("verified_on     = \"2026-08-30\""))
    }
}
