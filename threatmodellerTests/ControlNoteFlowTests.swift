import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Writing a control's note in the window, end to end: the evidence sheet
/// states the note, a save writes it into the controls file beside the
/// evidence, and a reopen reads it back.
@MainActor
@Suite("Writing a control's note in the window")
struct ControlNoteFlowTests {
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

    @Test func settingANoteWritesTheFileAndTheCardStatesIt() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setControlNote(key: try theControl(of: session).key, note: "Okta, enforced group-wide")
        #expect(model.errorMessage == nil)

        // The card states it before any save: the model holds the note.
        let shown = try theControl(of: session)
        #expect(shown.note == "Okta, enforced group-wide")

        await session.save()

        let written = try #require(useCases.project.text(at: controlsPath))
        #expect(written.contains("note   = \"Okta, enforced group-wide\""))
    }

    @Test func aReopenKeepsTheNote() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        model.setControlNote(key: try theControl(of: session).key, note: "Okta, enforced group-wide")
        await session.save()
        await session.open(root: "/work")

        let reopened = try theControl(of: session)
        #expect(reopened.note == "Okta, enforced group-wide")
    }

    @Test func anUnrelatedEditKeepsTheEvidenceAndTheNoteTogether() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setControlNote(key: try theControl(of: session).key, note: "Okta, enforced group-wide")
        model.setControlEvidence(
            key: try theControl(of: session).key,
            evidenceId: "tested",
            reference: "ci/imdsv2-test",
            verifiedOn: "2026-09-01"
        )
        await session.save()

        let written = try #require(useCases.project.text(at: controlsPath))
        #expect(written.contains("note        = \"Okta, enforced group-wide\""))
        #expect(written.contains("evidence    = \"tested\""))
    }

    @Test func clearingTheNoteRemovesIt() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setControlNote(key: try theControl(of: session).key, note: "Okta, enforced group-wide")
        await session.save()

        model.setControlNote(key: try theControl(of: session).key, note: "")
        await session.save()

        let written = try #require(useCases.project.text(at: controlsPath))
        #expect(written.contains("note") == false)
    }
}
