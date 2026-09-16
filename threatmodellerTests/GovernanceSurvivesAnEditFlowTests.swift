import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Issue #144. A person removes an entry in the assumptions panel, saves, and
/// opens the project again. Each of the four editors goes through one save,
/// and that save writes the `.governance` file. The system must open again
/// and every owner a person wrote must still be there.
@MainActor
@Suite("Governance survives an edit in the window")
struct GovernanceSurvivesAnEditFlowTests {
    private let architecture = """
    system "Payments" {
      asset "card-data" {
        name           = "Card data"
        classification = "restricted"
      }

      use_case "checkout" {
        text = "A customer pays for a basket."
      }

      third_party "stripe" {
        name   = "Stripe"
        kind   = "saas"
        uptime = "none"
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "db" {
        technology = "aws-rds"
        data       = "confidential"
      }

      user "alice" {
        name    = "Alice"
        role    = "Operator"
        access  = "admin"
        reaches = ["api"]
      }

      flow api -> db
    }

    """

    /// A project with one accepted control on the flow's threat and an owner
    /// written into the governance file, opened in the window.
    private func aGovernedProject() async throws -> (ProjectSession, TestDependencies, String) {
        let useCases = TestDependencies()
        useCases.project.put(architecture, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")

        let assessed = useCases.assessThreatModel().execute(AssessThreatModelRequest())
        let threat = try #require(
            assessed.threats.first {
                $0.threatId == "connection-mitm" && $0.source.id == "connection:api->db"
            }
        )
        let control = try #require(threat.controls.first)
        _ = useCases.setControlStatus().execute(
            SetControlStatusRequest(controlKey: control.key, statusId: "accepted")
        )
        await session.save()

        _ = useCases.writeRiskAcceptance().execute(
            WriteRiskAcceptanceRequest(
                root: "/work",
                systemName: "payments",
                threatId: "connection-mitm",
                sourceKind: "flow",
                sourceId: "api->db",
                accepted: SourceAcceptedRisk(
                    control: control.description,
                    owner: "Head of Platform",
                    acceptedOn: "2026-01-05",
                    reviewBy: "2026-07-05"
                )
            )
        )
        return (session, useCases, control.description)
    }

    /// Saves, opens the project again, and states the system opened and the
    /// owner is still in the file.
    private func saveAndOpenAgain(
        _ session: ProjectSession,
        _ useCases: TestDependencies,
        control: String
    ) async throws {
        await session.save()

        // Opening the root again reads every file from disk, the way the
        // window reads them when a person opens the project the next day.
        await session.open(root: "/work")

        #expect(session.errorMessage == nil)
        #expect(session.diagnostics.map(\.message) == [])
        #expect(session.model != nil)

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.governance"))
        let read = HclGovernanceSource().read(written)
        #expect(read.diagnostics.map(\.message) == [], "the save wrote:\n\(written)")
        let source = try #require(read.source)
        let threat = try #require(
            source.threat(for: ThreatKey("connection-mitm@connection:api->db"))
        )
        let accepted = try #require(threat.accepted.first { $0.control == control })
        #expect(accepted.owner == "Head of Platform")
        #expect(accepted.reviewBy == "2026-07-05")
    }

    @Test func removingAThirdPartyKeepsTheProjectOpenable() async throws {
        let (session, useCases, control) = try await aGovernedProject()
        let model = try #require(session.model)

        model.removeThirdParty(id: "stripe")
        #expect(model.errorMessage == nil)

        try await saveAndOpenAgain(session, useCases, control: control)
    }

    @Test func removingAnAssetKeepsTheProjectOpenable() async throws {
        let (session, useCases, control) = try await aGovernedProject()
        let model = try #require(session.model)

        model.removeSystemAsset(id: "card-data")
        #expect(model.errorMessage == nil)

        try await saveAndOpenAgain(session, useCases, control: control)
    }

    @Test func removingAUseCaseKeepsTheProjectOpenable() async throws {
        let (session, useCases, control) = try await aGovernedProject()
        let model = try #require(session.model)

        model.removeSystemUseCase(label: "checkout")
        #expect(model.errorMessage == nil)

        try await saveAndOpenAgain(session, useCases, control: control)
    }

    /// The way back for a person holding a file written before the fix: the
    /// window names the file, prints the parser's message with the line, and
    /// `threatmodeller format` rewrites the file.
    @Test func theWindowShowsTheParsersMessageWithTheLine() async throws {
        let useCases = TestDependencies()
        useCases.project.put(architecture, at: "/work/threatmodel/payments.arch")
        useCases.project.put("""
        governance for "Payments" {
          threat "connection-mitm" on flow "api->db" {
            accepted "Enforce TLS" {
            }
          }

          stale threat "connection-mitm" on flow "api->db" {
            stale accepted "Enforce TLS" {
              owner = "Head of Platform"
            }
          }
        }

        """, at: "/work/threatmodel/payments.governance")

        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")

        #expect(session.model == nil)
        #expect(session.errorMessage == "payments.governance did not parse.")
        #expect(
            session.diagnostics.map(\.message)
                == ["connection-mitm@connection:api->db is governed twice"]
        )

        let sheet = DiagnosticsSheet(
            fileName: "payments.governance",
            diagnostics: session.diagnostics,
            dismiss: {}
        )
        #expect(
            sheet.lines
                == ["payments.governance:1:1: connection-mitm@connection:api->db is governed twice"]
        )
    }

    @Test func removingAUserKeepsTheProjectOpenable() async throws {
        let (session, useCases, control) = try await aGovernedProject()
        let model = try #require(session.model)

        model.removeComponents(["alice"])
        #expect(model.errorMessage == nil)

        try await saveAndOpenAgain(session, useCases, control: control)
    }
}
