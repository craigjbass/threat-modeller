import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// Issue #144. A person removes a third party in the assumptions panel and
/// saves. The save writes the `.governance` file, and the file the window
/// wrote next opens must be a file the parser reads.
///
/// Before the fix the save wrote two blocks with one key, and the parser
/// refused the whole file with
/// `connection-mitm@flow:api->db is governed twice`, so the project stopped
/// opening. The cause was the key: `SourceGovernedThreat` keyed a block on
/// the file's word `flow`, and every other reader keys a threat on the
/// resolver's word `connection`, which section 5.10 of the language guide
/// names as the one key.
@Suite("A save writes a governance file the parser reads")
struct GovernanceDuplicateBlockTests {
    private let app = TestDependencies()

    private let architecture = """
    system "S" {
      third_party "stripe" {
        name   = "Stripe"
        kind   = "saas"
        uptime = "hard"
      }

      component "api" { technology = "aws-ec2" data = "confidential" }

      component "db" { technology = "aws-rds" data = "confidential" }

      flow api -> db
    }

    """

    /// Opens the system, accepts the first control the flow's threat offers,
    /// and saves. The answer is the one a person gives on screen.
    private func aGovernedFlowThreat() throws -> String {
        app.project.put(architecture, at: "/project/threatmodel/s.arch")
        _ = app.openSystem().execute(OpenSystemRequest(root: "/project", systemName: "s"))

        let assessed = app.assessThreatModel().execute(AssessThreatModelRequest())
        let threat = try #require(
            assessed.threats.first {
                $0.threatId == "connection-mitm" && $0.source.id == "connection:api->db"
            }
        )
        let control = try #require(threat.controls.first)
        _ = app.setControlStatus().execute(
            SetControlStatusRequest(controlKey: control.key, statusId: "accepted")
        )
        _ = app.saveSystemAnswers().execute(
            SaveSystemAnswersRequest(root: "/project", systemName: "s")
        )

        // The owner and the dates a person writes into the governance file.
        _ = app.writeRiskAcceptance().execute(
            WriteRiskAcceptanceRequest(
                root: "/project",
                systemName: "s",
                threatId: "connection-mitm",
                sourceKind: "flow",
                sourceId: "api->db",
                accepted: SourceAcceptedRisk(
                    control: control.description,
                    owner: "Head of Platform",
                    acceptedOn: "2026-01-05",
                    reviewBy: "2026-07-05",
                    rationale: "the link runs inside one account"
                )
            )
        )
        return control.description
    }

    @Test func removingAThirdPartyWritesAGovernanceFileTheParserReads() throws {
        let control = try aGovernedFlowThreat()

        #expect(
            app.removeThirdParty().execute(RemoveThirdPartyRequest(id: "stripe")) == .removed
        )
        _ = app.saveSystemAnswers().execute(
            SaveSystemAnswersRequest(root: "/project", systemName: "s")
        )

        let written = try #require(app.project.text(at: "/project/threatmodel/s.governance"))
        let read = HclGovernanceSource().read(written)

        #expect(
            read.diagnostics.map(\.message) == [],
            "the governance file the save wrote: \n\(written)"
        )
        let source = try #require(read.source)
        let threat = try #require(
            source.threat(for: ThreatKey("connection-mitm@connection:api->db"))
        )
        let accepted = try #require(threat.accepted.first { $0.control == control })
        #expect(accepted.owner == "Head of Platform")
        #expect(accepted.reviewBy == "2026-07-05")
        #expect(accepted.isStale == false)
        #expect(threat.isStale == false)
    }

    /// The system opens again after the save, which is what the user lost.
    @Test func theSystemOpensAgainAfterTheSave() throws {
        _ = try aGovernedFlowThreat()
        _ = app.removeThirdParty().execute(RemoveThirdPartyRequest(id: "stripe"))
        _ = app.saveSystemAnswers().execute(
            SaveSystemAnswersRequest(root: "/project", systemName: "s")
        )

        let opened = app.openSystem().execute(
            OpenSystemRequest(root: "/project", systemName: "s")
        )
        guard case .opened = opened else {
            Issue.record("the system did not open: \(opened)")
            return
        }
    }
}
