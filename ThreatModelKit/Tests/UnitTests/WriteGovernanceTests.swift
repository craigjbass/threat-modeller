import ArchitectureDSL
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// Writing one governance stanza from the window.
///
/// Each use case reads the file, changes one stanza and writes every other
/// stanza back unchanged, so a person deciding one entry decides nothing about
/// the rest.
@Suite("Writing a governance entry from the window")
struct WriteGovernanceTests {
    private let app = TestDependencies()

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private let governed = """
    governance for "Payments" {
      threat "credential-theft" on component "api" {
        accepted "Enforce IMDSv2 to block SSRF-based credential theft" {
          owner = "Head of Platform"
        }

        work "Protect the plist" {
          owner = "Platform team"
        }
      }

      action "reenable-devtool-rules" {
        owner = "Endpoint team"
      }
    }

    """

    private func aProject(holdingGovernance: Bool = false) {
        app.project.put(payments, at: "/work/threatmodel/payments.arch")
        if holdingGovernance {
            app.project.put(governed, at: "/work/threatmodel/payments.governance")
        }
    }

    private func write(
        _ accepted: SourceAcceptedRisk,
        threatId: String = "credential-theft",
        sourceKind: String = "component",
        sourceId: String = "api"
    ) -> WriteRiskAcceptanceResponse {
        app.writeRiskAcceptance().execute(
            WriteRiskAcceptanceRequest(
                root: "/work",
                systemName: "payments",
                systemDisplayName: "Payments",
                threatId: threatId,
                sourceKind: sourceKind,
                sourceId: sourceId,
                accepted: accepted
            )
        )
    }

    private func write(
        _ work: SourcePlannedWork,
        at place: PlannedWorkPlace
    ) -> WritePlannedWorkResponse {
        app.writePlannedWork().execute(
            WritePlannedWorkRequest(
                root: "/work",
                systemName: "payments",
                systemDisplayName: "Payments",
                place: place,
                work: work
            )
        )
    }

    private func listed() -> GovernanceSource? {
        guard case .listed(let source, _) = app.listGovernance().execute(
            ListGovernanceRequest(root: "/work", systemName: "payments")
        ) else { return nil }
        return source
    }

    // MARK: reading what the file states

    @Test func listsNothingForASystemWithNoFile() throws {
        aProject()

        let source = try #require(listed())
        #expect(source.systemName == "payments")
        #expect(source.threats.isEmpty)
        #expect(source.actions.isEmpty)
    }

    @Test func listsTheStanzasTheFileStates() throws {
        aProject(holdingGovernance: true)

        let source = try #require(listed())
        #expect(source.threats.count == 1)
        #expect(source.threats.first?.accepted.first?.owner == "Head of Platform")
        #expect(source.threats.first?.work.map(\.label) == ["Protect the plist"])
        #expect(source.actions.map(\.label) == ["reenable-devtool-rules"])
    }

    @Test func listsNoSystemTheProjectDoesNotHold() {
        aProject()

        let response = app.listGovernance().execute(
            ListGovernanceRequest(root: "/work", systemName: "gone")
        )
        #expect(response == .noSuchSystem)
    }

    // MARK: writing an accepted risk

    @Test func writesTheFirstAcceptanceIntoANewFile() throws {
        aProject()

        let response = write(
            SourceAcceptedRisk(
                control: "Enforce IMDSv2 to block SSRF-based credential theft",
                owner: "Head of Platform",
                acceptedOn: "2026-09-01",
                reviewBy: "2027-03-01",
                rationale: "The MFA rollout waits on the SSO migration.",
                sources: ["https://example.com/RSK-412"]
            )
        )

        #expect(response == .written(path: "/work/threatmodel/payments.governance"))
        let written = try #require(app.project.text(at: "/work/threatmodel/payments.governance"))
        #expect(written.contains("governance for \"Payments\" {"))
        #expect(written.contains("threat \"credential-theft\" on component \"api\" {"))
        #expect(written.contains("owner       = \"Head of Platform\""))
        #expect(written.contains("review_by   = \"2027-03-01\""))
        #expect(written.contains("sources     = [\"https://example.com/RSK-412\"]"))
    }

    @Test func replacesTheStanzaForTheSameControlAndKeepsTheRest() throws {
        aProject(holdingGovernance: true)

        let response = write(
            SourceAcceptedRisk(
                control: "Enforce IMDSv2 to block SSRF-based credential theft",
                owner: "Head of Security",
                reviewBy: "2027-03-01"
            )
        )

        #expect(response == .written(path: "/work/threatmodel/payments.governance"))
        let source = try #require(listed())
        #expect(source.threats.count == 1)
        #expect(source.threats.first?.accepted.count == 1)
        #expect(source.threats.first?.accepted.first?.owner == "Head of Security")
        // The other stanzas are not this decision, so they do not move.
        #expect(source.threats.first?.work.first?.owner == "Platform team")
        #expect(source.actions.first?.owner == "Endpoint team")
    }

    @Test func refusesADateThatIsNotADate() {
        aProject()

        let response = write(
            SourceAcceptedRisk(control: "Enforce MFA", owner: "Someone", reviewBy: "2027-13-01")
        )

        #expect(response == .refused(
            reason: "review_by is \"2027-13-01\", which is not a date"
        ))
        #expect(app.project.text(at: "/work/threatmodel/payments.governance") == nil)
    }

    @Test func refusesAnAcceptanceThatNamesNoControl() {
        aProject()

        let response = write(SourceAcceptedRisk(control: "  ", owner: "Someone"))

        #expect(response == .refused(reason: "an accepted risk names its control"))
    }

    @Test func writesNoSystemTheProjectDoesNotHold() {
        aProject()

        let response = app.writeRiskAcceptance().execute(
            WriteRiskAcceptanceRequest(
                root: "/work",
                systemName: "gone",
                systemDisplayName: nil,
                threatId: "credential-theft",
                sourceKind: "component",
                sourceId: "api",
                accepted: SourceAcceptedRisk(control: "Enforce MFA")
            )
        )

        #expect(response == .noSuchSystem)
    }

    // MARK: writing planned work

    @Test func addsAWorkStanzaTheFileDoesNotHold() throws {
        aProject(holdingGovernance: true)

        let response = write(
            SourcePlannedWork(
                label: "Rotate the keys",
                owner: "Platform team",
                effort: "small",
                dueBy: "2026-11-30",
                status: "in_progress",
                acceptance: "The audit log shows a rotation."
            ),
            at: .threat(threatId: "credential-theft", sourceKind: "component", sourceId: "api")
        )

        #expect(response == .written(path: "/work/threatmodel/payments.governance"))
        let source = try #require(listed())
        #expect(
            source.threats.first?.work.map(\.label)
                == ["Protect the plist", "Rotate the keys"]
        )
        #expect(source.threats.first?.work.last?.status == "in_progress")
    }

    @Test func changesAnActionStanza() throws {
        aProject(holdingGovernance: true)

        let response = write(
            SourcePlannedWork(label: "reenable-devtool-rules", owner: "Platform team", status: "done"),
            at: .action
        )

        #expect(response == .written(path: "/work/threatmodel/payments.governance"))
        let source = try #require(listed())
        #expect(source.actions.map(\.label) == ["reenable-devtool-rules"])
        #expect(source.actions.first?.owner == "Platform team")
        #expect(source.actions.first?.status == "done")
    }

    @Test func refusesAnEffortOutsideTheThree() {
        aProject()

        let response = write(
            SourcePlannedWork(label: "Rotate the keys", effort: "huge"),
            at: .action
        )

        #expect(response == .refused(
            reason: "effort is \"huge\"; this application holds \"small\", \"medium\", \"large\""
        ))
    }

    @Test func refusesAStatusOutsideTheFour() {
        aProject()

        let response = write(
            SourcePlannedWork(label: "Rotate the keys", status: "someday"),
            at: .action
        )

        #expect(response == .refused(
            reason: "status is \"someday\"; this application holds "
                + "\"planned\", \"in_progress\", \"done\", \"dropped\""
        ))
    }

    // MARK: one writer states the canonical shape

    @Test func aWrittenFileReadsBackAndWritesTheSameBytes() throws {
        aProject()

        _ = write(
            SourceAcceptedRisk(
                control: "Enforce IMDSv2 to block SSRF-based credential theft",
                owner: "Head of Platform",
                acceptedOn: "2026-09-01",
                reviewBy: "2027-03-01"
            )
        )
        _ = write(
            SourcePlannedWork(label: "reenable-devtool-rules", owner: "Endpoint team"),
            at: .action
        )

        let written = try #require(app.project.text(at: "/work/threatmodel/payments.governance"))
        let gateway = HclGovernanceSource()
        let read = gateway.read(written)
        #expect(read.hasErrors == false)
        #expect(gateway.write(try #require(read.source)) == written)
    }
}
