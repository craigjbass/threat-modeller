import Foundation
import Testing
import TestSupport
import ThreatModelKit
@testable import threatmodeller

/// What the History sheet reads from the project's git commits.
@MainActor
struct HistorySessionTests {
    private let architecture = """
    system "Payments" {
      catalogue = "v0.0.0"

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }
    """

    private func aSession(root: String = "/work") -> (HistorySession, TestDependencies) {
        let useCases = TestDependencies()
        return (HistorySession(useCases: useCases, root: root), useCases)
    }

    @Test func aNewSessionHoldsNoRowAndReadsNothingUntilReadIsCalled() {
        let (session, _) = aSession()

        #expect(session.rows.isEmpty)
        #expect(session.message == nil)
        #expect(session.isReading == false)
    }

    @Test func readOverAProjectWithCommitsFillsFoundAndRows() async {
        let (session, useCases) = aSession()
        useCases.project.put(architecture, at: "/work/threatmodel/payments.arch")
        useCases.history.add(
            hash: "aaaaaaa1111",
            date: Date(timeIntervalSince1970: 1_000_000),
            files: ["threatmodel/payments.arch": architecture]
        )
        useCases.history.add(
            hash: "bbbbbbb2222",
            date: Date(timeIntervalSince1970: 2_000_000),
            files: ["threatmodel/payments.arch": architecture]
        )

        await session.read()

        #expect(session.rows.map(\.commit.hash) == ["bbbbbbb2222", "aaaaaaa1111"])
        #expect(session.truncated == false)
        #expect(session.message == nil)
    }

    @Test func readOverCommitsThatTouchedNoThreatModelFileSaysSoInMessage() async {
        let (session, useCases) = aSession()
        useCases.project.put(architecture, at: "/work/threatmodel/payments.arch")

        await session.read()

        #expect(session.rows.isEmpty)
        #expect(session.message == "No commit in this project touched a threat model file.")
    }

    @Test func readOverARootThatIsNotARepositoryClearsFoundAndWritesTheReason() async {
        let (session, _) = aSession(root: "/elsewhere")

        await session.read()

        #expect(session.rows.isEmpty)
        #expect(session.message == "/elsewhere is not a git repository, so it holds no history")
    }

    @Test func readOverAProjectWithNoSuchSystemClearsFoundAndWritesTheReason() async {
        let (session, useCases) = aSession()
        useCases.project.put("not a threat model", at: "/work/threatmodel/readme.txt")

        await session.read()

        #expect(session.rows.isEmpty)
        #expect(session.message == "This project holds no such system.")
    }

    @Test func readOverAProjectThatCannotBeDiscoveredClearsFoundAndWritesTheReason() async {
        let (session, _) = aSession()

        await session.read()

        #expect(session.rows.isEmpty)
        #expect(session.message?.hasPrefix("The history could not be read:") == true)
    }

    @Test func oldestFirstAnswersTheRowsInReverse() async {
        let (session, useCases) = aSession()
        useCases.project.put(architecture, at: "/work/threatmodel/payments.arch")
        useCases.history.add(
            hash: "aaaaaaa1111",
            date: Date(timeIntervalSince1970: 1_000_000),
            files: ["threatmodel/payments.arch": architecture]
        )
        useCases.history.add(
            hash: "bbbbbbb2222",
            date: Date(timeIntervalSince1970: 2_000_000),
            files: ["threatmodel/payments.arch": architecture]
        )

        await session.read()

        #expect(session.oldestFirst.map(\.commit.hash) == session.rows.reversed().map(\.commit.hash))
        #expect(session.oldestFirst.first?.commit.hash == "aaaaaaa1111")
    }

    @Test func highestTotalAnswersOneWhenNoRowCarriesAScore() {
        let (session, _) = aSession()

        #expect(session.highestTotal == 1)
    }
}
