import ArchitectureDSL
import Foundation
import Testing
import ThreatModelKit
import TestSupport

@Suite("Scoring the model at each sampled commit")
struct ReadRiskHistoryTests {
    private let project = InMemoryProject(root: "/work")
    private let git = FakeGitHistory(root: "/work")

    private let oneComponent = """
    system "Payments" {
      catalogue = "v0.0.0"

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }
    """

    private let twoComponents = """
    system "Payments" {
      catalogue = "v0.0.0"

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "db" {
        technology = "aws-rds"
        data       = "restricted"
      }
    }
    """

    private func read(commits: Int = ReadRiskHistory.defaultCommits) -> ReadRiskHistoryResponse {
        ReadRiskHistory(
            projects: project,
            history: git,
            catalogue: CatalogueFixture.catalogue(),
            architectureSources: HclArchitectureSource(),
            controlsSources: HclControlsSource(),
            attackTreeSources: HclAttackTreeSource(),
            governanceSources: HclGovernanceSource(),
            layout: LayOutModel()
        ).execute(ReadRiskHistoryRequest(root: "/work", commits: commits))
    }

    private func rows(_ response: ReadRiskHistoryResponse) -> [RiskHistoryRow] {
        guard case .read(let history) = response else {
            Issue.record("expected the history to be read, got \(response)")
            return []
        }
        return history.rows
    }

    private func seed() {
        project.put(oneComponent, at: "/work/threatmodel/payments.arch")
        git.add(
            hash: "aaaaaaa1111",
            date: Date(timeIntervalSince1970: 1_000_000),
            files: ["threatmodel/payments.arch": oneComponent]
        )
        git.add(
            hash: "bbbbbbb2222",
            date: Date(timeIntervalSince1970: 2_000_000),
            files: ["threatmodel/payments.arch": twoComponents]
        )
    }

    @Test func scoresEverySampledCommitNewestFirst() throws {
        seed()

        let read = rows(read())

        #expect(read.count == 2)
        #expect(read.map(\.commit.shortHash) == ["bbbbbbb", "aaaaaaa"])
        let newest = try #require(read.first?.numbers)
        let oldest = try #require(read.last?.numbers)
        // The newer commit holds one component more, so it raises more.
        #expect(newest.totalScore > oldest.totalScore)
        #expect(newest.threatCount > oldest.threatCount)
        #expect(newest.worstScore >= oldest.worstScore)
        #expect(newest.catalogueTag == "v0.0.0")
    }

    @Test func readsTheSameRowsTwice() {
        seed()

        #expect(rows(read()) == rows(read()))
    }

    @Test func keepsTheRowOfACommitThatDidNotParse() throws {
        project.put(oneComponent, at: "/work/threatmodel/payments.arch")
        git.add(
            hash: "aaaaaaa1111",
            date: Date(timeIntervalSince1970: 1_000_000),
            files: ["threatmodel/payments.arch": "system \"Payments\" {"]
        )
        git.add(
            hash: "bbbbbbb2222",
            date: Date(timeIntervalSince1970: 2_000_000),
            files: ["threatmodel/payments.arch": oneComponent]
        )

        let read = rows(read())

        #expect(read.count == 2)
        #expect(read.first?.didParse == true)
        // A zero would read as "no risk", which is the opposite of what a file
        // that does not parse means.
        #expect(read.last?.didParse == false)
        #expect(read.last?.numbers == nil)
    }

    @Test func statesWhenTheBoundLeftCommitsOut() throws {
        seed()

        guard case .read(let bounded) = read(commits: 1) else {
            Issue.record("expected the history to be read")
            return
        }
        #expect(bounded.rows.count == 1)
        #expect(bounded.truncated)

        guard case .read(let everything) = read(commits: 10) else {
            Issue.record("expected the history to be read")
            return
        }
        #expect(everything.truncated == false)
    }

    @Test func countsTheAcceptedRisksAndTheOpenTrees() throws {
        project.put(oneComponent, at: "/work/threatmodel/payments.arch")
        git.add(
            hash: "aaaaaaa1111",
            date: Date(timeIntervalSince1970: 1_000_000),
            files: [
                "threatmodel/payments.arch": oneComponent,
                "threatmodel/payments.controls": """
                controls for "Payments" {
                  threat "credential-theft" on component "api" {
                    control "Enforce IMDSv2 to block SSRF-based credential theft" {
                      status = "accepted"
                    }
                  }
                }
                """
            ]
        )

        let numbers = try #require(rows(read()).first?.numbers)
        #expect(numbers.acceptedRisks == 1)
        #expect(numbers.openAttackTrees == 0)
    }

    @Test func saysSoForADirectoryThatIsNoRepository() {
        project.put(oneComponent, at: "/work/threatmodel/payments.arch")
        git.forget("/work")

        guard case .notARepository(let reason) = read() else {
            Issue.record("expected the directory to hold no history")
            return
        }
        #expect(reason.contains("not a git repository"))
    }

    @Test func readsNothingForAProjectWhoseCommitsTouchedNoThreatModelFile() {
        project.put(oneComponent, at: "/work/threatmodel/payments.arch")
        git.add(
            hash: "aaaaaaa1111",
            date: Date(timeIntervalSince1970: 1_000_000),
            files: ["README.md": "a readme"]
        )

        #expect(rows(read()).isEmpty)
    }

    @Test func namesAPathTheWayGitNamesIt() {
        #expect(
            ReadRiskHistory.relative("/work/threatmodel/payments.arch", to: "/work")
                == "threatmodel/payments.arch"
        )
        #expect(ReadRiskHistory.relative("threatmodel/p.arch", to: "/work") == "threatmodel/p.arch")
    }
}

@Suite("What changed since a commit")
struct CompareRiskToCommitTests {
    private func threat(
        _ id: String = "credential-theft",
        source: String = "api",
        score: Int = 12,
        statuses: [String: String] = [:],
        accepted: [String] = [],
        reviews: [String: String] = [:]
    ) -> ComparedThreat {
        ComparedThreat(
            key: ThreatKey(threatId: id, sourceId: "component:\(source)"),
            name: id,
            sourceName: source,
            riskScore: score,
            controlStatuses: statuses,
            acceptedControls: accepted,
            reviewDates: reviews
        )
    }

    private func change(
        now: [ComparedThreat],
        then: [ComparedThreat],
        catalogueNow: String? = nil,
        catalogueThen: String? = nil
    ) -> RiskChange {
        guard case .compared(let change) = CompareRiskToCommit().execute(
            CompareRiskToCommitRequest(
                now: now,
                then: then,
                catalogueNow: catalogueNow,
                catalogueThen: catalogueThen
            )
        ) else {
            Issue.record("expected a comparison")
            return RiskChange()
        }
        return change
    }

    @Test func namesTheThreatsRaisedAndTheThreatsGone() {
        let changed = change(
            now: [threat(), threat("dos-attack")],
            then: [threat(), threat("misconfiguration")]
        )

        #expect(changed.raised == ["dos-attack on api"])
        #expect(changed.gone == ["misconfiguration on api"])
    }

    @Test func namesEveryControlWhoseStatusMoved() {
        let changed = change(
            now: [threat(statuses: ["Enforce MFA": "implemented"])],
            then: [threat(statuses: ["Enforce MFA": "not_implemented"])]
        )

        #expect(
            changed.controlsChanged
                == ["credential-theft on api: \"Enforce MFA\" not_implemented \u{2192} implemented"]
        )
    }

    @Test func namesARiskNewlyAcceptedAndAReviewDateThatMoved() {
        let changed = change(
            now: [
                threat(
                    accepted: ["Enforce MFA"],
                    reviews: ["Enforce MFA": "2027-03-01"]
                )
            ],
            then: [threat(accepted: [], reviews: ["Enforce MFA": "2026-09-01"])]
        )

        #expect(changed.acceptedAdded == ["credential-theft on api: \"Enforce MFA\""])
        #expect(
            changed.reviewDatesMoved
                == ["credential-theft on api: \"Enforce MFA\" 2026-09-01 \u{2192} 2027-03-01"]
        )
    }

    @Test func statesTheScoreDeltaPerElementWorstFirst() {
        let changed = change(
            now: [threat(source: "api", score: 4), threat(source: "db", score: 16)],
            then: [threat(source: "api", score: 12), threat(source: "db", score: 12)]
        )

        #expect(changed.scoreDeltas.map(\.name) == ["api", "db"])
        #expect(changed.scoreDeltas.map(\.delta) == [-8, 4])
    }

    @Test func namesACatalogueTagThatMoved() {
        let changed = change(
            now: [threat()],
            then: [threat()],
            catalogueNow: "v1.1.0",
            catalogueThen: "v1.0.1"
        )

        #expect(changed.catalogueMoved == "the catalogue moved from v1.0.1 to v1.1.0")
    }

    @Test func statesTheDirectionInOneSentence() {
        #expect(
            change(now: [threat(score: 4)], then: [threat(score: 12)]).direction
                == "Risk is down 8 since the previous assessment."
        )
        #expect(
            change(now: [threat(score: 16)], then: [threat(score: 12)]).direction
                == "Risk is up 4 since the previous assessment."
        )
        #expect(
            change(now: [threat()], then: [threat()]).direction
                == "Risk is unchanged since the previous assessment."
        )
    }

    @Test func changesNothingWhenTheTwoReadingsMatch() {
        #expect(change(now: [threat()], then: [threat()]).isEmpty)
    }
}
