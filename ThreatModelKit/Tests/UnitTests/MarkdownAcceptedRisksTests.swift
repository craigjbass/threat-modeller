import Testing
import ThreatModelKit

@Suite("The accepted risks section of the report")
struct MarkdownAcceptedRisksTests {
    private func risk(
        threatName: String = "Credential theft",
        sourceName: String = "api",
        riskScore: Int = 12,
        owner: String = "Head of Platform",
        acceptedOn: String? = "2026-09-01",
        reviewBy: String? = "2027-03-01",
        rationale: String = "The MFA rollout waits on the SSO migration.",
        isOverdue: Bool = false,
        sources: [String] = []
    ) -> ReportAcceptedRisk {
        ReportAcceptedRisk(
            threatName: threatName,
            sourceName: sourceName,
            riskScore: riskScore,
            control: "Enforce MFA on all administrative access",
            owner: owner,
            acceptedOn: acceptedOn,
            reviewBy: reviewBy,
            rationale: rationale,
            isOverdue: isOverdue,
            sources: sources
        )
    }

    @Test func writesNoSectionWhenNothingIsAccepted() {
        #expect(MarkdownAcceptedRisks.lines([]).isEmpty)
    }

    @Test func writesOneRowPerAcceptedRisk() {
        let lines = MarkdownAcceptedRisks.lines([risk()])
        let text = lines.joined(separator: "\n")

        #expect(lines.first == "## Accepted risks")
        #expect(text.contains("The score is the full score: accepting a risk lowers nothing."))
        #expect(
            text.contains("| Threat | Element | Score | Owner | Accepted | Review by | Rationale | Sources |")
        )
        #expect(
            text.contains(
                "| Credential theft | api | 12 | Head of Platform | 2026-09-01 | 2027-03-01"
                    + " | The MFA rollout waits on the SSO migration. | \u{2014} |"
            )
        )
    }

    /// GAP: `accepted.sources` reached the model and no column read it.
    @Test func writesTheAcceptanceSources() {
        let lines = MarkdownAcceptedRisks.lines([
            risk(sources: ["https://example.com/decision"])
        ])

        #expect(lines.contains { $0.contains("https://example.com/decision") })
    }

    @Test func writesDashesForAnUngovernedRisk() {
        let lines = MarkdownAcceptedRisks.lines([
            risk(
                threatName: "Data exfiltration",
                sourceName: "ledger",
                riskScore: 9,
                owner: "",
                acceptedOn: nil,
                reviewBy: nil,
                rationale: ""
            )
        ])

        #expect(
            lines.contains(
                "| Data exfiltration | ledger | 9 | \u{2014} | \u{2014} | \u{2014} | \u{2014} | \u{2014} |"
            )
        )
    }

    @Test func marksAReviewDateThatHasPassed() {
        let lines = MarkdownAcceptedRisks.lines([risk(reviewBy: "2026-01-01", isOverdue: true)])

        #expect(lines.contains { $0.contains("2026-01-01 **overdue**") })
    }

    @Test func countsTheRisksPastTheirReviewDate() {
        #expect(
            MarkdownAcceptedRisks.overdueCount([
                risk(isOverdue: true),
                risk(isOverdue: true),
                risk(isOverdue: false)
            ]) == 2
        )
    }
}
