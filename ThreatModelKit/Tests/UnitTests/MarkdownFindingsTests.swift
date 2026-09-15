import Testing
import ThreatModelKit

struct MarkdownFindingsTests {
    private func threat(_ name: String, _ score: Int) -> ReportThreat {
        ReportThreat(
            threatId: name,
            name: name,
            description: "It can happen.",
            severityLabel: "Critical",
            riskScore: score,
            riskLevel: "critical",
            strideLabels: ["Tampering"],
            mitreTechniqueIds: ["T1195"],
            sourceName: "Build pipeline",
            sourceKind: "Component",
            controls: [ReportControl(description: "Pin hashes", isImplemented: false)],
            pathwayMitigationLabels: []
        )
    }

    @Test func writesEveryThreatAboveToleranceInFull() {
        let lines = MarkdownFindings.lines(
            ReportFindingsCut(above: [threat("Package substitution", 13)], notShown: 0),
            toleranceLabel: "Medium"
        )
        let text = lines.joined(separator: "\n")

        #expect(lines.first == "## Findings")
        #expect(text.contains("Every threat above the project's Medium risk tolerance."))
        #expect(text.contains("### Package substitution \u{2014} Build pipeline"))
        #expect(text.contains("It can happen."))
        #expect(text.contains("- Severity: Critical"))
        #expect(text.contains("- STRIDE: Tampering"))
        #expect(text.contains("- MITRE ATT&CK: [T1195](https://attack.mitre.org/techniques/T1195/)"))
        #expect(text.contains("- [ ] Pin hashes \u{2014} Not implemented"))
    }

    @Test func saysHowManyMoreQualified() {
        let text = MarkdownFindings.lines(
            ReportFindingsCut(above: [threat("a", 13)], notShown: 5),
            toleranceLabel: "Low"
        ).joined(separator: "\n")

        #expect(text.contains("5 more qualify and are in Appendix A."))
    }

    @Test func saysSoWhenNothingSitsAboveTheTolerance() {
        let text = MarkdownFindings.lines(
            ReportFindingsCut(above: [], notShown: 0),
            toleranceLabel: "High"
        ).joined(separator: "\n")

        #expect(text.contains("No threat sits above the project's High risk tolerance."))
        #expect(text.contains("###") == false)
    }
}
