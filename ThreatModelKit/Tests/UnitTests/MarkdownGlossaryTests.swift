import Testing
import ThreatModelKit

struct MarkdownGlossaryTests {
    @Test func definesEveryWordTheReportUsesForItself() {
        let lines = MarkdownGlossary.lines()
        let text = lines.joined(separator: "\n")

        #expect(lines.first == "## Glossary")
        for word in [
            "Answered", "Implemented", "Not applicable", "Accepted",
            "Compensating control", "Pathway mitigation", "Mitigates edge",
            "Adopted", "Assumed", "Inherent score", "Residual score",
            "If the assumptions hold", "Risk tolerance", "Prior", "Raised by"
        ] {
            #expect(text.contains("| \(word) |"), "the glossary does not define \(word)")
        }
    }
}
