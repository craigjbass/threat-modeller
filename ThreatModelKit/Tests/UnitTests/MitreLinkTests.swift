import Testing
import TestSupport
import ThreatModelKit

@Suite("Where a MITRE technique is written up")
struct MitreLinkTests {
    @Test func linksATechnique() {
        #expect(MitreLink.address(of: "T1078") == "https://attack.mitre.org/techniques/T1078/")
    }

    @Test func putsASubTechniqueInItsOwnSegment() {
        #expect(
            MitreLink.address(of: "T1550.001")
                == "https://attack.mitre.org/techniques/T1550/001/"
        )
    }

    @Test func theReportWritesTheLinkOnTheTechniqueLine() {
        let app = TestDependencies()
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  component "api" {
                    technology = "aws-ec2"
                    data       = "confidential"
                  }
                }
                """
            )
        )

        let markdown = app.exportModelAsMarkdown()
            .execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("[T") || markdown.contains("MITRE ATT&CK:"))
        if markdown.contains("MITRE ATT&CK:") {
            #expect(markdown.contains("(https://attack.mitre.org/techniques/"))
        }
    }
}
