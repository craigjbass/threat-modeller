import Foundation
import Testing
import TestSupport
import ThreatModelKit

/// `Generate Report` from the window passes the pictures the executable
/// passes, so the file the window writes holds the same figures.
///
/// The design is
/// `docs/superpowers/specs/2026-09-17-report-stage-pictures-design.md`.
@Suite("Compiling a report with its pictures")
struct CompileSystemReportPicturesTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func aProject() -> TestDependencies {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        _ = useCases.importArchitecture()
            .execute(ImportArchitectureRequest(text: payments))
        return useCases
    }

    /// A key the report files a threat picture under, for whichever threat
    /// the model raises first.
    private func aThreatKey(_ useCases: TestDependencies) throws -> String {
        let report = useCases.buildThreatModelReport()
            .execute(BuildThreatModelReportRequest()).report
        let threat = try #require(report.rollups.topResidual.first)
        return MarkdownThreatPictures.key(threatId: threat.threatId, sourceId: threat.sourceId)
    }

    /// The picture file goes beside the report, and the report links it.
    @Test func writesEachPictureBesideTheReport() throws {
        let useCases = aProject()
        let key = try aThreatKey(useCases)

        let written = useCases.compileSystemReport().execute(
            CompileSystemReportRequest(
                root: "/work",
                systemName: "payments",
                threatPictures: [key: "payments-threat-1.svg"],
                pictureFiles: ["payments-threat-1.svg": "<svg/>"]
            )
        )

        #expect(written == .written(path: "/work/threatmodel/payments.md"))
        #expect(useCases.project.text(at: "/work/threatmodel/payments-threat-1.svg") == "<svg/>")
        let report = try #require(useCases.project.text(at: "/work/threatmodel/payments.md"))
        #expect(report.contains("(payments-threat-1.svg)"))
        #expect(report.contains("## Top residual risk in detail"))
    }

    /// A caller that draws nothing writes the report it wrote before, with no
    /// picture section and no file beside it.
    @Test func writesNoPictureWhenTheCallerDrawsNone() throws {
        let useCases = aProject()

        let written = useCases.compileSystemReport().execute(
            CompileSystemReportRequest(root: "/work", systemName: "payments")
        )

        #expect(written == .written(path: "/work/threatmodel/payments.md"))
        let report = try #require(useCases.project.text(at: "/work/threatmodel/payments.md"))
        #expect(report.contains("## Top residual risk in detail") == false)
        #expect(report.contains("## Risk over time") == false)
    }

    /// The history the caller sampled writes the Risk over time section and
    /// links the graph the caller drew.
    @Test func writesTheHistoryTheCallerSampled() throws {
        let useCases = aProject()
        let rows = [
            RiskHistoryRow(
                commit: SourceCommit(
                    hash: "bbbbbbbbbbbb",
                    shortHash: "bbbbbbb",
                    author: "Ada",
                    date: Date(timeIntervalSince1970: 1_700_000_000),
                    subject: "now"
                ),
                numbers: RiskHistoryNumbers(
                    totalScore: 20,
                    worstScore: 9,
                    threatCount: 4,
                    acceptedRisks: 0,
                    openAttackTrees: 0,
                    catalogueTag: nil
                )
            ),
            RiskHistoryRow(
                commit: SourceCommit(
                    hash: "aaaaaaaaaaaa",
                    shortHash: "aaaaaaa",
                    author: "Ada",
                    date: Date(timeIntervalSince1970: 1_600_000_000),
                    subject: "then"
                ),
                numbers: RiskHistoryNumbers(
                    totalScore: 30,
                    worstScore: 9,
                    threatCount: 6,
                    acceptedRisks: 0,
                    openAttackTrees: 0,
                    catalogueTag: nil
                )
            )
        ]

        _ = useCases.compileSystemReport().execute(
            CompileSystemReportRequest(
                root: "/work",
                systemName: "payments",
                pictureFiles: ["payments-risk-over-time.svg": "<svg/>"],
                riskOverTimePicture: "payments-risk-over-time.svg",
                history: rows
            )
        )

        let report = try #require(useCases.project.text(at: "/work/threatmodel/payments.md"))
        #expect(report.contains("## Risk over time"))
        #expect(report.contains("(payments-risk-over-time.svg)"))
        #expect(
            useCases.project.text(at: "/work/threatmodel/payments-risk-over-time.svg") == "<svg/>"
        )
    }
}
