import CommandLineApplication
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// What `check` writes, in each of the three formats.
///
/// A pull request shows a red check with no word on it when a job's failures
/// sit in a log, so a job asks for the shape it can read.
@Suite("The shape check writes")
struct CheckOutputFormatTests {
    private let project = InMemoryProject(root: "/work")

    private func run(_ words: String...) -> (code: Int32, lines: [String]) {
        var lines: [String] = []
        let code = CommandLineApplication(
            projects: project,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(arguments: ["threatmodeller"] + words, output: { lines.append($0) })
        return (code, lines)
    }

    /// One system with one unanswered threat and one stale answer.
    private func seed() {
        project.put(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
              }
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        project.put(
            """
            controls for "Payments" {
              threat "credential-theft" on component "api" {
                control "Enforce IMDSv2 to block SSRF-based credential theft" {
                  status = "implemented"
                }

                control "Use IAM roles with minimal permissions" {
                  status = "implemented"
                }
              }

              threat "sql-injection" on component "gone" {
                control "Use parameterised queries" {
                  status = "implemented"
                }
              }
            }

            """,
            at: "/work/threatmodel/payments.controls"
        )
    }

    @Test func writesThePlainLinesByDefault() {
        seed()

        let result = run("check", "/work")

        #expect(result.code == 1)
        #expect(
            result.lines.contains(
                "/work/threatmodel/payments.controls: dos-attack on component \"api\" (Low) has no answer"
            )
        )
        #expect(
            result.lines.contains(
                "/work/threatmodel/payments.controls: sql-injection@component:gone"
                    + " is answered but no longer raised"
            )
        )
        #expect(result.lines.contains("payments: checked against a low risk tolerance"))
    }

    @Test func writesTheSamePlainLinesWhenTheFormatIsNamed() {
        seed()

        let named = run("check", "--format", "plain", "/work")
        let byDefault = run("check", "/work")

        #expect(named.lines == byDefault.lines)
        #expect(named.code == byDefault.code)
    }

    @Test func writesAWorkflowCommandForEveryFailure() {
        seed()

        let result = run("check", "--format", "github", "/work")

        #expect(result.code == 1)
        // The unanswered threat holds no stanza in this file, so it names the
        // file itself.
        #expect(
            result.lines.contains(
                "::error file=/work/threatmodel/payments.controls,line=1,col=1::"
                    + "dos-attack on component \"api\" (Low) has no answer"
            )
        )
        #expect(
            result.lines.contains(
                "::error file=/work/threatmodel/payments.controls,line=1,col=1::"
                    + "sql-injection@component:gone is answered but no longer raised"
            )
        )
        // The prose lines a person reads are not workflow commands.
        #expect(result.lines.allSatisfy { $0.hasPrefix("::") })
    }

    @Test func namesTheLineOfTheThreatStanzaWhenTheFileHoldsOne() {
        seed()
        // The compile writes a stanza for every raised threat, so after it the
        // unanswered threat has a line of its own.
        _ = run("compile", "/work")

        let result = run("check", "--format", "github", "/work")

        let dos = result.lines.first { $0.contains("dos-attack") }
        #expect(dos != nil)
        #expect(dos?.contains("line=1,") == false)
    }

    @Test func writesAWorkflowWarningForAWarningDiagnostic() {
        project.put("system \"Payments\" { }\n", at: "/work/threatmodel/payments.arch")
        project.put(
            """
            library "acme" {
              catalogue = "v0.9.0"

              technology "cribl-stream" {
                name     = "Cribl Stream"
                category = "compute"
              }
            }
            """,
            at: "/work/threatmodel/library/acme.lib"
        )

        let result = run("check", "--format", "github", "/work")

        // A library warning is about the project rather than one file, so it
        // stays a plain line and the run still passes.
        #expect(result.code == 0)
        #expect(result.lines.contains { $0.contains("was written against catalogue v0.9.0") })
    }

    @Test func writesOneJsonObject() throws {
        seed()

        let result = run("check", "--format", "json", "/work")

        #expect(result.code == 1)
        let text = result.lines.joined(separator: "\n")
        let data = Data(text.utf8)
        let report = try JSONDecoder().decode(CheckReportJSON.self, from: data)

        let system = try #require(report.systems.first)
        #expect(report.systems.count == 1)
        #expect(system.name == "payments")
        #expect(system.tolerance == "low")
        #expect(system.unanswered.map(\.threatId).contains("dos-attack"))
        #expect(system.unanswered.allSatisfy { $0.file == "/work/threatmodel/payments.controls" })
        #expect(system.stale == ["sql-injection@component:gone"])
        #expect(system.staleTrees.isEmpty)
    }

    @Test func writesNothingButTheJsonObject() {
        seed()

        let result = run("check", "--format", "json", "/work")

        // Every prose line the run says travels inside the object, so a tool
        // reading the output parses one document.
        #expect(result.lines.count == 1)
        #expect(result.lines.first?.hasPrefix("{") == true)
    }

    @Test func refusesAFormatItDoesNotHold() {
        seed()

        let result = run("check", "--format", "yaml", "/work")

        #expect(result.code == 2)
        #expect(
            result.lines.contains(
                "threatmodeller: there is no format \"yaml\"; this application holds plain|github|json"
            )
        )
    }

    @Test func compileAndFormatTakeTheSameFlag() {
        seed()

        #expect(run("compile", "--format", "github", "/work").code == 0)
        #expect(run("format", "--format", "github", "/work").code == 0)
    }
}
