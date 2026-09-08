import CommandLineApplication
import Testing
import ThreatModelKit
import TestSupport

@Suite("Running the threat modeller from a shell")
struct CommandLineApplicationTests {
    private let project = InMemoryProject(root: "/work")

    private let untidy = """
    system "Payments" {
    zone "app" {
    kind = "private"
    component "api" {
    technology = "aws-ec2"
    data = "confidential"
    }
    }
    }
    """

    private func run(_ words: String...) -> (code: Int32, lines: [String]) {
        var lines: [String] = []
        // The fixture catalogue, so a catalogue update never breaks a verb's
        // test.
        let code = CommandLineApplication(
            projects: project,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(arguments: ["threatmodeller"] + words, output: { lines.append($0) })
        return (code, lines)
    }

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    @Test func rewritesAFileInTheCanonicalShape() throws {
        project.put(untidy, at: "/work/threatmodel/payments.arch")

        let result = run("format", "/work")

        #expect(result.code == 0)
        #expect(result.lines == ["formatted /work/threatmodel/payments.arch"])
        let written = try #require(project.text(at: "/work/threatmodel/payments.arch"))
        #expect(written.contains("  zone \"app\" {"))
        #expect(written.contains("    kind    = \"private\""))
        #expect(written.hasSuffix("}\n"))
    }

    @Test func saysSoWhenAFileWasAlreadyCanonical() {
        project.put(untidy, at: "/work/threatmodel/payments.arch")
        _ = run("format", "/work")

        let result = run("format", "/work")

        #expect(result.code == 0)
        #expect(result.lines == ["unchanged /work/threatmodel/payments.arch"])
    }

    @Test func saysNothingAboutAnUnchangedFileWhenAskedToBeQuiet() {
        project.put(untidy, at: "/work/threatmodel/payments.arch")
        _ = run("format", "/work")

        let result = run("format", "/work", "--quiet")

        #expect(result.lines.isEmpty)
    }

    @Test func reportsADiagnosticTheWayAnEditorReadsIt() throws {
        project.put(
            "system \"P\" {\n  zone \"z\" {\n    kind = \"secret\"\n  }\n}",
            at: "/work/threatmodel/broken.arch"
        )

        let result = run("format", "/work")

        #expect(result.code == 2)
        let line = try #require(result.lines.first)
        #expect(line.hasPrefix("/work/threatmodel/broken.arch:3:5: error: "))
        #expect(line.contains("kind is \"secret\""))
    }

    @Test func leavesAFileItCouldNotParseAsItWas() throws {
        let broken = "system \"P\" {\n  zone \"z\" { kind = \"secret\" }\n}"
        project.put(broken, at: "/work/threatmodel/broken.arch")

        _ = run("format", "/work")

        #expect(project.text(at: "/work/threatmodel/broken.arch") == broken)
    }

    @Test func formatsEverySystemAndReportsTheWorstResult() {
        project.put(untidy, at: "/work/threatmodel/payments.arch")
        project.put("system \"P\" { zone \"z\" { kind = \"secret\" } }", at: "/work/threatmodel/broken.arch")

        let result = run("format", "/work")

        #expect(result.code == 2)
        #expect(result.lines.contains { $0.contains("formatted /work/threatmodel/payments.arch") })
    }

    @Test func saysSoWhenTheRootIsNotADirectory() {
        let result = run("format", "/nowhere")

        #expect(result.code == 3)
        #expect(result.lines.first == "threatmodeller: /nowhere is not a directory")
    }

    @Test func saysSoWhenAProjectHoldsNoArchitectureFiles() {
        project.put("a readme", at: "/work/README.md")

        let result = run("format", "/work")

        #expect(result.code == 0)
        #expect(result.lines.first?.contains("holds no .arch files") == true)
    }

    @Test func writesAControlsFileBesideTheArchitecture() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        let result = run("compile", "/work")

        #expect(result.code == 0)
        #expect(result.lines.first?.hasPrefix("/work/threatmodel/payments.controls: 0 answered") == true)
        let written = try #require(project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.hasPrefix("controls for \"Payments\" {"))
        #expect(written.contains("status = \"not_implemented\""))
    }

    @Test func writesTheControlsFileItReadWhenNothingChanged() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        _ = run("compile", "/work")
        let first = try #require(project.text(at: "/work/threatmodel/payments.controls"))

        _ = run("compile", "/work")

        #expect(project.text(at: "/work/threatmodel/payments.controls") == first)
    }

    @Test func failsTheBuildWhenAThreatHasNoAnswer() {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        let result = run("check", "/work")

        #expect(result.code == 1)
        #expect(result.lines.contains { $0.contains("has no answer") })
    }

    @Test func passesWhenEveryThreatIsAnswered() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        _ = run("compile", "/work")
        let compiled = try #require(project.text(at: "/work/threatmodel/payments.controls"))
        project.put(
            compiled.replacingOccurrences(of: "\"not_implemented\"", with: "\"accepted\""),
            at: "/work/threatmodel/payments.controls"
        )

        let result = run("check", "/work")

        #expect(result.code == 0)
        #expect(result.lines.contains { $0.contains("every threat is answered") })
    }

    @Test func writesTheReportBesideTheArchitecture() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        let result = run("report", "/work")

        #expect(result.code == 0)
        #expect(result.lines == ["wrote /work/threatmodel/payments.md"])
        let written = try #require(project.text(at: "/work/threatmodel/payments.md"))
        #expect(written.hasPrefix("# Payments\n"))
        #expect(written.contains("## Threats"))
    }

    @Test func writesTheReportWhereItWasTold() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        let result = run("report", "/work", "-o", "/out")

        #expect(result.code == 0)
        #expect(project.text(at: "/out/payments.md") != nil)
    }

    @Test func carriesTheAnswersIntoTheReport() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        _ = run("compile", "/work")
        let compiled = try #require(project.text(at: "/work/threatmodel/payments.controls"))
        project.put(
            compiled.replacingOccurrences(of: "\"not_implemented\"", with: "\"implemented\""),
            at: "/work/threatmodel/payments.controls"
        )

        _ = run("report", "/work")

        let written = try #require(project.text(at: "/work/threatmodel/payments.md"))
        #expect(written.contains("- [x] "))
        #expect(written.contains("\u{2014} Implemented"))
    }

    @Test func refusesAVerbItDoesNotHold() {
        let result = run("frobnicate")

        #expect(result.code == 2)
        #expect(result.lines.first == "threatmodeller: there is no verb \"frobnicate\"")
    }

    @Test func showsTheUsageWhenAskedForHelp() {
        let result = run("help")

        #expect(result.code == 0)
        #expect(result.lines.first?.contains("the code-first threat modeller") == true)
    }

    @Test func showsTheUsageWhenGivenNoVerb() {
        let result = run()

        #expect(result.code == 2)
        #expect(result.lines.first?.contains("Usage:") == true)
    }

    @Test func warnsWithoutRefusingTheFile() throws {
        project.put("system \"P\" {\n  zone \"empty\" { }\n}", at: "/work/threatmodel/e.arch")

        let result = run("format", "/work")

        #expect(result.code == 0)
        #expect(result.lines.contains { $0.contains("warning: the zone \"empty\" holds no components") })
    }
}
