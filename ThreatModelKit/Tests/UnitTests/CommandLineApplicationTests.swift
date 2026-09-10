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

    @Test func theToleranceFlagOverridesTheFilesTolerance() throws {
        project.put(
            """
            system "Payments" {
              component "db" {
                technology = "aws-rds"
                data       = "confidential"
              }
            }
            """,
            at: "/work/threatmodel/payments.arch"
        )
        // A check recompiles, so it applies this finding before it scores the
        // threat: medium (2) times confidential (3) is 6, and "targeted"
        // cuts that to 4 (rounded), the medium band's first score. Low does
        // not cover it; medium does, which is what this test proves.
        project.put(
            """
            controls for "Payments" {
              tolerance = "low"

              threat "misconfiguration" on component "db" {
                severity = "medium"
                score    = 6

                likelihood "no in-the-wild use" {
                  tier      = "targeted"
                  rationale = "no known exploitation"
                }
              }
            }
            """,
            at: "/work/threatmodel/payments.controls"
        )

        let atTheFilesTolerance = run("check", "/work")
        #expect(atTheFilesTolerance.code == 1)

        let atMedium = run("check", "/work", "--tolerance", "medium")
        #expect(atMedium.code == 0)
        #expect(atMedium.lines.contains { $0.contains("checked against a medium risk tolerance") })
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

/// A project whose systems name a technology only a library defines.
@Suite("Running the threat modeller over a project with a library")
struct CommandLineLibraryTests {
    private let project = InMemoryProject(root: "/work")

    private let acme = """
    library "acme" {
      technology "cribl-stream" {
        name     = "Cribl Stream"
        category = "compute"
        threats  = ["pipeline-tamper"]
      }

      threat "pipeline-tamper" {
        name     = "Pipeline tampering"
        severity = "high"

        control "Sign pipeline configurations"
      }
    }

    """

    private func run(_ words: String...) -> (code: Int32, lines: [String]) {
        var lines: [String] = []
        let code = CommandLineApplication(
            projects: project,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(arguments: ["threatmodeller"] + words, output: { lines.append($0) })
        return (code, lines)
    }

    @Test func compilesAThreatOnlyTheLibraryDefines() throws {
        project.put("""
        system "Payments" {
          component "ingest" { technology = "acme-cribl-stream" }
        }
        """, at: "/work/threatmodel/payments.arch")
        project.put(acme, at: "/work/threatmodel/library/acme.lib")

        let outcome = run("compile", "/work")

        #expect(outcome.code == 0)
        let written = try #require(project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("threat \"acme-pipeline-tamper\" on component \"ingest\""))
        #expect(written.contains("control \"Sign pipeline configurations\""))
    }

    @Test func refusesWhenALibraryDoesNotParse() {
        project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        project.put("library \"acme\" { nonsense }", at: "/work/threatmodel/library/acme.lib")

        let outcome = run("check", "/work")

        #expect(outcome.code == 2)
        #expect(outcome.lines.contains { $0.contains("acme.lib") })
    }

    @Test func saysWhatALibraryWarnsAbout() {
        project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        project.put("""
        library "acme" {
          technology "t" { name = "T" category = "compute" threats = ["bare"] }
          threat "bare" { name = "Bare" severity = "low" }
        }
        """, at: "/work/threatmodel/library/acme.lib")

        let outcome = run("check", "/work")

        #expect(outcome.lines.contains { $0.contains("bare") })
    }
}

/// The `library` verbs. Every one runs over a fake fetcher, so no test reaches
/// a server or runs `git`.
@Suite("Managing a library from a shell")
struct LibraryVerbTests {
    private let project = InMemoryProject(root: "/work")
    private let fetcher = FakeLibraryFetcher()
    private let repository = "github.com/acme/threat-elements"

    private func run(_ words: String...) -> (code: Int32, lines: [String]) {
        var lines: [String] = []
        let code = CommandLineApplication(
            projects: project,
            fetcher: fetcher,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(arguments: ["threatmodeller"] + words, output: { lines.append($0) })
        return (code, lines)
    }

    private func aProject() {
        project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        fetcher.put(
            ["acme.lib": "library \"acme\" {\n  name = \"Acme Platform\"\n}\n"],
            repository: repository,
            tag: "v2.1.0"
        )
    }

    @Test func addsALibrary() {
        aProject()

        let outcome = run("library", "add", repository, "v2.1.0", "/work")

        #expect(outcome.code == 0)
        #expect(project.text(at: "/work/threatmodel/library/acme.lib") != nil)
        #expect(project.text(at: "/work/threatmodel/library/library.lock.json") != nil)
        #expect(outcome.lines.contains { $0.contains("acme") })
    }

    @Test func exitsFourWhenTheFetchFails() {
        aProject()

        let outcome = run("library", "add", repository, "v9", "/work")

        #expect(outcome.code == 4)
        #expect(outcome.lines.contains { $0.contains("v9") })
    }

    @Test func exitsTwoWhenWhatItFetchedDoesNotParse() {
        aProject()
        fetcher.put(["bad.lib": "library \"x\" { nonsense }"], repository: "bad", tag: "v1")

        let outcome = run("library", "add", "bad", "v1", "/work")

        #expect(outcome.code == 2)
    }

    @Test func verifiesWhatItAdded() {
        aProject()
        _ = run("library", "add", repository, "v2.1.0", "/work")

        let outcome = run("library", "verify", "/work")

        #expect(outcome.code == 0)
        #expect(outcome.lines.contains { $0.contains("acme.lib") })
    }

    @Test func exitsOneWhenAFileDoesNotMatchTheLockFile() {
        aProject()
        _ = run("library", "add", repository, "v2.1.0", "/work")
        project.put(
            "library \"acme\" { name = \"Changed\" }\n",
            at: "/work/threatmodel/library/acme.lib"
        )

        let outcome = run("library", "verify", "/work")

        #expect(outcome.code == 1)
        #expect(outcome.lines.contains { $0.contains("acme.lib") })
    }

    @Test func listsWhatTheProjectHolds() {
        aProject()
        _ = run("library", "add", repository, "v2.1.0", "/work")

        let outcome = run("library", "list", "/work")

        #expect(outcome.code == 0)
        #expect(outcome.lines.contains { $0.contains("acme") && $0.contains("v2.1.0") })
    }

    @Test func updatesALibraryAtItsRecordedTag() {
        aProject()
        _ = run("library", "add", repository, "v2.1.0", "/work")
        fetcher.put(
            ["acme.lib": "library \"acme\" {\n  name = \"Moved\"\n}\n"],
            repository: repository,
            tag: "v2.1.0"
        )

        let outcome = run("library", "update", "/work")

        #expect(outcome.code == 0)
        #expect(project.text(at: "/work/threatmodel/library/acme.lib")?.contains("Moved") == true)
    }

    @Test func removesALibraryNoSystemNames() {
        aProject()
        _ = run("library", "add", repository, "v2.1.0", "/work")

        let outcome = run("library", "remove", "acme", "/work")

        #expect(outcome.code == 0)
        #expect(project.text(at: "/work/threatmodel/library/acme.lib") == nil)
    }

    @Test func refusesToRemoveALibraryASystemNames() {
        aProject()
        _ = run("library", "add", repository, "v2.1.0", "/work")
        project.put(
            "system \"Payments\" { component \"i\" { technology = \"acme-thing\" } }",
            at: "/work/threatmodel/payments.arch"
        )

        let outcome = run("library", "remove", "acme", "/work")

        #expect(outcome.code == 1)
        #expect(outcome.lines.contains { $0.contains("payments") })
        #expect(project.text(at: "/work/threatmodel/library/acme.lib") != nil)
    }

    @Test func removesItAnywayWhenForced() {
        aProject()
        _ = run("library", "add", repository, "v2.1.0", "/work")
        project.put(
            "system \"Payments\" { component \"i\" { technology = \"acme-thing\" } }",
            at: "/work/threatmodel/payments.arch"
        )

        let outcome = run("library", "remove", "acme", "--force", "/work")

        #expect(outcome.code == 0)
        #expect(project.text(at: "/work/threatmodel/library/acme.lib") == nil)
    }

    @Test func exitsOneWhenALibraryHasANewerTag() {
        aProject()
        _ = run("library", "add", repository, "v2.1.0", "/work")
        fetcher.put([:], repository: repository, tag: "v2.2.0")

        let outcome = run("library", "outdated", "/work")

        #expect(outcome.code == 1)
        #expect(outcome.lines.contains { $0.contains("v2.2.0") })
    }

    @Test func exitsZeroWhenNothingIsNewer() {
        aProject()
        _ = run("library", "add", repository, "v2.1.0", "/work")

        let outcome = run("library", "outdated", "/work")

        #expect(outcome.code == 0)
    }

    @Test func saysWhatTheOperationsAreWhenItIsGivenNone() {
        aProject()

        let outcome = run("library", "/work")

        #expect(outcome.code == 2)
        #expect(outcome.lines.joined(separator: "\n").contains("library add"))
    }

    @Test func namesTheVerbsInTheUsageText() {
        let outcome = run("help")

        let usage = outcome.lines.joined(separator: "\n")
        #expect(usage.contains("library add"))
        #expect(usage.contains("library verify"))
        #expect(usage.contains("library outdated"))
    }
}
