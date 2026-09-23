import Foundation
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

    // MARK: the attack tree file

    private let treeSystem = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "db" {
        technology = "aws-rds"
        data       = "restricted"
      }

      flow api -> db
    }

    """

    private let oneTree = """
    attack_trees for "Payments" {
      tree "t" {
        raises_risk_by = 40

        goal "misconfiguration" on component "db"

        step "credential-theft" on component "api"
      }
    }

    """

    private let brokenTree = """
    attack_trees for "Payments" {
      tree "t" {
        goal "misconfiguration" on component "db"

        step "credential-theft" on component "gone"
      }
    }

    """

    @Test func compileWritesATreeStanzaIntoTheControlsFile() throws {
        project.put(treeSystem, at: "/work/threatmodel/payments.arch")
        project.put(oneTree, at: "/work/threatmodel/payments.attacktree")

        #expect(run("compile", "/work").code == 0)

        let controls = try #require(try project.read(path: "/work/threatmodel/payments.controls"))
        #expect(controls.contains("tree \"t\" {"))
        #expect(controls.contains("step \"credential-theft@component:api\" {"))
    }

    @Test func checkFailsOnATreeThatNoLongerBinds() {
        project.put(treeSystem, at: "/work/threatmodel/payments.arch")
        project.put(brokenTree, at: "/work/threatmodel/payments.attacktree")
        _ = run("compile", "/work")

        let checked = run("check", "/work")

        #expect(checked.code == 1)
        #expect(checked.lines.contains {
            $0.contains("the tree \"t\" is written but no longer binds")
        })
    }

    @Test func reportWritesTheAttackTreeSection() throws {
        project.put(treeSystem, at: "/work/threatmodel/payments.arch")
        project.put(oneTree, at: "/work/threatmodel/payments.attacktree")

        #expect(run("report", "/work").code == 0)

        let report = try #require(try project.read(path: "/work/threatmodel/payments.md"))
        #expect(report.contains("## Attack trees"))
    }

    @Test func formatRewritesTheAttackTreeFile() throws {
        project.put(treeSystem, at: "/work/threatmodel/payments.arch")
        project.put("""
        attack_trees for "Payments" {
        tree "t" {
        goal "misconfiguration" on component "db"
        step "credential-theft" on component "api"
        }
        }
        """, at: "/work/threatmodel/payments.attacktree")

        #expect(run("format", "/work").code == 0)

        let written = try #require(try project.read(path: "/work/threatmodel/payments.attacktree"))
        #expect(written.contains("  tree \"t\" {"))
    }

    @Test func everyVerbRunsOnASystemWithNoAttackTreeFile() {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        #expect(run("compile", "/work").code == 0)
        #expect(run("format", "/work").code == 0)
        #expect(run("report", "/work").code == 0)
    }

    // MARK: a library written against another catalogue tag

    @Test func namesALibraryWrittenAgainstAnotherCatalogueTagAndStillPasses() {
        // A system with no component raises no threat, so this run fails for
        // the tag alone or for nothing at all.
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

        let result = run("check", "/work")

        // A warning is not a failure.
        #expect(result.code == 0)
        #expect(
            result.lines.contains(
                "threatmodeller: the library \"acme\" was written against catalogue v0.9.0, "
                    + "and the catalogue in use is v0.0.0"
            )
        )
    }

    // MARK: a picture of each threat that matters

    @Test func writesAPictureOfEachTopResidualThreat() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        let result = run("report", "/work")

        #expect(result.code == 0)
        let markdown = try #require(try project.read(path: "/work/threatmodel/payments.md"))
        #expect(markdown.contains("## Top residual risk in detail"))
        #expect(markdown.contains("![") && markdown.contains("payments-threat-1.svg)"))

        let picture = try #require(try project.read(path: "/work/threatmodel/payments-threat-1.svg"))
        #expect(picture.hasPrefix("<svg"))
        #expect(picture.contains("EC2"))
    }

    @Test func writesThePicturesWhereTheReportGoes() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        _ = run("report", "/work", "-o", "/out")

        #expect(project.exists(path: "/out/payments-threat-1.svg"))
    }

    // MARK: the report as one page

    @Test func writesNoPageUnlessItIsAsked() {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        _ = run("report", "/work")

        #expect(project.exists(path: "/work/threatmodel/payments.html") == false)
    }

    @Test func writesThePageBesideTheReport() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        let result = run("report", "/work", "--html")

        #expect(result.code == 0)
        #expect(result.lines.contains("wrote /work/threatmodel/payments.html"))
        let page = try #require(try project.read(path: "/work/threatmodel/payments.html"))
        #expect(page.hasPrefix("<!doctype html>"))
        #expect(page.contains("<h1>"))
    }

    @Test func thePageHoldsEveryPictureItself() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        _ = run("report", "/work", "--html")

        let page = try #require(try project.read(path: "/work/threatmodel/payments.html"))
        // A page that reads its pictures from files beside it is not one file.
        #expect(page.contains("<figure><svg"))
        #expect(page.contains("src=\"payments-threat-1.svg\"") == false)
    }

    // MARK: drawing a picture

    @Test func writesTheDiagramAsSvg() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        let result = run("draw", "/work")

        #expect(result.code == 0)
        #expect(result.lines == ["wrote /work/threatmodel/payments.svg"])
        let svg = try #require(try project.read(path: "/work/threatmodel/payments.svg"))
        #expect(svg.hasPrefix("<svg"))
        #expect(svg.contains("EC2"))
    }

    @Test func writesTheDiagramWhereItIsTold() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        let result = run("draw", "/work", "-o", "/out")

        #expect(result.code == 0)
        #expect(result.lines == ["wrote /out/payments.svg"])
    }

    @Test func saysNothingAboutADiagramWhenAskedToBeQuiet() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        #expect(run("draw", "/work", "--quiet").lines.isEmpty)
    }

    @Test func refusesToDrawAFileThatDoesNotParse() throws {
        project.put("system \"Broken\" {", at: "/work/threatmodel/broken.arch")

        #expect(run("draw", "/work").code == 2)
    }

    @Test func offersDrawInTheHelp() {
        #expect(run("help").lines.joined().contains("threatmodeller draw"))
    }

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

    /// GAP audit #260 / issue #264: the bracket named `answer.severityLabel`
    /// while the field it filled was called `riskLevel`. Credential theft's
    /// severity is Critical, and a `public` component's sensitivity is the
    /// lowest rank, so the computed risk level is Medium, not Critical.
    @Test func namesTheComputedRiskLevelInTheBracketNotTheCatalogueSeverity() {
        project.put(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "public"
              }
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )

        let result = run("check", "/work")

        #expect(result.lines.contains { $0.contains("credential-theft on component \"api\" (Medium)") })
        #expect(result.lines.contains { $0.contains("(Critical)") } == false)
    }

    @Test func passesWhenEveryThreatIsAnswered() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        _ = run("compile", "/work")
        let compiled = try #require(project.text(at: "/work/threatmodel/payments.controls"))
        project.put(
            compiled.replacingOccurrences(of: "\"not_implemented\"", with: "\"implemented\""),
            at: "/work/threatmodel/payments.controls"
        )

        let result = run("check", "/work")

        #expect(result.code == 0)
        #expect(result.lines.contains { $0.contains("every threat is answered") })
    }

    // MARK: the history verb

    private func aHistory() -> FakeGitHistory {
        let git = FakeGitHistory(root: "/work")
        git.add(
            hash: "aaaaaaa1111",
            date: Date(timeIntervalSince1970: 1_000_000),
            files: ["threatmodel/payments.arch": payments]
        )
        git.add(
            hash: "bbbbbbb2222",
            date: Date(timeIntervalSince1970: 2_000_000),
            files: ["threatmodel/payments.arch": payments]
        )
        return git
    }

    private func run(_ words: [String], history: GitHistoryGateway) -> (code: Int32, lines: [String]) {
        var lines: [String] = []
        let code = CommandLineApplication(
            projects: project,
            history: history,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(arguments: ["threatmodeller"] + words, output: { lines.append($0) })
        return (code, lines)
    }

    @Test func historyPrintsOneRowPerSampledCommit() {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        let result = run(["history", "/work"], history: aHistory())

        #expect(result.code == 0)
        #expect(result.lines.count == 2)
        #expect(result.lines.allSatisfy { $0.contains("total ") })
        #expect(result.lines.first?.contains("bbbbbbb") == true)
    }

    @Test func historyPrintsTheSameRowsTwice() {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        let git = aHistory()

        #expect(run(["history", "/work"], history: git).lines
            == run(["history", "/work"], history: git).lines)
    }

    @Test func historyBoundsTheSampleAndSaysSo() {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        let result = run(["history", "--commits", "1", "/work"], history: aHistory())

        #expect(result.lines.count == 2)
        #expect(result.lines.contains { $0.contains("the project holds more") })
    }

    @Test func historySaysSoForADirectoryThatIsNoRepository() {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        let git = aHistory()
        git.forget("/work")

        let result = run(["history", "/work"], history: git)

        #expect(result.code == 0)
        #expect(result.lines.contains { $0.contains("is not a git repository") })
    }

    @Test func reportWritesTheRiskOverTimeSectionAndItsGraph() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        #expect(run(["report", "/work"], history: aHistory()).code == 0)

        let report = try #require(try project.read(path: "/work/threatmodel/payments.md"))
        #expect(report.contains("## Risk over time"))
        #expect(report.contains("payments-risk-over-time.svg"))
        let chart = try #require(
            try project.read(path: "/work/threatmodel/payments-risk-over-time.svg")
        )
        #expect(chart.hasPrefix("<svg"))
    }

    @Test func reportWritesNoHistorySectionForAProjectWithNoHistory() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        let git = FakeGitHistory(root: "/work")

        #expect(run(["report", "/work"], history: git).code == 0)

        let report = try #require(try project.read(path: "/work/threatmodel/payments.md"))
        #expect(report.contains("## Risk over time") == false)
        #expect(report.contains("## What changed") == false)
    }

    // MARK: the policy file

    @Test func checkFailsForAPolicyBreachAndNamesTheRule() {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        project.put(
            """
            policy {
              system_requires_owner = true
            }
            """,
            at: "/work/threatmodel/policy.hcl"
        )

        let result = run("check", "/work")

        #expect(result.code == 1)
        #expect(
            result.lines.contains { $0.contains("system_requires_owner: this system states no owner") }
        )
    }

    @Test func checkPassesWhenTheSystemKeepsTheRule() throws {
        project.put(
            """
            system "Payments" {
              owner = "Payments team"
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        project.put(
            """
            policy {
              system_requires_owner = true
            }
            """,
            at: "/work/threatmodel/policy.hcl"
        )

        #expect(run("check", "/work").code == 0)
    }

    @Test func writesAPolicyBreachAsAWorkflowCommand() {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        project.put(
            """
            policy {
              system_requires_owner = true
            }
            """,
            at: "/work/threatmodel/policy.hcl"
        )

        let result = run("check", "--format", "github", "/work")

        #expect(result.code == 1)
        #expect(
            result.lines.contains {
                $0.hasPrefix("::error file=") && $0.contains("system_requires_owner")
            }
        )
    }

    @Test func checksAsItDidForAProjectWithNoPolicyFile() {
        project.put(
            """
            system "Payments" { }

            """,
            at: "/work/threatmodel/payments.arch"
        )

        #expect(run("check", "/work").code == 0)
    }

    @Test func reportWritesThePolicySection() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        project.put(
            """
            policy {
              system_requires_owner = true
            }
            """,
            at: "/work/threatmodel/policy.hcl"
        )

        #expect(run("report", "/work").code == 0)

        let report = try #require(try project.read(path: "/work/threatmodel/payments.md"))
        #expect(report.contains("## Policy"))
        #expect(report.contains("| system_requires_owner | the file states an owner | no"))
    }

    // MARK: a split system

    private static let splitHeader = """
    system "Payments" {
      catalogue = "v1.0.0"
    }
    """

    private static let splitEdge = """
    component "waf" {
      technology = "aws-rds"
      data       = "internal"
    }
    """

    private static let splitLedger = """
    component "api" {
      technology = "aws-ec2"
      data       = "confidential"
    }

    flow waf -> api
    """

    private func aSplitProject() {
        project.put(Self.splitHeader, at: "/work/threatmodel/payments/arch/payments.arch")
        project.put(Self.splitEdge, at: "/work/threatmodel/payments/arch/edge.arch")
        project.put(Self.splitLedger, at: "/work/threatmodel/payments/arch/ledger.arch")
    }

    @Test func compileWritesOneControlsFilePerArchitectureFile() throws {
        aSplitProject()

        let result = run("compile", "/work")

        #expect(result.code == 0)
        let edge = try #require(
            project.text(at: "/work/threatmodel/payments/controls/edge.controls")
        )
        let ledger = try #require(
            project.text(at: "/work/threatmodel/payments/controls/ledger.controls")
        )
        // An answer sits in the file that mirrors the architecture file its
        // element came from.
        #expect(edge.contains("on component \"waf\""))
        #expect(edge.contains("on component \"api\"") == false)
        #expect(ledger.contains("on component \"api\""))
    }

    @Test func checkReadsEveryFileOfASplitSystem() {
        aSplitProject()
        _ = run("compile", "/work")

        let result = run("check", "/work")

        // Nothing is answered yet, so the check fails and names the threats
        // of both files.
        #expect(result.code == 1)
        #expect(result.lines.contains { $0.contains("\"api\"") })
        #expect(result.lines.contains { $0.contains("\"waf\"") })
    }

    @Test func checkRefusesAComponentThatNestsAndStatesAnotherZone() {
        project.put(Self.splitHeader, at: "/work/threatmodel/payments/arch/payments.arch")
        project.put(
            """
            zone "edge" {
              kind = "public"

              component "waf" {
                technology = "aws-waf"
                zone       = "core"
              }
            }

            zone "core" { kind = "private" }
            """,
            at: "/work/threatmodel/payments/arch/edge.arch"
        )

        let result = run("check", "/work")

        #expect(result.code == 2)
        #expect(result.lines.contains {
            $0.contains("arch/edge.arch")
                && $0.contains("the component \"waf\" sits in the zone \"edge\" and states zone \"core\"")
        })
    }

    @Test func checkRefusesAZoneNoPartFileDeclares() {
        project.put(Self.splitHeader, at: "/work/threatmodel/payments/arch/payments.arch")
        project.put(
            "component \"api\" {\n  technology = \"aws-ec2\"\n  zone       = \"ghost\"\n}",
            at: "/work/threatmodel/payments/arch/ledger.arch"
        )

        let result = run("check", "/work")

        #expect(result.code == 2)
        #expect(result.lines.contains {
            $0.contains("the component \"api\" states zone \"ghost\", which this system does not declare")
        })
    }

    @Test func checkReadsAComponentWhoseZoneAnotherPartFileDeclares() {
        project.put(Self.splitHeader, at: "/work/threatmodel/payments/arch/payments.arch")
        project.put(
            "zone \"edge\" {\n  kind = \"public\"\n\n  component \"waf\" { technology = \"aws-waf\" }\n}",
            at: "/work/threatmodel/payments/arch/edge.arch"
        )
        project.put(
            "component \"api\" {\n  technology = \"aws-ec2\"\n  zone       = \"edge\"\n}",
            at: "/work/threatmodel/payments/arch/ledger.arch"
        )
        _ = run("compile", "/work")

        let result = run("check", "/work")

        #expect(result.code == 1)
        #expect(result.lines.contains { $0.contains("\"api\"") })
    }

    @Test func reportWritesOneReportInsideTheSubproject() {
        aSplitProject()

        let result = run("report", "/work")

        #expect(result.code == 0)
        #expect(project.text(at: "/work/threatmodel/payments/payments.md") != nil)
    }

    @Test func formatRewritesEveryFileOfASplitSystem() throws {
        project.put(Self.splitHeader, at: "/work/threatmodel/payments/arch/payments.arch")
        project.put(
            "component \"waf\" {\ntechnology = \"aws-waf\"\n}",
            at: "/work/threatmodel/payments/arch/edge.arch"
        )

        let result = run("format", "/work")

        #expect(result.code == 0)
        let written = try #require(
            project.text(at: "/work/threatmodel/payments/arch/edge.arch")
        )
        #expect(written.hasPrefix("component \"waf\" {"))
        #expect(written.contains("  technology = \"aws-waf\""))
    }

    @Test func splitMovesAFlatSystemIntoADirectory() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        _ = run("compile", "/work")
        #expect(project.text(at: "/work/threatmodel/payments.controls") != nil)

        let result = run("split", "payments", "/work")

        #expect(result.code == 0)
        #expect(project.text(at: "/work/threatmodel/payments/arch/payments.arch") != nil)
        #expect(project.text(at: "/work/threatmodel/payments/controls/payments.controls") != nil)
        #expect(project.text(at: "/work/threatmodel/payments.arch") == nil)
        #expect(project.text(at: "/work/threatmodel/payments.controls") == nil)
    }

    /// A subproject a person wrote by hand is read and written again, so
    /// every component outside a zone moves into the header file.
    @Test func splitSortsASystemThatIsAlreadyADirectory() throws {
        aSplitProject()

        let result = run("split", "payments", "/work")

        #expect(result.code == 0)
        let header = try #require(
            project.text(at: "/work/threatmodel/payments/arch/payments.arch")
        )
        #expect(header.contains("component \"api\""))
        #expect(header.contains("component \"waf\""))
        #expect(project.text(at: "/work/threatmodel/payments/arch/ledger.arch") == nil)
        #expect(project.text(at: "/work/threatmodel/payments/arch/edge.arch") == nil)
    }

    @Test func splitRefusesASystemTheProjectDoesNotHold() {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        let result = run("split", "ledger", "/work")

        #expect(result.code == 3)
        #expect(result.lines.contains { $0.contains("holds no system called \"ledger\"") })
    }

    /// A split system reads and writes the same way after a split: the moved
    /// files compile, and the compile writes beside them.
    @Test func aSplitSystemCompilesAfterASplit() {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        _ = run("split", "payments", "/work")

        let result = run("compile", "/work")

        #expect(result.code == 0)
        #expect(project.text(at: "/work/threatmodel/payments/controls/payments.controls") != nil)
    }

    // MARK: attack and actors

    /// A small STIX bundle, the shape `AttackSyncTests` states.
    private static let bundle = """
    {
      "type": "bundle",
      "objects": [
        {
          "type": "intrusion-set",
          "id": "intrusion-set--1",
          "name": "FIN7",
          "external_references": [
            { "source_name": "mitre-attack", "external_id": "G0046" }
          ]
        },
        {
          "type": "attack-pattern",
          "id": "attack-pattern--1",
          "name": "Phishing",
          "kill_chain_phases": [
            { "kill_chain_name": "mitre-attack", "phase_name": "initial-access" }
          ],
          "external_references": [
            { "source_name": "mitre-attack", "external_id": "T1566" }
          ]
        },
        {
          "type": "relationship",
          "relationship_type": "uses",
          "source_ref": "intrusion-set--1",
          "target_ref": "attack-pattern--1"
        }
      ]
    }
    """

    private let attackData = InMemoryAttackData()
    private let downloader = FakeAttackDownloader()

    private func runAttack(_ words: String...) -> (code: Int32, lines: [String]) {
        var lines: [String] = []
        let code = CommandLineApplication(
            projects: project,
            attackData: attackData,
            downloader: downloader,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(arguments: ["threatmodeller"] + words, output: { lines.append($0) })
        return (code, lines)
    }

    @Test func attackSyncDownloadsExtractsAndWritesTheLockFile() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        downloader.put(
            Data(Self.bundle.utf8),
            at: AttackRelease.address(of: AttackRelease.default)
        )

        let result = runAttack("attack", "sync", "/work")

        #expect(result.code == 0)
        #expect(result.lines.contains { $0.contains("1 groups, 1 techniques") })
        #expect(attackData.read(fileName: AttackDataLocation.groupsFileName) != nil)
        #expect(project.text(at: "/work/threatmodel/\(AttackLock.fileName)") != nil)
    }

    /// It states the tag, the address and the size before it starts.
    @Test func attackSyncSaysWhatItWillDo() {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        downloader.put(
            Data(Self.bundle.utf8),
            at: AttackRelease.address(of: AttackRelease.default)
        )

        let result = runAttack("attack", "sync", "/work")

        let said = result.lines.joined(separator: "\n")
        #expect(said.contains(AttackRelease.default))
        #expect(said.contains("attack-stix-data"))
        #expect(said.contains("MB"))
    }

    @Test func attackVerifyMakesNoNetworkCall() {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        downloader.put(
            Data(Self.bundle.utf8),
            at: AttackRelease.address(of: AttackRelease.default)
        )
        _ = runAttack("attack", "sync", "/work")
        let downloadsAfterSync = downloader.downloads.count

        let result = runAttack("attack", "verify", "/work")

        #expect(result.code == 0)
        #expect(result.lines.contains { $0.contains("matches") })
        #expect(downloader.downloads.count == downloadsAfterSync)
    }

    @Test func attackVerifySaysWhenThisMachineHoldsNoData() {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        project.put(
            """
            {
              "bundle" : "enterprise-attack/enterprise-attack-19.2.json",
              "files" : { "groups.json" : "0" },
              "repository" : "mitre-attack/attack-stix-data",
              "tag" : "v19.2"
            }
            """,
            at: "/work/threatmodel/\(AttackLock.fileName)"
        )

        let result = runAttack("attack", "verify", "/work")

        #expect(result.code == 1)
        #expect(result.lines.contains { $0.contains("attack sync v19.2") })
    }

    @Test func actorsListStatesEachActorAndWhatItPerforms() {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        let result = runAttack("actors", "list", "/work")

        #expect(result.code == 0)
        #expect(result.lines.contains { $0.contains("threats") })
    }

    @Test func actorsListWithMitreSaysToSynchroniseWhenNothingIsThere() {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        let result = runAttack("actors", "list", "--mitre", "/work")

        #expect(result.lines.contains { $0.contains("attack sync") })
    }

    /// Nothing but a synchronise reaches the network.
    @Test func compilingAndReportingReachNoNetwork() {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        _ = runAttack("compile", "/work")
        _ = runAttack("check", "/work")
        _ = runAttack("report", "/work")

        #expect(downloader.downloads.isEmpty)
    }

    // MARK: the library file

    private static let untidyLibrary = """
    library "acme" {
    name = "Acme Platform"
    technology "cribl-stream" {
    name = "Cribl Stream"
    category = "monitoring"
    threats = ["pipeline-tamper"]
    }
    threat "pipeline-tamper" {
    name = "Pipeline tampering"
    severity = "high"
    control "Sign pipeline configurations"
    }
    }
    """

    @Test func formatRewritesALibraryFile() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        project.put(Self.untidyLibrary, at: "/work/threatmodel/library/acme.lib")

        let result = run("format", "/work")

        #expect(result.code == 0)
        let written = try #require(project.text(at: "/work/threatmodel/library/acme.lib"))
        #expect(written.contains("  technology \"cribl-stream\" {"))
        #expect(result.lines.contains { $0.contains("formatted /work/threatmodel/library/acme.lib") })
    }

    @Test func formattingALibraryTwiceChangesNothingTheSecondTime() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        project.put(Self.untidyLibrary, at: "/work/threatmodel/library/acme.lib")
        _ = run("format", "/work")
        let once = try #require(project.text(at: "/work/threatmodel/library/acme.lib"))

        let result = run("format", "/work")

        #expect(project.text(at: "/work/threatmodel/library/acme.lib") == once)
        #expect(result.lines.contains { $0.contains("unchanged /work/threatmodel/library/acme.lib") })
    }

    @Test func formatRefusesALibraryThatDoesNotParse() {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        project.put("library \"acme\" { technology }", at: "/work/threatmodel/library/acme.lib")

        let result = run("format", "/work")

        #expect(result.code == 2)
        #expect(result.lines.contains { $0.contains("/work/threatmodel/library/acme.lib:") })
    }

    // MARK: the governance file

    @Test func compileWritesAGovernanceFileForAnAcceptedRisk() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        _ = run("compile", "/work")
        let compiled = try #require(project.text(at: "/work/threatmodel/payments.controls"))
        project.put(
            compiled.replacingOccurrences(of: "\"not_implemented\"", with: "\"accepted\""),
            at: "/work/threatmodel/payments.controls"
        )

        #expect(run("compile", "/work").code == 0)

        let governance = try #require(project.text(at: "/work/threatmodel/payments.governance"))
        #expect(governance.hasPrefix("governance for \"Payments\" {"))
        #expect(governance.contains("accepted \""))
    }

    @Test func writesNoGovernanceFileForASystemThatGovernsNothing() {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        #expect(run("compile", "/work").code == 0)

        #expect(project.text(at: "/work/threatmodel/payments.governance") == nil)
    }

    @Test func checkFailsForAnAcceptedRiskWithNoOwner() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        _ = run("compile", "/work")
        let compiled = try #require(project.text(at: "/work/threatmodel/payments.controls"))
        project.put(
            compiled.replacingOccurrences(of: "\"not_implemented\"", with: "\"accepted\""),
            at: "/work/threatmodel/payments.controls"
        )
        _ = run("compile", "/work")

        let result = run("check", "/work")

        #expect(result.code == 1)
        #expect(result.lines.contains { $0.contains("is accepted by nobody") })
    }

    /// The route a person walks when a project starts to accept risk:
    /// accept, watch `check` fail, compile to write the governance file, fill
    /// in who carries each risk and when they look at it again, and check
    /// again. The Linux job used to walk this in shell; it walks here instead,
    /// where the same run covers macOS and Linux.
    @Test func checkPassesOnceEveryAcceptedRiskHasAnOwnerAndAReviewDate() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        _ = run("compile", "/work")
        let compiled = try #require(project.text(at: "/work/threatmodel/payments.controls"))
        project.put(
            compiled.replacingOccurrences(of: "\"not_implemented\"", with: "\"accepted\""),
            at: "/work/threatmodel/payments.controls"
        )
        _ = run("compile", "/work")
        let written = try #require(project.text(at: "/work/threatmodel/payments.governance"))

        project.put(Self.governed(written), at: "/work/threatmodel/payments.governance")
        let result = run("check", "/work")

        #expect(result.code == 0)
        #expect(result.lines.contains { $0.contains("is accepted by nobody") } == false)
    }

    /// Puts an owner and two dates in every `accepted` block of a governance
    /// file, as a person would.
    private static func governed(_ text: String) -> String {
        var lines: [String] = []
        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            lines.append(String(line))
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("accepted \""), trimmed.hasSuffix("{") else { continue }
            let indent = String(repeating: " ", count: line.count - trimmed.count + 2)
            lines.append(indent + "owner       = \"The Platform Team\"")
            lines.append(indent + "accepted_on = \"2026-01-01\"")
            lines.append(indent + "review_by   = \"2099-01-01\"")
        }
        return lines.joined(separator: "\n")
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
        #expect(
            result.lines == [
                "wrote /work/threatmodel/payments.md",
                "wrote 3 threat diagrams beside it"
            ]
        )
        let written = try #require(project.text(at: "/work/threatmodel/payments.md"))
        #expect(written.hasPrefix("# Payments\n"))
        #expect(written.contains("## Appendix A \u{2014} Full threat register"))
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
