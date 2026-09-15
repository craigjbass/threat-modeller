import CommandLineApplication
import FileGateways
import Foundation
import Testing
import ThreatModelKit
import TestSupport

@Suite("A team's own shape for the report")
struct ReportTemplateTests {
    private let app = TestDependencies()
    private let project = InMemoryProject(root: "/work")

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
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

    private func aProject() {
        project.put(payments, at: "/work/threatmodel/payments.arch")
    }

    // MARK: reading a template

    @Test func aSlotOnALineOfItsOwnIsASlot() throws {
        let read = ReportTemplate.read("""
        # Our report

        {{executive_summary}}
        {{findings}}
        """)
        let template = try #require(read.template)

        #expect(template.slots == [.executiveSummary, .findings])
        #expect(template.pieces.first == .text("# Our report"))
    }

    /// A slot inside a sentence is a sentence.
    @Test func aSlotInsideALineIsText() throws {
        let read = ReportTemplate.read("The {{findings}} are below.")
        let template = try #require(read.template)

        #expect(template.slots.isEmpty)
        #expect(template.pieces == [.text("The {{findings}} are below.")])
    }

    @Test func aSectionThatDoesNotExistIsRefused() {
        let read = ReportTemplate.read("{{the_bit_i_want}}")

        #expect(read.template == nil)
        #expect(read.diagnostics.contains { $0.message.contains("the_bit_i_want") })
        #expect(read.diagnostics.contains { $0.message.contains("executive_summary") })
    }

    @Test func aSectionNamedTwiceIsRefused() {
        let read = ReportTemplate.read("{{findings}}\n{{findings}}")

        #expect(read.template == nil)
        #expect(read.diagnostics.contains { $0.message.contains("named twice") })
    }

    @Test func theFrontMatterStatesTheBannerAndTheCover() throws {
        let read = ReportTemplate.read("""
        ---
        banner: OFFICIAL — SENSITIVE
        cover: true
        cover_title: Payments threat model
        cover_subtitle: For the security review board
        ---
        {{findings}}
        """)
        let template = try #require(read.template)

        #expect(template.frontMatter.banner == "OFFICIAL — SENSITIVE")
        #expect(template.frontMatter.hasCover)
        #expect(template.frontMatter.coverTitle == "Payments threat model")
        #expect(template.frontMatter.coverSubtitle == "For the security review board")
        #expect(template.slots == [.findings])
    }

    @Test func aFrontMatterFieldThatDoesNotExistIsRefused() {
        let read = ReportTemplate.read("---\nfooter: nothing\n---\n{{findings}}")

        #expect(read.template == nil)
        #expect(read.diagnostics.contains { $0.message.contains("footer") })
        #expect(read.diagnostics.contains { $0.message.contains("cover_title") })
    }

    @Test func aFrontMatterWithNoClosingLineIsRefused() {
        let read = ReportTemplate.read("---\nbanner: OFFICIAL\n{{findings}}")

        #expect(read.template == nil)
        #expect(read.diagnostics.contains { $0.message.contains("no closing") })
    }

    // MARK: rendering

    /// The default template renders the report byte for byte as it did before
    /// templates existed.
    @Test func theDefaultTemplateWritesTheReportItAlwaysWrote() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        let plain = app.exportModelAsMarkdown()
            .execute(ExportModelAsMarkdownRequest()).markdown
        let templated = app.exportModelAsMarkdown()
            .execute(
                ExportModelAsMarkdownRequest(template: ExportModelAsMarkdown.defaultTemplate)
            ).markdown

        #expect(plain == templated)
    }

    /// Every sample this application ships, rendered both ways.
    @Test func theDefaultTemplateWritesEverySampleTheSameWay() throws {
        let samples = BundledSampleModels()
        let codec = ThreatModelCodec()
        #expect(samples.all().isEmpty == false)

        for sample in samples.all() {
            let app = TestDependencies()
            let model = try codec.decode(try samples.document(id: sample.id))
            app.modelStore.mutate(label: "sample") { held in held = model }

            let plain = app.exportModelAsMarkdown()
                .execute(ExportModelAsMarkdownRequest()).markdown
            let templated = app.exportModelAsMarkdown()
                .execute(
                    ExportModelAsMarkdownRequest(template: ExportModelAsMarkdown.defaultTemplate)
                ).markdown

            #expect(plain == templated, "\(sample.id) reads differently")
        }
    }

    @Test func aTemplateWritesTheTeamsOwnWordsAndTheSectionsItNames() throws {
        aProject()
        project.put("""
        # The board's report

        The board reads this line first.

        {{findings}}
        """, at: "/work/report.md.template")

        #expect(run("report", "/work", "--template", "/work/report.md.template", "--commits", "0").code == 0)

        let report = try #require(project.text(at: "/work/threatmodel/payments.md"))
        #expect(report.hasPrefix("# The board's report"))
        #expect(report.contains("The board reads this line first."))
        #expect(report.contains("## Findings"))
        #expect(report.contains("## Appendix A") == false)
        #expect(report.contains("## Glossary") == false)
    }

    @Test func aProjectStatesItsOwnTemplate() throws {
        aProject()
        project.put("policy {\n  template = \"board.md\"\n}\n", at: "/work/threatmodel/policy.hcl")
        project.put("# The board's report\n\n{{findings}}\n", at: "/work/board.md")

        #expect(run("report", "/work", "--commits", "0").code == 0)

        let report = try #require(project.text(at: "/work/threatmodel/payments.md"))
        #expect(report.hasPrefix("# The board's report"))
    }

    /// The flag wins over the file, the way every other flag does.
    @Test func theFlagWinsOverTheFile() throws {
        aProject()
        project.put("policy {\n  template = \"board.md\"\n}\n", at: "/work/threatmodel/policy.hcl")
        project.put("# The board's report\n\n{{findings}}\n", at: "/work/board.md")
        project.put("# The other report\n\n{{findings}}\n", at: "/work/other.md")

        #expect(run("report", "/work", "--template", "/work/other.md", "--commits", "0").code == 0)

        let report = try #require(project.text(at: "/work/threatmodel/payments.md"))
        #expect(report.hasPrefix("# The other report"))
    }

    @Test func aTemplateThatDoesNotParseStopsTheRun() {
        aProject()
        project.put("{{the_bit_i_want}}\n", at: "/work/board.md")

        let run = self.run("report", "/work", "--template", "/work/board.md")

        #expect(run.code != 0)
        #expect(run.lines.contains { $0.contains("the_bit_i_want") })
        #expect(project.text(at: "/work/threatmodel/payments.md") == nil)
    }

    @Test func aTemplateThatIsNotThereStopsTheRun() {
        aProject()

        let run = self.run("report", "/work", "--template", "/work/nothing.md")

        #expect(run.code != 0)
        #expect(run.lines.contains { $0.contains("there is no template at") })
    }

    @Test func theBannerReadsAtTheTopOfTheMarkdown() throws {
        aProject()
        project.put("---\nbanner: OFFICIAL\n---\n{{findings}}\n", at: "/work/board.md")

        #expect(run("report", "/work", "--template", "/work/board.md", "--commits", "0").code == 0)

        let report = try #require(project.text(at: "/work/threatmodel/payments.md"))
        #expect(report.hasPrefix("> OFFICIAL"))
    }

    // MARK: the page

    @Test func thePageHoldsTheBannerAndTheCover() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let template = try #require(
            ReportTemplate.read("""
            ---
            banner: OFFICIAL — SENSITIVE
            cover: true
            cover_title: Payments threat model
            cover_subtitle: For the board
            ---
            {{findings}}
            """).template
        )

        let page = app.exportModelAsHtml()
            .execute(ExportModelAsHtmlRequest(template: template)).html

        #expect(page.contains("<div class=\"banner\">OFFICIAL — SENSITIVE</div>"))
        #expect(page.contains("<section class=\"cover\">"))
        #expect(page.contains("<h1>Payments threat model</h1>"))
        #expect(page.contains("For the board"))
        #expect(page.contains(".banner { position: fixed;"))
    }

    @Test func aPageWithNoTemplateHoldsNeither() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        let page = app.exportModelAsHtml().execute(ExportModelAsHtmlRequest()).html

        #expect(page.contains("class=\"banner\"") == false)
        #expect(page.contains("class=\"cover\"") == false)
    }

    /// A cover with no title of its own covers the report with the system's
    /// own name.
    @Test func aCoverWithNoTitleTakesTheSystemsName() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let template = try #require(ReportTemplate.read("---\ncover: true\n---\n{{system_name}}").template)

        let page = app.exportModelAsHtml()
            .execute(ExportModelAsHtmlRequest(template: template)).html

        #expect(page.contains("<h1>Payments</h1>"))
    }
}
