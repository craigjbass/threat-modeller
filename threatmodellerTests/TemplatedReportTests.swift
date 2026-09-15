import Foundation
import Testing
import TestSupport
import ThreatModelKit
@testable import threatmodeller

/// The window renders every report through the project's template, the way
/// `threatmodeller report` does.
@MainActor
struct TemplatedReportTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private let policy = "policy {\n  template = \"board.md\"\n}\n"
    private let board = "# The board's report\n\n{{findings}}\n"

    /// A project over `payments`, with the named files beside it.
    private func aProject(putting files: [String: String]) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        for (path, text) in files { useCases.project.put(text, at: path) }
        let session = ProjectSession(useCases: useCases, defaults: aTestDefaults())
        await session.open(root: "/work")
        return (session, useCases)
    }

    // MARK: Generate Report

    @Test func generateReportRendersThroughTheProjectsTemplate() async throws {
        let (session, useCases) = await aProject(putting: [
            "/work/threatmodel/policy.hcl": policy,
            "/work/board.md": board
        ])

        session.compileReport()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.md"))
        #expect(written.hasPrefix("# The board's report"))
        #expect(written.contains("## Findings"))
        #expect(written.contains("## Glossary") == false)
    }

    @Test func generateReportWithoutATemplateKeepsTheShippedShape() async throws {
        let (session, useCases) = await aProject(putting: [:])

        session.compileReport()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.md"))
        #expect(written.hasPrefix("# Payments\n"))
    }

    @Test func generateReportStopsWhenTheTemplateIsNotThere() async {
        let (session, useCases) = await aProject(putting: [
            "/work/threatmodel/policy.hcl": policy
        ])

        session.compileReport()

        #expect(
            session.errorMessage
                == "The report could not be written: there is no template at /work/board.md"
        )
        #expect(useCases.project.text(at: "/work/threatmodel/payments.md") == nil)
        #expect(session.reportPath == nil)
    }

    // MARK: the File menu exports

    @Test func theMarkdownExportRendersThroughTheProjectsTemplate() async throws {
        let (session, useCases) = await aProject(putting: [
            "/work/threatmodel/policy.hcl": policy,
            "/work/board.md": board
        ])

        let export = try #require(session.model?.markdownExport())

        let text = String(decoding: export.data, as: UTF8.self)
        #expect(text.hasPrefix("# The board's report"))

        // The export and *Generate Report* write the same report.
        session.compileReport()
        #expect(text == useCases.project.text(at: "/work/threatmodel/payments.md"))
    }

    @Test func theMarkdownExportWithoutATemplateKeepsTheShippedShape() async throws {
        let (session, _) = await aProject(putting: [:])

        let export = try #require(session.model?.markdownExport())

        #expect(String(decoding: export.data, as: UTF8.self).hasPrefix("# Payments\n"))
    }

    @Test func theHtmlExportRendersThroughTheProjectsTemplate() async throws {
        let (session, _) = await aProject(putting: [
            "/work/threatmodel/policy.hcl": policy,
            "/work/board.md": board
        ])

        let export = try #require(session.model?.htmlExport())

        let page = String(decoding: export.data, as: UTF8.self)
        #expect(page.contains("The board&#8217;s report") || page.contains("The board's report"))
        #expect(page.contains("Glossary") == false)
    }

    @Test func theExportsStopWhenTheTemplateIsNotThere() async {
        let (session, _) = await aProject(putting: [
            "/work/threatmodel/policy.hcl": policy
        ])

        #expect(session.model?.markdownExport()?.data == nil)
        #expect(session.model?.errorMessage == "There is no template at /work/board.md.")

        #expect(session.model?.htmlExport()?.data == nil)
        let pdf = await session.model?.pdfExport()
        #expect(pdf?.data == nil)
    }
}
