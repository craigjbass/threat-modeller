import ArchitectureDSL
import Testing
import TestSupport
@testable import ThreatModelKit

/// A team defines Cribl once, and a project names it. From the moment the
/// library loads, its threat is a threat like any other.
@Suite("Using a shared library")
struct UsingASharedLibraryTests {
    private let payments = """
    system "Payments" {
      component "ingest" { technology = "acme-cribl-stream" }
    }
    """

    private let acme = """
    library "acme" {
      name = "Acme Platform"

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

    /// A project holding one library, and the catalogue that reads it.
    private func aProject() throws -> (InMemoryProject, MergedCatalogue) {
        let projects = InMemoryProject()
        projects.put(payments, at: "/project/threatmodel/payments.arch")
        projects.put(acme, at: "/project/threatmodel/library/acme.lib")

        let base = CatalogueFixture.catalogue()
        let store = LibraryStore()
        guard case .loaded(let libraries, _) = LoadLibraries(
            projects: projects,
            sources: HclLibrarySource(),
            catalogue: base
        ).execute(LoadLibrariesRequest(root: "/project")) else {
            throw LoadFault.theLibraryDidNotLoad
        }
        store.set(libraries)
        return (projects, MergedCatalogue(base: base, store: store))
    }

    private enum LoadFault: Error { case theLibraryDidNotLoad }

    private func compile(
        _ catalogue: TechnologyCatalogue,
        architecture: String,
        controls: String? = nil
    ) -> CompileControlsResponse {
        CompileControls(
            catalogue: catalogue,
            architectureSources: HclArchitectureSource(),
            controlsSources: HclControlsSource(),
            layout: LayOutModel()
        )
        .execute(CompileControlsRequest(architectureText: architecture, controlsText: controls))
    }

    @Test func compilesAStanzaForAThreatOnlyTheLibraryDefines() throws {
        let (_, catalogue) = try aProject()

        guard case .compiled(let text, _, let unanswered, _) = compile(
            catalogue,
            architecture: payments
        ) else {
            Issue.record("the controls did not compile")
            return
        }

        #expect(text.contains("threat \"acme-pipeline-tamper\" on component \"ingest\""))
        #expect(text.contains("control \"Sign pipeline configurations\""))
        #expect(unanswered == 1)
    }

    @Test func keepsTheAnswerAPersonWroteIntoIt() throws {
        let (_, catalogue) = try aProject()
        guard case .compiled(let stub, _, _, _) = compile(catalogue, architecture: payments) else {
            Issue.record("the controls did not compile")
            return
        }
        let answered = stub.replacingOccurrences(
            of: "status = \"not_implemented\"",
            with: "status = \"implemented\""
        )

        guard case .compiled(let text, let answers, let unanswered, _) = compile(
            catalogue,
            architecture: payments,
            controls: answered
        ) else {
            Issue.record("the answered controls did not compile")
            return
        }

        #expect(text.contains("status = \"implemented\""))
        #expect(answers == 1)
        #expect(unanswered == 0)
    }

    @Test func marksTheAnswerStaleWhenTheComponentLeaves() throws {
        let (_, catalogue) = try aProject()
        guard case .compiled(let stub, _, _, _) = compile(catalogue, architecture: payments) else {
            Issue.record("the controls did not compile")
            return
        }

        guard case .compiled(let text, _, _, let stale) = compile(
            catalogue,
            architecture: "system \"Payments\" { }",
            controls: stub
        ) else {
            Issue.record("the emptied architecture did not compile")
            return
        }

        #expect(stale == 1)
        #expect(text.contains("stale threat \"acme-pipeline-tamper\""))
    }

    @Test func raisesNothingWhenTheLibraryIsNotLoaded() {
        guard case .compiled(_, _, let unanswered, _) = compile(
            CatalogueFixture.catalogue(),
            architecture: payments
        ) else {
            Issue.record("the controls did not compile")
            return
        }

        // The component names a technology nothing defines, so it raises no
        // threat. The import reports that as a warning.
        #expect(unanswered == 0)
    }
}
