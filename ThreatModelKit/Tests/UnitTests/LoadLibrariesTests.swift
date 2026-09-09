import ArchitectureDSL
import Testing
import TestSupport
@testable import ThreatModelKit

@Suite("Loading a project's libraries")
struct LoadLibrariesTests {
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

    private func aProject(_ files: [String: String]) -> LoadLibrariesUseCase {
        let projects = InMemoryProject()
        for (path, text) in files { projects.put(text, at: path) }
        return LoadLibraries(
            projects: projects,
            sources: HclLibrarySource(),
            catalogue: CatalogueFixture.catalogue()
        )
    }

    @Test func readsEveryLibraryBesideTheSystems() throws {
        let load = aProject([
            "/project/threatmodel/payments.arch": "system \"Payments\" { }",
            "/project/threatmodel/library/acme.lib": acme
        ])

        guard case .loaded(let libraries, let warnings) = load.execute(
            LoadLibrariesRequest(root: "/project")
        ) else {
            Issue.record("the libraries did not load")
            return
        }

        #expect(warnings.isEmpty)
        #expect(libraries.map(\.label) == ["acme"])
        #expect(libraries.first?.technologies.map(\.id.value) == ["acme-cribl-stream"])
        #expect(libraries.first?.threats.map(\.id.value) == ["acme-pipeline-tamper"])
    }

    @Test func loadsNothingWhenTheProjectHoldsNoLibrary() {
        let load = aProject(["/project/threatmodel/payments.arch": "system \"Payments\" { }"])

        guard case .loaded(let libraries, _) = load.execute(
            LoadLibrariesRequest(root: "/project")
        ) else {
            Issue.record("a project with no library did not load")
            return
        }

        #expect(libraries.isEmpty)
    }

    @Test func refusesAFileThatDoesNotParse() {
        let load = aProject([
            "/project/threatmodel/payments.arch": "system \"Payments\" { }",
            "/project/threatmodel/broken.lib": "library \"acme\" { nonsense }",
            "/project/threatmodel/library/broken.lib": "library \"acme\" { nonsense }"
        ])

        guard case .refused(let fileName, let diagnostics) = load.execute(
            LoadLibrariesRequest(root: "/project")
        ) else {
            Issue.record("a library that does not parse did not refuse")
            return
        }

        #expect(fileName == "broken.lib")
        #expect(diagnostics.isEmpty == false)
    }

    @Test func refusesTwoLibrariesWithTheSameLabel() {
        let load = aProject([
            "/project/threatmodel/payments.arch": "system \"Payments\" { }",
            "/project/threatmodel/library/one.lib": "library \"acme\" { }",
            "/project/threatmodel/library/two.lib": "library \"acme\" { }"
        ])

        guard case .refused(let fileName, let diagnostics) = load.execute(
            LoadLibrariesRequest(root: "/project")
        ) else {
            Issue.record("two libraries with one label did not refuse")
            return
        }

        #expect(fileName == "two.lib")
        #expect(diagnostics.first?.message.contains("acme") == true)
    }

    @Test func refusesAValueTheTaxonomyDoesNotHold() {
        let load = aProject([
            "/project/threatmodel/payments.arch": "system \"Payments\" { }",
            "/project/threatmodel/library/acme.lib": """
            library "acme" {
              technology "t" { name = "T" category = "observability" }
            }
            """
        ])

        guard case .refused(_, let diagnostics) = load.execute(
            LoadLibrariesRequest(root: "/project")
        ) else {
            Issue.record("an unknown category did not refuse")
            return
        }

        #expect(diagnostics.first?.message.contains("observability") == true)
    }

    @Test func carriesTheWarningsAFileRaises() throws {
        let load = aProject([
            "/project/threatmodel/payments.arch": "system \"Payments\" { }",
            "/project/threatmodel/library/acme.lib": """
            library "acme" {
              technology "t" { name = "T" category = "compute" threats = ["bare"] }
              threat "bare" { name = "Bare" severity = "low" }
            }
            """
        ])

        guard case .loaded(_, let warnings) = load.execute(
            LoadLibrariesRequest(root: "/project")
        ) else {
            Issue.record("a library that only warns did not load")
            return
        }

        let warning = try #require(warnings.first)
        #expect(warning.message.contains("bare"))
    }

    @Test func saysSoWhenTheRootIsNotAProject() {
        let load = aProject([:])

        guard case .notAProject = load.execute(LoadLibrariesRequest(root: "/nowhere")) else {
            Issue.record("a root that is not a project did not say so")
            return
        }
    }
}
