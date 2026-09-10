import ArchitectureDSL
import CatalogueGateways
import FileGateways
import Foundation
import Testing
import ThreatModelKit

/// Proves Tasks 1 to 12 as one path: a `.lib` threat and an `.arch` system,
/// through `compile`, `check` and `report`, over real files in a temporary
/// directory.
///
/// The vendored catalogue holds no threat this story needs, so the project
/// declares its own in a `.lib` file, the way `UsingASharedLibraryTests`
/// does. `Library.build` prefixes every id with the library's label, so the
/// architecture names `endpoint-laptop` and `endpoint-sip-bypass`, not the
/// bare ids the `.lib` file states.
struct LikelihoodEndToEndTests {
    private let library = """
    library "endpoint" {
      name = "Endpoint Security"

      technology "laptop" {
        name     = "Developer Laptop"
        category = "compute"
        threats  = ["sip-bypass"]
      }

      threat "sip-bypass" {
        name     = "SIP Bypass"
        severity = "high"
      }
    }
    """

    /// A high severity on restricted data scores 12, the floor of the
    /// critical band. `research` cuts it by three quarters to 3, inside
    /// `risk_tolerance = "low"`. The `baseline` component carries the same
    /// technology with its own threats turned off, so it exists only to be
    /// the mitigation's source.
    private let architecture = """
    system "ClearanceKit" {
      risk_tolerance = "low"

      assumption "mdm-push" {
        text  = "the hardening baseline is written, and MDM has not pushed it yet"
        owner = "platform team"
      }

      component "laptop" {
        technology = "endpoint-laptop"
        data       = "restricted"
      }

      component "baseline" {
        technology = "endpoint-laptop"
        threats    = false
      }

      mitigates baseline -> laptop {
        threats         = ["endpoint-sip-bypass"]
        reduces_risk_by = 60
        status          = "assumed"
      }
    }
    """

    @Test func compilesChecksAndReports() throws {
        let manager = FileManager.default
        let root = manager.temporaryDirectory
            .appendingPathComponent("threat-modeller-likelihood-\(UUID().uuidString)")
        try manager.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: root) }

        let projects = FileSystemProject()
        let architectureSources = HclArchitectureSource()
        let controlsSources = HclControlsSource()

        try projects.write(architecture, to: "\(root.path)/threatmodel/clearancekit.arch")
        try projects.write(library, to: "\(root.path)/threatmodel/library/endpoint.lib")

        let catalogue = try BundledTechnologyCatalogue()
        let store = LibraryStore()
        guard case .loaded(let libraries, let libraryWarnings) = LoadLibraries(
            projects: projects,
            sources: HclLibrarySource(),
            catalogue: catalogue
        ).execute(LoadLibrariesRequest(root: root.path)) else {
            Issue.record("the library did not load")
            return
        }
        // The threat states no control on purpose: this story answers it with
        // a likelihood finding, never a control, so the library's own warning
        // that nothing can answer it is expected, not a fault.
        #expect(libraryWarnings.count == 1)
        #expect(libraryWarnings.first?.message.contains("sip-bypass") == true)
        store.set(libraries)
        let merged = MergedCatalogue(base: catalogue, store: store)

        let layout = try projects.discover(root: root.path)
        let system = try #require(layout.systems.first)
        let architectureText = try projects.read(path: system.architecturePath)

        // Step 1: compile writes the tolerance.
        let compiles = CompileControls(
            catalogue: merged,
            architectureSources: architectureSources,
            controlsSources: controlsSources,
            layout: LayOutModel()
        )
        guard case .compiled(let stub, _, let firstUnanswered, _) = compiles.execute(
            CompileControlsRequest(architectureText: architectureText)
        ) else {
            Issue.record("the first compile did not write a stub")
            return
        }
        #expect(firstUnanswered == 1)
        #expect(stub.contains("tolerance = \"low\""))
        #expect(stub.contains("threat \"endpoint-sip-bypass\" on component \"laptop\" {"))
        try projects.write(stub, to: system.controlsPath)

        // Step 2: check exits 1 without a likelihood finding.
        let checks = CheckControlAnswers(compiles: compiles, sources: controlsSources)
        guard case .checked(let unanswered, _, _, let usedTolerance) = checks.execute(
            CheckControlAnswersRequest(architectureText: architectureText, controlsText: stub)
        ) else {
            Issue.record("the first check refused the files")
            return
        }
        #expect(usedTolerance == "low")
        #expect(unanswered.contains { $0.threatId == "endpoint-sip-bypass" })

        // A likelihood finding of "research" cuts the score of 12 to 3, which
        // sits inside the "low" tolerance.
        let answered = stub.replacingOccurrences(
            of: "score    = 12\n  }",
            with: """
            score    = 12

                likelihood "no in-the-wild use" {
                  tier      = "research"
                  rationale = "no known exploitation, per the vendor advisory"
                  sources   = ["https://example.test/advisory"]
                }
              }
            """
        )
        #expect(answered != stub, "the score line was not where the test expected it")

        // Step 3: check passes once the finding sits inside the tolerance.
        guard case .checked(let none, _, _, _) = checks.execute(
            CheckControlAnswersRequest(architectureText: architectureText, controlsText: answered)
        ) else {
            Issue.record("the second check refused the files")
            return
        }
        #expect(none.isEmpty)
        try projects.write(answered, to: system.controlsPath)

        // The block's removal is still unanswered, so a build without it
        // still fails.
        guard case .checked(let stillUnanswered, _, _, _) = checks.execute(
            CheckControlAnswersRequest(architectureText: architectureText, controlsText: stub)
        ) else {
            Issue.record("the third check refused the files")
            return
        }
        #expect(stillUnanswered.isEmpty == false)

        // Step 4: report holds the Assumptions section, the Likelihood line
        // and the target posture the assumed edge buys.
        let models = InMemoryThreatModelGateway()
        let imported = ImportArchitecture(
            models: models,
            catalogue: merged,
            sources: architectureSources,
            layout: LayOutModel()
        ).execute(ImportArchitectureRequest(text: architectureText))
        guard case .imported = imported else {
            Issue.record("the report's import refused the architecture: \(imported)")
            return
        }
        let applied = ApplyControlAnswers(models: models, catalogue: merged, sources: controlsSources)
            .execute(ApplyControlAnswersRequest(text: answered))
        guard case .applied = applied else {
            Issue.record("the answers did not apply: \(applied)")
            return
        }

        let markdown = ExportModelAsMarkdown(
            reports: BuildThreatModelReport(models: models, catalogue: merged)
        ).execute(ExportModelAsMarkdownRequest()).markdown
        try projects.write(markdown, to: system.reportPath)

        #expect(markdown.contains("## Assumptions"))
        #expect(
            markdown.contains(
                "- mdm-push: the hardening baseline is written, and MDM has not pushed it yet"
                    + " (platform team)"
            )
        )
        #expect(markdown.contains("- Likelihood: Research (12 \u{2192} 3)"))
        #expect(markdown.contains("- If the assumptions hold: 1"))
    }
}
