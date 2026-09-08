import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

@Suite("Starting a project that holds nothing")
struct InitialiseProjectTests {
    private let app = TestDependencies()

    private func initialise(
        root: String = "/work",
        sampleId: String? = nil
    ) -> InitialiseProjectResponse {
        app.initialiseProject().execute(
            InitialiseProjectRequest(root: root, sampleId: sampleId)
        )
    }

    /// The fake project has a root and nothing in it.
    private func anEmptyRoot() {
        app.project.put("a readme", at: "/work/README.md")
    }

    @Test func writesAnExampleIntoAnEmptyRoot() throws {
        anEmptyRoot()

        let response = initialise()

        guard case .created(let systemName, let path) = response else {
            Issue.record("expected an example to be written, got \(response)")
            return
        }
        #expect(systemName == FakeSampleModels.sampleId)
        #expect(path == "/work/threatmodel/\(FakeSampleModels.sampleId).arch")
        let written = try #require(app.project.text(at: path))
        #expect(written.hasPrefix("system \"One Component\" {"))
    }

    @Test func writesSomethingTheApplicationCanOpen() throws {
        anEmptyRoot()
        _ = initialise()

        let opened = app.openProject().execute(OpenProjectRequest(root: "/work"))

        #expect(
            opened == .opened(systems: [FakeSampleModels.sampleId], directory: "/work/threatmodel")
        )
        let drawn = app.openSystem().execute(
            OpenSystemRequest(root: "/work", systemName: FakeSampleModels.sampleId)
        )
        #expect(drawn == .opened(name: "One Component", warnings: []))
        #expect(
            app.viewThreatModel().execute(ViewThreatModelRequest()).components.isEmpty == false
        )
        #expect(app.assessThreatModel().execute(AssessThreatModelRequest()).threats.isEmpty == false)
    }

    @Test func neverWritesOverASystemThatIsAlreadyThere() throws {
        app.project.put("system \"Mine\" { }", at: "/work/threatmodel/mine.arch")

        let response = initialise()

        #expect(response == .alreadyHasSystems(names: ["mine"]))
        #expect(app.project.text(at: "/work/threatmodel/mine.arch") == "system \"Mine\" { }")
    }

    @Test func refusesARootThatIsNotADirectory() {
        let response = initialise(root: "/nowhere")

        guard case .notAProject(let reason) = response else {
            Issue.record("expected .notAProject, got \(response)")
            return
        }
        #expect(reason.contains("/nowhere"))
    }

    @Test func refusesAnExampleThisApplicationDoesNotHold() {
        anEmptyRoot()

        #expect(initialise(sampleId: "no-such-example") == .noSuchSample)
        #expect(app.project.text(at: "/work/threatmodel/no-such-example.arch") == nil)
    }

    @Test func writesTheExampleTheUserPicked() throws {
        anEmptyRoot()

        let response = initialise(sampleId: FakeSampleModels.sampleId)

        guard case .created(let systemName, _) = response else {
            Issue.record("expected an example to be written, got \(response)")
            return
        }
        #expect(systemName == FakeSampleModels.sampleId)
    }
}
