import Testing
import ThreatModelKit
import TestSupport

@Suite("Opening and saving a system in a project")
struct ProjectUseCaseTests {
    private let app = TestDependencies()

    private let payments = """
    system "Payments" {
      zone "app" {
        kind    = "private"
        network = "vpc"

        component "api" {
          technology = "aws-ec2"
          data       = "confidential"
        }
      }
    }

    """

    private func aProject() {
        app.project.put(payments, at: "/project/threatmodel/payments.arch")
        app.project.put("system \"Reporting\" { }", at: "/project/threatmodel/reporting.arch")
    }

    @Test func listsTheSystemsAProjectHolds() {
        aProject()

        let response = app.openProject().execute(OpenProjectRequest(root: "/project"))

        #expect(
            response == .opened(systems: ["payments", "reporting"], directory: "/project/threatmodel")
        )
    }

    @Test func saysSoWhenTheRootIsNotADirectory() {
        let response = app.openProject().execute(OpenProjectRequest(root: "/nowhere"))

        guard case .notAProject(let reason) = response else {
            Issue.record("expected .notAProject, got \(response)")
            return
        }
        #expect(reason.contains("/nowhere"))
    }

    @Test func drawsTheSystemTheUserChose() {
        aProject()

        let response = app.openSystem().execute(
            OpenSystemRequest(root: "/project", systemName: "payments")
        )

        #expect(response == .opened(name: "Payments", warnings: []))
        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.map(\.id) == ["api"])
        #expect(view.zones.map(\.id) == ["app"])
    }

    @Test func refusesASystemWhoseFileHasAFault() throws {
        app.project.put(
            "system \"Broken\" {\n  component \"a\" { data = \"public\" }\n}",
            at: "/project/threatmodel/broken.arch"
        )

        let response = app.openSystem().execute(
            OpenSystemRequest(root: "/project", systemName: "broken")
        )

        guard case .refused(let fileName, let diagnostics) = response else {
            Issue.record("expected .refused, got \(response)")
            return
        }
        #expect(fileName == "broken.arch")
        #expect(diagnostics.isEmpty == false)
        #expect(diagnostics[0].described(in: fileName).hasPrefix("broken.arch:"))
    }

    @Test func refusesASystemTheProjectDoesNotHold() {
        aProject()

        #expect(
            app.openSystem().execute(OpenSystemRequest(root: "/project", systemName: "ghost"))
                == .noSuchSystem
        )
    }

    @Test func writesTheModelBackToTheFileItCameFrom() throws {
        aProject()
        _ = app.openSystem().execute(OpenSystemRequest(root: "/project", systemName: "payments"))
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 4000, y: 4000, sensitivity: "restricted")
        )

        let response = app.saveSystem().execute(
            SaveSystemRequest(root: "/project", systemName: "payments")
        )

        #expect(response == .saved(architecturePath: "/project/threatmodel/payments.arch"))
        let written = try #require(app.project.text(at: "/project/threatmodel/payments.arch"))
        #expect(written.contains("technology = \"aws-rds\""))
        #expect(written.contains("technology = \"aws-ec2\""))
    }

    @Test func refusesToSaveASystemTheProjectDoesNotHold() {
        aProject()

        #expect(
            app.saveSystem().execute(SaveSystemRequest(root: "/project", systemName: "ghost"))
                == .noSuchSystem
        )
    }
}
