import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The project session is the translator for a project window. These tests run
/// it over a project held in memory, so no test touches a disk.
@MainActor
struct ProjectSessionTests {
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

    private func aProject() -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        useCases.project.put("system \"Reporting\" { component \"r\" { technology = \"aws-rds\" } }",
                             at: "/work/threatmodel/reporting.arch")
        return (ProjectSession(useCases: useCases), useCases)
    }

    @Test func listsTheSystemsAndDrawsTheFirst() {
        let (session, _) = aProject()

        session.open(root: "/work")

        #expect(session.systems == ["payments", "reporting"])
        #expect(session.chosenSystem == "payments")
        #expect(session.model?.canvas.components.map(\.id) == ["api"])
        #expect(session.errorMessage == nil)
    }

    @Test func drawsTheSystemTheUserPicked() {
        let (session, _) = aProject()
        session.open(root: "/work")

        session.choose("reporting")

        #expect(session.chosenSystem == "reporting")
        #expect(session.model?.canvas.components.map(\.technologyId) == ["aws-rds"])
    }

    @Test func writesTheDrawnSystemBackToItsFile() throws {
        let (session, useCases) = aProject()
        session.open(root: "/work")
        session.model?.add(technologyId: "aws-rds", x: 900, y: 700)

        session.save()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.arch"))
        #expect(written.contains("technology = \"aws-rds\""))
        #expect(session.errorMessage == nil)
    }

    @Test func drawsNothingWhenAFileDidNotParse() {
        let useCases = TestDependencies()
        useCases.project.put(
            "system \"Broken\" {\n  zone \"z\" {\n    kind = \"secret\"\n  }\n}",
            at: "/work/threatmodel/broken.arch"
        )
        let session = ProjectSession(useCases: useCases)

        session.open(root: "/work")

        #expect(session.model == nil)
        #expect(session.hasErrors)
        #expect(session.diagnosticsFileName == "broken.arch")
        #expect(session.diagnostics.first?.line == 3)
        #expect(session.errorMessage == "broken.arch did not parse.")
    }

    @Test func drawsAFileThatOnlyWarns() {
        let useCases = TestDependencies()
        useCases.project.put(
            "system \"P\" {\n  zone \"empty\" { }\n  component \"a\" { technology = \"aws-ec2\" }\n}",
            at: "/work/threatmodel/p.arch"
        )
        let session = ProjectSession(useCases: useCases)

        session.open(root: "/work")

        #expect(session.hasErrors == false)
        #expect(session.diagnostics.count == 1)
        #expect(session.model?.canvas.components.count == 1)
    }

    @Test func saysSoWhenTheRootIsNotAProject() {
        let session = ProjectSession(useCases: TestDependencies())

        session.open(root: "/nowhere")

        #expect(session.model == nil)
        #expect(session.errorMessage?.hasPrefix("That is not a project:") == true)
    }

    @Test func saysSoWhenAProjectHoldsNoArchitectureFiles() {
        let useCases = TestDependencies()
        useCases.project.put("a readme", at: "/work/README.md")
        let session = ProjectSession(useCases: useCases)

        session.open(root: "/work")

        #expect(session.systems.isEmpty)
        #expect(session.errorMessage?.contains("holds no .arch files") == true)
    }

    @Test func readsAProjectPathOffTheCommandLine() {
        #expect(ProjectLaunchArgument.path(in: ["app", "-project", "/work"]) == "/work")
        #expect(ProjectLaunchArgument.path(in: ["app"]) == nil)
        #expect(ProjectLaunchArgument.path(in: ["app", "-project"]) == nil)
    }
}
