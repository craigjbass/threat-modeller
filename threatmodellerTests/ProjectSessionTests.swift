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

/// What a project window writes back: the architecture, the answers, and the
/// report when a person asks for it.
@MainActor
struct ProjectAnswerTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func aProject() -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(useCases: useCases)
        session.open(root: "/work")
        return (session, useCases)
    }

    @Test func writesTheAnswersBesideTheArchitecture() throws {
        let (session, useCases) = aProject()

        session.save()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.hasPrefix("controls for \"Payments\" {"))
        #expect(written.contains("status = \"not_implemented\""))
        #expect(session.unansweredThreats > 0)
        #expect(session.errorMessage == nil)
    }

    @Test func carriesAnAnswerFromTheSidebarIntoTheFile() throws {
        let (session, useCases) = aProject()
        let control = try #require(session.model?.threats.first?.controls.first)

        session.model?.setControlStatus(key: control.key, statusId: "accepted")
        session.save()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("status = \"accepted\""))
    }

    @Test func carriesACompensatingControlIntoTheFile() throws {
        let (session, useCases) = aProject()
        let threat = try #require(session.model?.threats.first)

        session.model?.setCompensatingControl(
            threatKey: "\(threat.threatId)@\(threat.source.id)",
            label: "Watched by the SIEM",
            reducesRiskBy: 50,
            rationale: "It alerts on use."
        )
        session.save()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("compensating \"Watched by the SIEM\" {"))
        #expect(written.contains("reduces_risk_by = 50"))
        #expect(written.contains("rationale       = \"It alerts on use.\""))
        // The score on screen followed.
        let after = try #require(session.model?.threats.first { $0.threatId == threat.threatId })
        #expect(after.riskScore < threat.riskScore)
    }

    @Test func writesTheReportOnlyWhenAsked() throws {
        let (session, useCases) = aProject()

        session.save()
        #expect(useCases.project.text(at: "/work/threatmodel/payments.md") == nil)

        session.compileReport()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.md"))
        #expect(written.hasPrefix("# Payments\n"))
        #expect(session.reportPath == "/work/threatmodel/payments.md")
    }

    @Test func readsBackTheAnswersItWrote() throws {
        let (session, useCases) = aProject()
        let control = try #require(session.model?.threats.first?.controls.first)
        session.model?.setControlStatus(key: control.key, statusId: "implemented")
        session.save()

        // A second application, reading only what is on disk.
        let reader = TestDependencies()
        reader.project.put(payments, at: "/work/threatmodel/payments.arch")
        reader.project.put(
            try #require(useCases.project.text(at: "/work/threatmodel/payments.controls")),
            at: "/work/threatmodel/payments.controls"
        )
        let second = ProjectSession(useCases: reader)
        second.open(root: "/work")

        #expect(second.model?.summary.controlsRecorded == 1)
    }
}

/// A project directory with nothing in it. The application offers to write an
/// example rather than showing an empty window.
@MainActor
struct EmptyProjectTests {
    private func anEmptyRoot() -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put("a readme", at: "/work/README.md")
        let session = ProjectSession(useCases: useCases)
        session.open(root: "/work")
        return (session, useCases)
    }

    @Test func offersToWriteAnExample() {
        let (session, _) = anEmptyRoot()

        #expect(session.canInitialise)
        #expect(session.examples.isEmpty == false)
        #expect(session.errorMessage?.contains("Start from an example") == true)
    }

    @Test func writesTheExampleAndDrawsIt() throws {
        let (session, useCases) = anEmptyRoot()

        session.initialise(sampleId: FakeSampleModels.sampleId)

        #expect(session.canInitialise == false)
        #expect(session.systems == [FakeSampleModels.sampleId])
        #expect(session.chosenSystem == FakeSampleModels.sampleId)
        #expect(session.model?.canvas.components.isEmpty == false)
        #expect(session.model?.threats.isEmpty == false)
        #expect(session.errorMessage == nil)
        let written = try #require(
            useCases.project.text(at: "/work/threatmodel/\(FakeSampleModels.sampleId).arch")
        )
        #expect(written.hasPrefix("system \"One Component\" {"))
    }

    @Test func writesTheFirstExampleWhenTheUserNamesNone() {
        let (session, _) = anEmptyRoot()

        session.initialise()

        #expect(session.systems.isEmpty == false)
    }

    @Test func offersNothingWhenTheProjectAlreadyHoldsASystem() {
        let useCases = TestDependencies()
        useCases.project.put("system \"Mine\" { }", at: "/work/threatmodel/mine.arch")
        let session = ProjectSession(useCases: useCases)

        session.open(root: "/work")

        #expect(session.canInitialise == false)
    }

    @Test func neverWritesOverASystemThatIsAlreadyThere() throws {
        let useCases = TestDependencies()
        useCases.project.put("system \"Mine\" { }", at: "/work/threatmodel/mine.arch")
        let session = ProjectSession(useCases: useCases)
        session.open(root: "/work")

        session.initialise()

        #expect(session.errorMessage == "This project already holds mine.")
        #expect(useCases.project.text(at: "/work/threatmodel/mine.arch") == "system \"Mine\" { }")
    }

    @Test func saysSoWhenTheExampleIsGone() {
        let (session, _) = anEmptyRoot()

        session.initialise(sampleId: "no-such-example")

        #expect(session.errorMessage == "This application no longer holds that example.")
        #expect(session.canInitialise)
    }

    @Test func offersNothingWhenNoProjectIsOpen() {
        let session = ProjectSession(useCases: TestDependencies())

        #expect(session.canInitialise == false)
    }
}
