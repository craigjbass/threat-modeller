import CoreGraphics
import Foundation
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// A defaults suite made for one test, so nothing a test writes reaches the
/// user's own defaults.
@MainActor
func aTestDefaults() -> UserDefaults {
    let suite = "project-session-test-\(testDefaultsCount)"
    testDefaultsCount += 1
    let defaults = UserDefaults(suiteName: suite)!
    defaults.removePersistentDomain(forName: suite)
    return defaults
}

@MainActor
private var testDefaultsCount = 0

/// A watcher a test drives by hand.
@MainActor
final class FakeProjectWatcher: ProjectWatching {
    private(set) var watchedDirectory: String?
    private var onChange: (() -> Void)?

    func watch(directory: String, onChange: @escaping () -> Void) {
        watchedDirectory = directory
        self.onChange = onChange
    }

    func stop() {
        watchedDirectory = nil
        onChange = nil
    }

    /// What the real watcher calls when a file changes.
    func fire() { onChange?() }
}

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

    private func aProject() async -> (ProjectSession, TestDependencies) {
        let (session, useCases, _) = await aWatchedProject()
        return (session, useCases)
    }

    private func aWatchedProject() async -> (ProjectSession, TestDependencies, FakeProjectWatcher) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        useCases.project.put("system \"Reporting\" { component \"r\" { technology = \"aws-rds\" } }",
                             at: "/work/threatmodel/reporting.arch")
        let watcher = FakeProjectWatcher()
        return (ProjectSession(useCases: useCases, watcher: watcher, defaults: aTestDefaults()), useCases, watcher)
    }

    // MARK: opening one of a project's own files

    /// A user double-clicks a system's file in Finder. This application opens
    /// projects, so the file has to open the project that holds it, on that
    /// system.
    @Test func opensTheProjectAroundASystemFileAndDrawsThatSystem() async {
        let (session, _) = await aProject()

        let opened = await session.openSystemFile(at: "/work/threatmodel/reporting.arch")

        #expect(opened)
        #expect(session.root == "/work")
        #expect(session.chosenSystem == "reporting")
    }

    @Test func opensTheSameProjectFromASystemsControlsFile() async {
        let (session, _) = await aProject()

        let opened = await session.openSystemFile(at: "/work/threatmodel/reporting.controls")

        #expect(opened)
        #expect(session.chosenSystem == "reporting")
    }

    @Test func opensNothingForAFileThisApplicationDoesNotRead() async {
        let (session, _) = await aProject()

        let opened = await session.openSystemFile(at: "/work/notes.txt")

        #expect(opened == false)
        #expect(session.root == nil)
    }

    @Test func listsTheSystemsAndDrawsTheFirst() async {
        let (session, _) = await aProject()

        await session.open(root: "/work")

        #expect(session.systems == ["payments", "reporting"])
        #expect(session.chosenSystem == "payments")
        #expect(session.model?.canvas.components.map(\.id) == ["api"])
        #expect(session.errorMessage == nil)
    }

    // MARK: what the window is told while a load runs

    @Test func saysNothingIsLoadingOnceAProjectIsOpen() async {
        let (session, _) = await aProject()

        await session.open(root: "/work")

        #expect(session.loading == nil)
    }

    /// Picking a system goes straight to choose, which had no way of saying it
    /// had finished. The window draws the stage instead of the diagram, so a
    /// stage left behind hides the diagram for good.
    @Test func saysNothingIsLoadingOnceASystemIsPicked() async {
        let (session, _) = await aProject()
        await session.open(root: "/work")

        await session.choose("reporting")

        #expect(session.chosenSystem == "reporting")
        #expect(session.loading == nil)
    }

    @Test func saysNothingIsLoadingWhenASystemDidNotParse() async {
        let useCases = TestDependencies()
        useCases.project.put("system \"Broken\" {", at: "/work/threatmodel/broken.arch")
        let session = ProjectSession(useCases: useCases, watcher: FakeProjectWatcher(), defaults: aTestDefaults())

        await session.open(root: "/work")

        #expect(session.loading == nil)
    }

    @Test func drawsTheSystemTheUserPicked() async {
        let (session, _) = await aProject()
        await session.open(root: "/work")

        await session.choose("reporting")

        #expect(session.chosenSystem == "reporting")
        #expect(session.model?.canvas.components.map(\.technologyId) == ["aws-rds"])
    }

    @Test func writesTheDrawnSystemBackToItsFile() async throws {
        let (session, useCases) = await aProject()
        await session.open(root: "/work")
        session.model?.add(technologyId: "aws-rds", x: 900, y: 700)

        await session.save()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.arch"))
        #expect(written.contains("technology = \"aws-rds\""))
        #expect(session.errorMessage == nil)
    }

    @Test func drawsNothingWhenAFileDidNotParse() async {
        let useCases = TestDependencies()
        useCases.project.put(
            "system \"Broken\" {\n  zone \"z\" {\n    kind = \"secret\"\n  }\n}",
            at: "/work/threatmodel/broken.arch"
        )
        let session = ProjectSession(useCases: useCases, defaults: aTestDefaults())

        await session.open(root: "/work")

        #expect(session.model == nil)
        #expect(session.hasErrors)
        #expect(session.diagnosticsFileName == "broken.arch")
        #expect(session.diagnostics.first?.line == 3)
        #expect(session.errorMessage == "broken.arch did not parse.")
    }

    @Test func drawsAFileThatOnlyWarns() async {
        let useCases = TestDependencies()
        useCases.project.put(
            "system \"P\" {\n  zone \"empty\" { }\n  component \"a\" { technology = \"aws-ec2\" }\n}",
            at: "/work/threatmodel/p.arch"
        )
        let session = ProjectSession(useCases: useCases, defaults: aTestDefaults())

        await session.open(root: "/work")

        #expect(session.hasErrors == false)
        #expect(session.diagnostics.count == 1)
        #expect(session.model?.canvas.components.count == 1)
    }

    @Test func saysSoWhenTheRootIsNotAProject() async {
        let session = ProjectSession(useCases: TestDependencies(), defaults: aTestDefaults())

        await session.open(root: "/nowhere")

        #expect(session.model == nil)
        #expect(session.errorMessage?.hasPrefix("That is not a project:") == true)
    }

    @Test func saysSoWhenAProjectHoldsNoArchitectureFiles() async {
        let useCases = TestDependencies()
        useCases.project.put("a readme", at: "/work/README.md")
        let session = ProjectSession(useCases: useCases, defaults: aTestDefaults())

        await session.open(root: "/work")

        #expect(session.systems.isEmpty)
        #expect(session.errorMessage?.contains("holds no .arch files") == true)
    }

    @Test func readsAProjectPathOffTheCommandLine() async {
        #expect(ProjectLaunchArgument.path(in: ["app", "-project", "/work"]) == "/work")
        #expect(ProjectLaunchArgument.path(in: ["app"]) == nil)
        #expect(ProjectLaunchArgument.path(in: ["app", "-project"]) == nil)
    }

    // MARK: following the files

    @Test func watchesTheProjectDirectory() async {
        let (session, _, watcher) = await aWatchedProject()

        await session.open(root: "/work")

        #expect(watcher.watchedDirectory == "/work/threatmodel")
    }

    @Test func doesNothingWhenTheFilesDidNotChange() async {
        let (session, _, watcher) = await aWatchedProject()
        await session.open(root: "/work")
        let drawn = session.model

        watcher.fire()

        await session.settle()

        #expect(session.model === drawn)
        #expect(session.hasFilesChangedOnDisk == false)
    }

    @Test func redrawsWhenTheFilesChangedAndNothingIsUnsaved() async {
        let (session, useCases, watcher) = await aWatchedProject()
        await session.open(root: "/work")
        useCases.project.put(
            """
            system "Payments" {
              zone "app" {
                kind    = "private"
                network = "vpc"

                component "api" {
                  technology = "aws-ec2"
                  data       = "confidential"
                }

                component "db" {
                  technology = "aws-rds"
                  data       = "confidential"
                }
              }
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )

        watcher.fire()

        await session.settle()

        #expect(session.model?.canvas.components.map(\.id) == ["api", "db"])
        #expect(session.hasFilesChangedOnDisk == false)
    }

    @Test func asksWhenTheFilesChangedAndSomethingIsUnsaved() async {
        let (session, useCases, watcher) = await aWatchedProject()
        await session.open(root: "/work")
        session.model?.addAtDefaultPoint(technologyId: "aws-rds")
        let drawn = session.model
        useCases.project.put(
            "system \"Payments\" { component \"other\" { technology = \"aws-rds\" } }",
            at: "/work/threatmodel/payments.arch"
        )

        watcher.fire()

        await session.settle()

        #expect(session.hasUnsavedChanges)
        #expect(session.hasFilesChangedOnDisk)
        #expect(session.model === drawn)
    }

    private func aWatchedSplitProject() async -> (ProjectSession, TestDependencies, FakeProjectWatcher) {
        let useCases = TestDependencies()
        useCases.project.put(
            "system \"Payments\" { }",
            at: "/work/threatmodel/payments/arch/payments.arch"
        )
        useCases.project.put(
            "component \"api\" { technology = \"aws-ec2\" }",
            at: "/work/threatmodel/payments/arch/edge.arch"
        )
        let watcher = FakeProjectWatcher()
        return (ProjectSession(useCases: useCases, watcher: watcher, defaults: aTestDefaults()), useCases, watcher)
    }

    @Test func redrawsWhenAPartFileOfASplitSystemChanges() async {
        let (session, useCases, watcher) = await aWatchedSplitProject()
        await session.open(root: "/work")

        useCases.project.put(
            """
            component "api" { technology = "aws-ec2" }

            component "db" { technology = "aws-rds" }
            """,
            at: "/work/threatmodel/payments/arch/edge.arch"
        )

        watcher.fire()
        await session.settle()

        #expect(session.model?.canvas.components.map(\.id).sorted() == ["api", "db"])
        #expect(session.hasFilesChangedOnDisk == false)
    }

    @Test func redrawsWhenTheHeaderFileOfASplitSystemChanges() async {
        let (session, useCases, watcher) = await aWatchedSplitProject()
        await session.open(root: "/work")

        useCases.project.put(
            "system \"Payments\" { risk_tolerance = \"low\" }",
            at: "/work/threatmodel/payments/arch/payments.arch"
        )

        watcher.fire()
        await session.settle()

        #expect(session.hasFilesChangedOnDisk == false)
    }

    @Test func reloadsWhenTheUserAsksForIt() async {
        let (session, useCases, watcher) = await aWatchedProject()
        await session.open(root: "/work")
        session.model?.addAtDefaultPoint(technologyId: "aws-rds")
        useCases.project.put(
            "system \"Payments\" { component \"other\" { technology = \"aws-rds\" } }",
            at: "/work/threatmodel/payments.arch"
        )
        watcher.fire()
        await session.settle()

        await session.reloadFromDisk()

        #expect(session.model?.canvas.components.map(\.id) == ["other"])
        #expect(session.hasFilesChangedOnDisk == false)
    }

    @Test func keepsWhatIsOnScreenWhenTheUserAsksForThat() async {
        let (session, useCases, watcher) = await aWatchedProject()
        await session.open(root: "/work")
        session.model?.addAtDefaultPoint(technologyId: "aws-rds")
        let drawn = session.model
        useCases.project.put(
            "system \"Payments\" { component \"other\" { technology = \"aws-rds\" } }",
            at: "/work/threatmodel/payments.arch"
        )
        watcher.fire()
        await session.settle()

        session.keepMine()

        #expect(session.hasFilesChangedOnDisk == false)
        #expect(session.model === drawn)
    }

    @Test func doesNotRedrawAfterItsOwnSave() async {
        let (session, _, watcher) = await aWatchedProject()
        await session.open(root: "/work")
        session.model?.addAtDefaultPoint(technologyId: "aws-rds")
        await session.save()
        let drawn = session.model

        watcher.fire()

        await session.settle()

        #expect(session.model === drawn)
        #expect(session.hasFilesChangedOnDisk == false)
        #expect(session.hasUnsavedChanges == false)
    }

    @Test func aReloadKeepsTheChosenSystem() async {
        let (session, useCases, watcher) = await aWatchedProject()
        await session.open(root: "/work")
        await session.choose("reporting")
        useCases.project.put(
            "system \"Reporting\" { component \"r2\" { technology = \"aws-rds\" } }",
            at: "/work/threatmodel/reporting.arch"
        )

        watcher.fire()

        await session.settle()

        #expect(session.chosenSystem == "reporting")
        #expect(session.model?.canvas.components.map(\.id) == ["r2"])
    }

    // MARK: the auto sync switch

    @Test func startsWithAutoSyncOn() async {
        let (session, _, _) = await aWatchedProject()

        #expect(session.isAutoSyncOn)
    }

    @Test func doesNotRedrawWhileAutoSyncIsOff() async {
        let (session, useCases, watcher) = await aWatchedProject()
        await session.open(root: "/work")
        session.isAutoSyncOn = false
        let drawn = session.model
        useCases.project.put(
            "system \"Payments\" { component \"other\" { technology = \"aws-rds\" } }",
            at: "/work/threatmodel/payments.arch"
        )

        watcher.fire()

        await session.settle()

        #expect(session.model === drawn)
        #expect(session.hasFilesChangedOnDisk)
    }

    @Test func redrawsWhenAutoSyncIsTurnedBackOn() async {
        let (session, useCases, watcher) = await aWatchedProject()
        await session.open(root: "/work")
        session.isAutoSyncOn = false
        useCases.project.put(
            "system \"Payments\" { component \"other\" { technology = \"aws-rds\" } }",
            at: "/work/threatmodel/payments.arch"
        )
        watcher.fire()
        await session.settle()

        session.isAutoSyncOn = true
        await session.settle()

        #expect(session.model?.canvas.components.map(\.id) == ["other"])
        #expect(session.hasFilesChangedOnDisk == false)
    }

    @Test func leavesAnUnsavedModelAloneWhenAutoSyncIsTurnedBackOn() async {
        let (session, useCases, watcher) = await aWatchedProject()
        await session.open(root: "/work")
        session.isAutoSyncOn = false
        session.model?.addAtDefaultPoint(technologyId: "aws-rds")
        let drawn = session.model
        useCases.project.put(
            "system \"Payments\" { component \"other\" { technology = \"aws-rds\" } }",
            at: "/work/threatmodel/payments.arch"
        )
        watcher.fire()
        await session.settle()

        session.isAutoSyncOn = true

        #expect(session.model === drawn)
        #expect(session.hasFilesChangedOnDisk)
    }

    @Test func remembersTheSwitchForTheNextSession() async {
        let defaults = aTestDefaults()
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let first = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: defaults
        )

        first.isAutoSyncOn = false
        let second = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: defaults
        )

        #expect(second.isAutoSyncOn == false)
    }

    // MARK: what the last action did

    @Test func saysWhatTheSaveDid() async {
        let (session, _) = await aProject()
        await session.open(root: "/work")

        await session.save()

        #expect(session.lastActionMessage?.hasPrefix("Saved") == true)
    }

    @Test func saysWhereTheReportWent() async {
        let (session, _) = await aProject()
        await session.open(root: "/work")

        session.compileReport()

        #expect(session.lastActionMessage == "Report: \(session.reportPath ?? "")")
    }

    /// The message is read once and then goes, so the window never says
    /// "Saved." over a model the person has changed since.
    @Test func clearsTheMessageWhenTheWaitEnds() async {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let timer = FakeCoalescer()
        let session = ProjectSession(
            useCases: useCases,
            defaults: aTestDefaults(),
            messageTimer: timer
        )
        await session.open(root: "/work")

        session.compileReport()
        #expect(session.lastActionMessage != nil)
        timer.fire()

        #expect(session.lastActionMessage == nil)
    }

    @Test func aSecondMessageReplacesTheFirstAndStartsTheWaitAgain() async {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let timer = FakeCoalescer()
        let session = ProjectSession(
            useCases: useCases,
            defaults: aTestDefaults(),
            messageTimer: timer
        )
        await session.open(root: "/work")

        session.compileReport()
        await session.save()

        #expect(session.lastActionMessage?.hasPrefix("Saved") == true)
        #expect(timer.scheduledCount == 2)
        timer.fire()
        #expect(session.lastActionMessage == nil)
    }

    /// A load states what is happening now, so it takes the toolbar from a
    /// message that states what happened.
    @Test func aLoadStageAndAMessageNeverShowAtOnce() async {
        let (session, _) = await aProject()
        await session.open(root: "/work")
        session.compileReport()

        #expect(session.loading == nil)
        #expect(session.toolbarMessage == session.lastActionMessage)
        #expect(session.toolbarMessage != nil)
    }

    @Test func clearsTheMessageWhenAnotherSystemIsPicked() async {
        let (session, _) = await aProject()
        await session.open(root: "/work")
        session.compileReport()

        await session.choose("reporting")

        #expect(session.lastActionMessage == nil)
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

    private func aProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(useCases: useCases, defaults: aTestDefaults())
        await session.open(root: "/work")
        return (session, useCases)
    }

    @Test func writesTheAnswersBesideTheArchitecture() async throws {
        let (session, useCases) = await aProject()

        await session.save()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.hasPrefix("controls for \"Payments\" {"))
        #expect(written.contains("status = \"not_implemented\""))
        #expect(session.unansweredThreats > 0)
        #expect(session.errorMessage == nil)
    }

    @Test func carriesAnAnswerFromTheSidebarIntoTheFile() async throws {
        let (session, useCases) = await aProject()
        let control = try #require(session.model?.threats.first?.controls.first)

        session.model?.setControlStatus(key: control.key, statusId: "accepted")
        await session.save()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("status = \"accepted\""))
    }

    @Test func carriesACompensatingControlIntoTheFile() async throws {
        let (session, useCases) = await aProject()
        let threat = try #require(session.model?.threats.first)

        session.model?.setCompensatingControl(
            threatKey: "\(threat.threatId)@\(threat.source.id)",
            label: "Watched by the SIEM",
            reducesRiskBy: 50,
            rationale: "It alerts on use."
        )
        await session.save()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("compensating \"Watched by the SIEM\" {"))
        #expect(written.contains("reduces_risk_by = 50"))
        #expect(written.contains("rationale       = \"It alerts on use.\""))
        // The score on screen followed.
        let after = try #require(session.model?.threats.first { $0.threatId == threat.threatId })
        #expect(after.riskScore < threat.riskScore)
    }

    @Test func writesTheReportOnlyWhenAsked() async throws {
        let (session, useCases) = await aProject()

        await session.save()
        #expect(useCases.project.text(at: "/work/threatmodel/payments.md") == nil)

        session.compileReport()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.md"))
        #expect(written.hasPrefix("# Payments\n"))
        #expect(session.reportPath == "/work/threatmodel/payments.md")
    }

    @Test func readsBackTheAnswersItWrote() async throws {
        let (session, useCases) = await aProject()
        let control = try #require(session.model?.threats.first?.controls.first)
        session.model?.setControlStatus(key: control.key, statusId: "implemented")
        await session.save()

        // A second application, reading only what is on disk.
        let reader = TestDependencies()
        reader.project.put(payments, at: "/work/threatmodel/payments.arch")
        reader.project.put(
            try #require(useCases.project.text(at: "/work/threatmodel/payments.controls")),
            at: "/work/threatmodel/payments.controls"
        )
        let second = ProjectSession(useCases: reader, defaults: aTestDefaults())
        await second.open(root: "/work")

        #expect(second.model?.summary.controlsRecorded == 1)
    }
}

/// A project directory with nothing in it. The application offers to write an
/// example rather than showing an empty window.
@MainActor
struct EmptyProjectTests {
    private func anEmptyRoot() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put("a readme", at: "/work/README.md")
        let session = ProjectSession(useCases: useCases, defaults: aTestDefaults())
        await session.open(root: "/work")
        return (session, useCases)
    }

    @Test func offersToWriteAnExample() async {
        let (session, _) = await anEmptyRoot()

        #expect(session.canInitialise)
        #expect(session.examples.isEmpty == false)
        #expect(session.errorMessage?.contains("Name a system") == true)
    }

    @Test func writesTheExampleAndDrawsIt() async throws {
        let (session, useCases) = await anEmptyRoot()

        await session.initialise(sampleId: FakeSampleModels.sampleId)

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

    @Test func writesTheFirstExampleWhenTheUserNamesNone() async {
        let (session, _) = await anEmptyRoot()

        await session.initialise()

        #expect(session.systems.isEmpty == false)
    }

    @Test func offersNothingWhenTheProjectAlreadyHoldsASystem() async {
        let useCases = TestDependencies()
        useCases.project.put("system \"Mine\" { }", at: "/work/threatmodel/mine.arch")
        let session = ProjectSession(useCases: useCases, defaults: aTestDefaults())

        await session.open(root: "/work")

        #expect(session.canInitialise == false)
    }

    @Test func neverWritesOverASystemThatIsAlreadyThere() async throws {
        let useCases = TestDependencies()
        useCases.project.put("system \"Mine\" { }", at: "/work/threatmodel/mine.arch")
        let session = ProjectSession(useCases: useCases, defaults: aTestDefaults())
        await session.open(root: "/work")

        await session.initialise()

        #expect(session.errorMessage == "This project already holds mine.")
        #expect(useCases.project.text(at: "/work/threatmodel/mine.arch") == "system \"Mine\" { }")
    }

    @Test func saysSoWhenTheExampleIsGone() async {
        let (session, _) = await anEmptyRoot()

        await session.initialise(sampleId: "no-such-example")

        #expect(session.errorMessage == "This application no longer holds that example.")
        #expect(session.canInitialise)
    }

    // MARK: starting with nothing in it

    @Test func writesAnEmptySystemAndDrawsIt() async throws {
        let (session, useCases) = await anEmptyRoot()

        await session.initialiseEmpty(systemName: "Payments")

        #expect(session.canInitialise == false)
        #expect(session.systems == ["payments"])
        #expect(session.chosenSystem == "payments")
        #expect(session.model?.canvas.components.isEmpty == true)
        #expect(session.errorMessage == nil)
        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.arch"))
        #expect(written.hasPrefix("system \"Payments\" {"))
    }

    @Test func saysSoWhenTheSystemNameIsBlank() async {
        let (session, _) = await anEmptyRoot()

        await session.initialiseEmpty(systemName: "   ")

        #expect(session.errorMessage == "Give the system a name.")
        #expect(session.canInitialise)
    }

    /// The name a user is offered first. Typing the folder name again is work
    /// nobody needs, and the folder is usually what the system is called.
    @Test func offersTheFolderNameAsTheSystemName() async {
        let (session, _) = await anEmptyRoot()

        #expect(session.suggestedSystemName == "work")
    }

    @Test func offersNothingWhenNoProjectIsOpen() async {
        let session = ProjectSession(useCases: TestDependencies(), defaults: aTestDefaults())

        #expect(session.canInitialise == false)
    }
}


/// Laying the drawn diagram out again, from the View menu.
@MainActor
@Suite("Laying the diagram out again")
struct LayOutDiagramTests {
    private let payments = """
    system "Payments" {
      zone "app" {
        kind = "private"

        component "api" { technology = "aws-ec2" }
        component "db" { technology = "aws-rds" }
      }

      flow api -> db
    }

    """

    private func aProject() async -> ProjectSession {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return session
    }

    private func positions(_ session: ProjectSession) -> [String: CGPoint] {
        Dictionary(
            uniqueKeysWithValues: (session.model?.canvas.components ?? []).map {
                ($0.id, CGPoint(x: $0.x, y: $0.y))
            }
        )
    }

    @Test func oneUndoPutsEveryElementBack() async throws {
        let session = await aProject()
        let model = try #require(session.model)
        let ids = model.canvas.components.map(\.id)
        model.move(ids.map { ComponentMove(componentId: $0, x: 1500, y: 1500) })
        let scattered = positions(session)

        await session.layOutDiagram()
        #expect(positions(session) != scattered)

        model.undo()

        #expect(positions(session) == scattered)
        #expect(session.loading == nil)
    }

    @Test func layingOutTheSelectionMovesNothingElse() async throws {
        let session = await aProject()
        let model = try #require(session.model)
        let ids = model.canvas.components.map(\.id)
        model.move(ids.map { ComponentMove(componentId: $0, x: 1500, y: 1500) })
        let before = positions(session)

        await session.layOutDiagram(componentIds: [ids[0]], zoneIds: [])

        #expect(positions(session)[ids[1]] == before[ids[1]])
        #expect(positions(session)[ids[0]] != before[ids[0]])
    }
}

/// A coalescer a test drives by hand, so no test waits.
@MainActor
final class FakeCoalescer: ChangeCoalescing {
    private(set) var scheduledCount = 0
    private(set) var cancelledCount = 0
    private var work: (@MainActor () -> Void)?

    var hasPendingWork: Bool { work != nil }

    func schedule(_ work: @escaping @MainActor () -> Void) {
        scheduledCount += 1
        self.work = work
    }

    func cancel() {
        cancelledCount += 1
        work = nil
    }

    /// What the real coalescer does when the wait ends.
    func fire() {
        let pending = work
        work = nil
        pending?()
    }
}

/// What Auto Sync writes. With it on, a change on screen reaches the files
/// without the user pressing Synchronise.
@MainActor
struct AutomaticSaveTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func aProject() async -> (ProjectSession, TestDependencies, FakeCoalescer) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        useCases.project.put(
            "system \"Reporting\" { component \"r\" { technology = \"aws-rds\" } }",
            at: "/work/threatmodel/reporting.arch"
        )
        useCases.project.put(
            "system \"Other\" { component \"o\" { technology = \"aws-rds\" } }",
            at: "/other/threatmodel/other.arch"
        )
        let coalescer = FakeCoalescer()
        let session = ProjectSession(
            useCases: useCases,
            defaults: aTestDefaults(),
            coalescer: coalescer
        )
        await session.open(root: "/work")
        return (session, useCases, coalescer)
    }

    @Test func writesTheAnswersWhenAControlChangesAndAutoSyncIsOn() async throws {
        let (session, useCases, coalescer) = await aProject()
        let control = try #require(session.model?.threats.first?.controls.first)

        session.model?.setControlStatus(key: control.key, statusId: "accepted")
        coalescer.fire()
        await session.settle()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("status = \"accepted\""))
        #expect(session.hasUnsavedChanges == false)
    }

    @Test func writesNothingWhileAutoSyncIsOff() async {
        let (session, useCases, coalescer) = await aProject()
        session.isAutoSyncOn = false

        session.model?.add(technologyId: "aws-rds", x: 900, y: 700)

        #expect(coalescer.hasPendingWork == false)
        #expect(useCases.project.text(at: "/work/threatmodel/payments.controls") == nil)
        #expect(session.hasUnsavedChanges)
    }

    @Test func dropsAPendingWriteWhenAnotherSystemIsPicked() async {
        let (session, _, coalescer) = await aProject()
        session.model?.add(technologyId: "aws-rds", x: 900, y: 700)
        #expect(coalescer.hasPendingWork)

        await session.choose("reporting")

        #expect(coalescer.hasPendingWork == false)
    }

    @Test func dropsAPendingWriteWhenAutoSyncIsTurnedOff() async {
        let (session, _, coalescer) = await aProject()
        session.model?.add(technologyId: "aws-rds", x: 900, y: 700)
        #expect(coalescer.hasPendingWork)

        session.isAutoSyncOn = false

        #expect(coalescer.hasPendingWork == false)
    }

    @Test func dropsAPendingWriteWhenAnotherProjectIsOpened() async {
        let (session, _, coalescer) = await aProject()
        session.model?.add(technologyId: "aws-rds", x: 900, y: 700)
        #expect(coalescer.hasPendingWork)

        await session.open(root: "/other")

        #expect(coalescer.hasPendingWork == false)
    }
}

/// A project that holds a shared library. Its technologies and its threats
/// reach the palette and the sidebar the way the vendored catalogue's do.
@MainActor
struct ProjectLibraryTests {
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

    private func aProject(_ files: [String: String]) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        for (path, text) in files { useCases.project.put(text, at: path) }
        return (ProjectSession(useCases: useCases, defaults: aTestDefaults()), useCases)
    }

    @Test func raisesAThreatOnlyTheLibraryDefines() async throws {
        let (session, _) = await aProject([
            "/work/threatmodel/payments.arch": payments,
            "/work/threatmodel/library/acme.lib": acme
        ])

        await session.open(root: "/work")

        #expect(session.errorMessage == nil)
        let threats = try #require(session.model?.threats)
        #expect(threats.contains { $0.threatId == "acme-pipeline-tamper" })
    }

    @Test func showsTheLibraryAsItsOwnPaletteGroup() async {
        let (session, _) = await aProject([
            "/work/threatmodel/payments.arch": payments,
            "/work/threatmodel/library/acme.lib": acme
        ])

        await session.open(root: "/work")

        #expect(session.model?.palette.contains { $0.id == "acme" } == true)
        #expect(
            session.model?.palette.first { $0.id == "acme" }?.displayName == "Acme Platform"
        )
    }

    @Test func saysSoWhenALibraryDoesNotParse() async {
        let (session, _) = await aProject([
            "/work/threatmodel/payments.arch": payments,
            "/work/threatmodel/library/acme.lib": "library \"acme\" { nonsense }"
        ])

        await session.open(root: "/work")

        #expect(session.model == nil)
        #expect(session.diagnosticsFileName == "acme.lib")
        #expect(session.errorMessage?.contains("acme.lib") == true)
    }

    @Test func drawsAProjectThatHoldsNoLibrary() async {
        let (session, _) = await aProject([
            "/work/threatmodel/payments.arch": "system \"Payments\" { }"
        ])

        await session.open(root: "/work")

        #expect(session.errorMessage == nil)
        #expect(session.model != nil)
    }
}

/// The rules the project states for itself, as the window lists them beside
/// the diagnostics. The rules come from the same evaluation the report reads,
/// so the window and the report can never disagree.
@MainActor
struct ProjectPolicyTests {
    private let policy = """
    policy {
      system_requires_owner = true
    }
    """

    private func aProject(_ files: [String: String]) async -> ProjectSession {
        let useCases = TestDependencies()
        for (path, text) in files { useCases.project.put(text, at: path) }
        return ProjectSession(useCases: useCases, defaults: aTestDefaults())
    }

    @Test func listsAKeptRule() async {
        let session = await aProject([
            "/work/threatmodel/payments.arch": """
            system "Payments" {
              owner = "Payments team"
            }

            """,
            "/work/threatmodel/policy.hcl": policy
        ])

        await session.open(root: "/work")

        #expect(session.policyRules == [
            ReportPolicyRule(
                name: "system_requires_owner",
                asks: "the file states an owner",
                breaches: []
            )
        ])
        #expect(session.hasPolicyBreach == false)
    }

    @Test func listsABreachedRuleWithTheWordsTheCheckPrints() async {
        let session = await aProject([
            "/work/threatmodel/payments.arch": "system \"Payments\" { }\n",
            "/work/threatmodel/policy.hcl": policy
        ])

        await session.open(root: "/work")

        #expect(session.policyRules == [
            ReportPolicyRule(
                name: "system_requires_owner",
                asks: "the file states an owner",
                breaches: ["this system states no owner"]
            )
        ])
        #expect(session.hasPolicyBreach)
    }

    @Test func listsNothingForAProjectWithNoPolicyFile() async {
        let session = await aProject([
            "/work/threatmodel/payments.arch": "system \"Payments\" { }\n"
        ])

        await session.open(root: "/work")

        #expect(session.policyRules.isEmpty)
        #expect(session.hasPolicyBreach == false)
    }
}

/// The systems picker states the unanswered count and the worst level beside
/// each name, the same numbers `threatmodeller list` prints. These tests hold
/// `ProjectSession.systemSummaries` to that.
@MainActor
@Suite("The systems picker states more than a name")
struct SystemsPickerTests {
    private let payments = """
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

    private let paymentsAnswered = """
    controls for "Payments" {
      threat "credential-theft" on component "api" {
        control "Enforce IMDSv2 to block SSRF-based credential theft" {
          status = "accepted"
        }

        control "Use IAM roles with minimal permissions" {
          status = "accepted"
        }
      }
    }

    """

    private func aProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(useCases: useCases, defaults: aTestDefaults())
        await session.open(root: "/work")
        return (session, useCases)
    }

    @Test func statesTheUnansweredCountAndTheWorstLevelListStates() async throws {
        let (session, useCases) = await aProject()

        guard case .listed(let expected) = useCases.listSystem().execute(
            ListSystemRequest(root: "/work", systemName: "payments")
        ) else {
            Issue.record("payments did not list")
            return
        }

        let summary = try #require(session.systemSummaries["payments"])
        #expect(summary.unanswered == expected.unanswered)
        #expect(summary.worstLevel == expected.worstLevel)
        #expect(summary.unanswered > 0)
    }

    @Test func theUnansweredCountDropsByOneAfterAThreatIsAnswered() async throws {
        let (session, _) = await aProject()
        let before = try #require(session.systemSummaries["payments"])
        let control = try #require(session.model?.threats.first?.controls.first)

        session.model?.setControlStatus(key: control.key, statusId: "accepted")
        await session.save()

        let after = try #require(session.systemSummaries["payments"])
        #expect(after.unanswered == before.unanswered - 1)
    }

    @Test func theRowUpdatesAfterAReload() async throws {
        let (session, useCases) = await aProject()
        let before = try #require(session.systemSummaries["payments"])
        #expect(before.unanswered > 0)

        // Somebody else answers a threat and this session reloads from disk.
        useCases.project.put(paymentsAnswered, at: "/work/threatmodel/payments.controls")
        await session.reloadFromDisk()

        let after = try #require(session.systemSummaries["payments"])
        #expect(after.unanswered < before.unanswered)
    }

    @Test func aSystemWhoseFileDoesNotParseShowsADiagnosticMarkAndOpensTheOthers() async throws {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        useCases.project.put("system \"Broken\" {", at: "/work/threatmodel/broken.arch")
        let session = ProjectSession(useCases: useCases, defaults: aTestDefaults())

        await session.open(root: "/work")

        #expect(session.systems.sorted() == ["broken", "payments"])
        let broken = try #require(session.systemSummaries["broken"])
        #expect(broken.isUnparsed)
        // The picker still opens the system that did parse.
        await session.choose("payments")
        #expect(session.model != nil)
        #expect(session.systemSummaries["payments"]?.isUnparsed == false)
    }
}
