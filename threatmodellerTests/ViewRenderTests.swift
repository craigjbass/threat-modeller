import AppKit
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Draws each view and reads the pixels back.
///
/// These replace the interface journeys, which needed macOS Automation Mode and
/// so could not run on a machine that asks for authentication to enable it.
/// `ImageRenderer` needs none of that: it lays a view out and paints it in this
/// process. What it proves is narrower than a journey — a view builds, lays out
/// and draws something — and what a control does is stated by the session tests
/// beside this file.
@MainActor
struct ViewRenderTests {
    // MARK: what a drawn view is

    /// The image a view draws at a stated size, or nil.
    private func draw(_ view: some View, width: Double = 900, height: Double = 700) -> NSBitmapImageRep? {
        let renderer = ImageRenderer(content: view.frame(width: width, height: height))
        renderer.scale = 1
        guard let image = renderer.cgImage else { return nil }
        return NSBitmapImageRep(cgImage: image)
    }

    /// True when the picture holds more than one colour, which is what tells a
    /// view that drew its content from a view that drew a blank rectangle.
    private func hasContent(_ image: NSBitmapImageRep) -> Bool {
        var seen: Set<String> = []
        let across = stride(from: 4, to: image.pixelsWide - 4, by: max(1, image.pixelsWide / 40))
        let down = stride(from: 4, to: image.pixelsHigh - 4, by: max(1, image.pixelsHigh / 40))

        for x in across {
            for y in down {
                guard let colour = image.colorAt(x: x, y: y) else { continue }
                seen.insert(
                    String(
                        format: "%.2f,%.2f,%.2f",
                        colour.redComponent,
                        colour.greenComponent,
                        colour.blueComponent
                    )
                )
                if seen.count > 1 { return true }
            }
        }
        return false
    }

    private func expectDrawn(
        _ view: some View,
        width: Double = 900,
        height: Double = 700,
        _ what: String
    ) {
        guard let image = draw(view, width: width, height: height) else {
            Issue.record("\(what) drew nothing at all")
            return
        }
        #expect(image.pixelsWide == Int(width), "\(what) drew the wrong width")
        #expect(image.pixelsHigh == Int(height), "\(what) drew the wrong height")
        #expect(hasContent(image), "\(what) drew a blank rectangle")
    }

    // MARK: the models the views draw

    private func aModel() -> ThreatModelSession {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        session.addZone(x: -100, y: -100, width: 800, height: 700)
        return session
    }

    private func anEmptyProject() -> ProjectSession {
        let useCases = TestDependencies()
        useCases.project.put("a readme", at: "/work/README.md")
        // A fake watcher, so a render test never reaches the file system.
        let session = ProjectSession(useCases: useCases, watcher: FakeProjectWatcher(), defaults: aTestDefaults())
        session.open(root: "/work")
        return session
    }

    private func aDrawnProject() -> ProjectSession {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
              }
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        let session = ProjectSession(useCases: useCases, watcher: FakeProjectWatcher(), defaults: aTestDefaults())
        session.open(root: "/work")
        return session
    }

    /// The assertion has teeth: a view that draws one flat colour fails it.
    /// Without this, every test in this file could pass on a blank window.
    @Test func knowsABlankRectangleFromADrawnView() throws {
        let blank = try #require(draw(Color.white, width: 200, height: 200))
        let drawn = try #require(draw(ProjectWindow(session: aDrawnProject())))

        #expect(hasContent(blank) == false)
        #expect(hasContent(drawn))
    }

    // MARK: the project window, which is what this change touched

    @Test func drawsTheOfferWhenAProjectHoldsNothing() throws {
        let session = anEmptyProject()

        #expect(session.canInitialise)
        expectDrawn(ProjectWindow(session: session), "the empty project window")
    }

    @Test func namesEveryExampleItOffers() {
        let session = anEmptyProject()

        // The window draws one button per example, so the names it offers are
        // the names the examples carry.
        #expect(session.examples.map(\.name) == ["One Component"])
    }

    @Test func drawsTheSystemAProjectHolds() {
        let session = aDrawnProject()

        #expect(session.canInitialise == false)
        expectDrawn(ProjectWindow(session: session), "the project window")
    }

    @Test func drawsTheOfferAndThenTheSystemItWrote() {
        let session = anEmptyProject()
        expectDrawn(ProjectWindow(session: session), "the empty project window")

        session.initialise()

        #expect(session.model != nil)
        expectDrawn(ProjectWindow(session: session), "the project window after the example")
    }

    // MARK: the workflow bar

    @Test func drawsTheWorkflowBar() throws {
        let session = aDrawnProject()

        let bar = try #require(draw(WorkflowBar(session: session), width: 900, height: 90))

        #expect(hasContent(bar))
    }

    @Test func drawsWhatTheLastActionDid() throws {
        let session = aDrawnProject()
        session.compileReport()

        #expect(session.lastActionMessage?.hasPrefix("Report: ") == true)
        let bar = try #require(draw(WorkflowBar(session: session), width: 900, height: 90))
        #expect(hasContent(bar))
    }

    @Test func drawsTheNoticeWhenTheFilesChangedUnderAnUnsavedModel() throws {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
              }
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        let watcher = FakeProjectWatcher()
        let session = ProjectSession(useCases: useCases, watcher: watcher, defaults: aTestDefaults())
        session.open(root: "/work")
        session.model?.addAtDefaultPoint(technologyId: "aws-rds")
        useCases.project.put(
            "system \"Payments\" { component \"other\" { technology = \"aws-rds\" } }",
            at: "/work/threatmodel/payments.arch"
        )
        watcher.fire()

        #expect(session.hasFilesChangedOnDisk)
        expectDrawn(ProjectWindow(session: session), "the project window with the notice")
    }

    // MARK: the welcome window

    private func aRecentStore(named name: String) -> RecentProjects {
        let suite = "welcome-render-\(name)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        return RecentProjects(defaults: defaults)
    }

    @Test func drawsTheWelcomeWindow() throws {
        let view = WelcomeWindow(
            catalogue: ViewCatalogueVersionResponse(
                repository: "threat-catalogue",
                tag: "v1.4.2",
                technologyCount: 42
            ),
            recents: aRecentStore(named: "full"),
            openProject: {},
            openRecentProject: { _ in }
        )

        let image = try #require(draw(view, width: 620, height: 520))

        #expect(hasContent(image))
    }

    @Test func drawsTheWelcomeWindowWithNoCatalogue() throws {
        let view = WelcomeWindow(
            catalogue: nil,
            recents: aRecentStore(named: "empty"),
            openProject: {},
            openRecentProject: { _ in }
        )

        let image = try #require(draw(view, width: 620, height: 520))

        #expect(hasContent(image))
    }

    // MARK: the rest of the chrome

    @Test func drawsTheCanvas() {
        expectDrawn(CanvasView(session: aModel(), canvas: CanvasState()), "the canvas")
    }

    @Test func drawsThePalette() {
        expectDrawn(
            PaletteView(session: aModel(), canvas: CanvasState()),
            width: 300,
            height: 700,
            "the palette"
        )
    }

    @Test func drawsTheThreatSidebar() {
        expectDrawn(ThreatSidebar(session: aModel()), width: 400, height: 700, "the threat sidebar")
    }

    @Test func drawsTheNodePanel() throws {
        let session = aModel()
        let component = try #require(session.canvas.components.first)

        expectDrawn(
            ComponentPanel(session: session, component: component),
            width: 900,
            height: 60,
            "the node panel"
        )
    }

    @Test func drawsTheZonePanel() throws {
        let session = aModel()
        let zone = try #require(session.canvas.zones.first)

        expectDrawn(
            ZonePanel(session: session, zone: zone),
            width: 900,
            height: 60,
            "the zone panel"
        )
    }

    @Test func drawsTheCompensatingControlSheet() throws {
        let session = aModel()
        let threat = try #require(session.threats.first)

        expectDrawn(
            CompensatingControlSheet(threat: threat, session: session),
            width: 460,
            height: 420,
            "the compensating control sheet"
        )
    }

    @Test func drawsTheDiagnosticsSheet() {
        expectDrawn(
            DiagnosticsSheet(
                fileName: "payments.arch",
                diagnostics: [
                    Diagnostic(severity: .error, line: 3, column: 5, message: "kind is \"secret\""),
                    Diagnostic(severity: .warning, line: 9, column: 1, message: "an empty zone")
                ],
                dismiss: {}
            ),
            width: 560,
            height: 380,
            "the diagnostics sheet"
        )
    }

    @Test func drawsTheSamplesBrowser() {
        expectDrawn(
            SampleBrowser(session: aModel(), canvas: CanvasState()),
            width: 480,
            height: 360,
            "the samples browser"
        )
    }

    @Test func drawsTheTechnologyEditor() {
        expectDrawn(
            CustomTechnologyEditor(session: aModel(), technologyId: nil),
            width: 520,
            height: 560,
            "the technology editor"
        )
    }

    @Test func drawsTheAboutWindow() {
        expectDrawn(
            AboutWindow(
                catalogue: ViewCatalogueVersionResponse(
                    repository: "jib1337/threat-model-library",
                    tag: "v1.0.1",
                    technologyCount: 286
                )
            ),
            width: 460,
            height: 400,
            "the About window"
        )
    }
}
