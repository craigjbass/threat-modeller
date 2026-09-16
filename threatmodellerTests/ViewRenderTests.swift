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

    private func aViewedComponent(shapeId: String) -> ViewedComponent {
        ViewedComponent(
            id: "c1",
            technologyId: "aws-ec2",
            name: "Web Server",
            customName: nil,
            providerId: "aws",
            categoryId: "compute",
            x: 0,
            y: 0,
            sensitivityId: "confidential",
            threatsDisabled: false,
            isUnknownTechnology: false,
            zoneId: nil,
            runsAsId: "user",
            shapeId: shapeId,
            shapeOverrideId: nil
        )
    }

    private func aNode(
        shapeId: String,
        risk: ElementRisk?,
        zoneName: String? = nil
    ) -> ComponentNodeView {
        ComponentNodeView(
            component: aViewedComponent(shapeId: shapeId),
            risk: risk,
            isSelected: false,
            onSelect: { _ in },
            onDragChanged: { _ in },
            onDragEnded: { _ in },
            onAnchorDragChanged: { _ in },
            onAnchorDragEnded: { _ in },
            zoneName: zoneName
        )
    }

    private func aModel() -> ThreatModelSession {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        session.addZone(x: -100, y: -100, width: 800, height: 700)
        return session
    }

    private func anEmptyProject() async -> ProjectSession {
        let useCases = TestDependencies()
        useCases.project.put("a readme", at: "/work/README.md")
        // A fake watcher, so a render test never reaches the file system.
        let session = ProjectSession(useCases: useCases, watcher: FakeProjectWatcher(), defaults: aTestDefaults())
        await session.open(root: "/work")
        return session
    }

    private func aDrawnProject() async -> ProjectSession {
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
        await session.open(root: "/work")
        return session
    }

    /// The assertion has teeth: a view that draws one flat colour fails it.
    /// Without this, every test in this file could pass on a blank window.
    @Test func knowsABlankRectangleFromADrawnView() async throws {
        let blank = try #require(draw(Color.white, width: 200, height: 200))
        let drawn = try #require(draw(ProjectWindow(session: await aDrawnProject())))

        #expect(hasContent(blank) == false)
        #expect(hasContent(drawn))
    }

    // MARK: the project window, which is what this change touched

    @Test func drawsTheOfferWhenAProjectHoldsNothing() async throws {
        let session = await anEmptyProject()

        #expect(session.canInitialise)
        expectDrawn(ProjectWindow(session: session), "the empty project window")
    }

    @Test func namesEveryExampleItOffers() async {
        let session = await anEmptyProject()

        // The window draws one button per example, so the names it offers are
        // the names the examples carry.
        #expect(session.examples.map(\.name) == ["One Component"])
    }

    @Test func drawsTheSystemAProjectHolds() async {
        let session = await aDrawnProject()

        #expect(session.canInitialise == false)
        expectDrawn(ProjectWindow(session: session), "the project window")
    }

    /// A project holding a system that parses and one that does not, so the
    /// picker draws a name beside a count and a name beside a diagnostic
    /// mark.
    private func aProjectWithAnUnparsedSystem() async -> ProjectSession {
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
        useCases.project.put("system \"Broken\" {", at: "/work/threatmodel/broken.arch")
        let session = ProjectSession(useCases: useCases, watcher: FakeProjectWatcher(), defaults: aTestDefaults())
        await session.open(root: "/work")
        return session
    }

    /// The systems picker states the unanswered count and the worst level
    /// beside a parsed system's name, and a diagnostic mark beside one that
    /// did not parse. Neither row stops the window drawing.
    @Test func drawsTheSystemsPickerWithACountAndADiagnosticMark() async throws {
        let session = await aProjectWithAnUnparsedSystem()

        #expect(session.systemSummaries["payments"]?.isUnparsed == false)
        #expect(session.systemSummaries["broken"]?.isUnparsed == true)
        expectDrawn(ProjectWindow(session: session), "the project window with a mixed picker")

        await session.choose("payments")

        #expect(session.model != nil)
        expectDrawn(ProjectWindow(session: session), "the project window with payments chosen")
    }

    @Test func drawsTheOfferAndThenTheSystemItWrote() async {
        let session = await anEmptyProject()
        expectDrawn(ProjectWindow(session: session), "the empty project window")

        await session.initialise()

        #expect(session.model != nil)
        expectDrawn(ProjectWindow(session: session), "the project window after the example")
    }

    // MARK: the context menus

    /// Each of the four menus, drawn. A `contextMenu` cannot be opened by a
    /// test, so the rows are drawn as the menu draws them.
    @Test func drawsTheFourContextMenus() async throws {
        let session = ThreatModelSession(useCases: TestDependencies())
        let canvas = CanvasState()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 400, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])
        let flow = try #require(session.canvas.connections.first)
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 400, height: 300))
        let menu = ElementMenu(session: session, canvas: canvas)

        for (what, rows) in [
            ("component", menu.component(ids[0])),
            ("zone", menu.zone(zoneId)),
            ("connection", menu.connection(flow.id)),
            ("canvas", menu.background(at: .zero))
        ] {
            expectDrawn(
                VStack(alignment: .leading) { ElementMenuView(rows: rows) }
                    .padding()
                    .background(Color(nsColor: .windowBackgroundColor)),
                width: 320,
                height: 420,
                "the \(what) menu"
            )
        }
    }

    // MARK: the threats stage

    /// The threats stage draws the diagram beside the threat list, with
    /// nothing picked on the diagram and with a node picked, which is what
    /// puts a selection panel under the canvas.
    @Test func drawsTheThreatsStageWithSomethingSelectedAndWithNothing() async throws {
        let project = await aDrawnProject()
        let model = try #require(project.model)
        let canvas = CanvasState()
        let stage = ProjectColumns(
            project: project,
            session: model,
            canvas: canvas,
            stage: .constant(.threats)
        )

        expectDrawn(stage, width: 1200, height: 800, "the threats stage with nothing picked")

        let node = try #require(model.canvas.components.first)
        canvas.select(componentId: node.id, addingToSelection: false)

        expectDrawn(stage, width: 1200, height: 800, "the threats stage with a node picked")
    }

    // MARK: the floating workflow panel

    @Test func drawsTheFloatingWorkflowPanel() async throws {
        let session = await aDrawnProject()

        let panel = try #require(
            draw(
                WorkflowPanel(session: session, stage: .constant(.architecture)),
                width: 900,
                height: 120
            )
        )

        #expect(hasContent(panel))
    }

    /// The panel floats above a selection panel, so the two never cover each
    /// other. Each of the four selection panels is a different height.
    @Test func drawsTheFloatingPanelLiftedAboveASelectionPanel() async throws {
        let session = await aDrawnProject()

        let lifted = try #require(
            draw(
                WorkflowPanel(session: session, stage: .constant(.architecture), liftedBy: 60),
                width: 900,
                height: 200
            )
        )

        #expect(hasContent(lifted))
    }

    // MARK: the Libraries sheet

    /// A session over a project holding one library, so the sheet has a row.
    private func aLibrarySession(usingTheLibrary: Bool = false) async -> LibrarySession {
        let useCases = TestDependencies()
        useCases.project.put(
            usingTheLibrary
                ? "system \"Payments\" { component \"i\" { technology = \"acme-thing\" } }"
                : "system \"Payments\" { }",
            at: "/work/threatmodel/payments.arch"
        )
        useCases.libraryFetcher.put(
            ["acme.lib": "library \"acme\" {\n  name = \"Acme Platform\"\n}\n"],
            repository: "github.com/acme/threat-elements",
            tag: "v2.1.0"
        )
        let session = LibrarySession(useCases: useCases, root: "/work", onChange: {})
        await session.add(repository: "github.com/acme/threat-elements", tag: "v2.1.0")
        return session
    }

    @Test func drawsTheLibrariesSheet() async throws {
        let session = await aLibrarySession()

        let sheet = try #require(draw(LibrariesSheet(session: session, dismiss: {})))

        #expect(hasContent(sheet))
    }

    @Test func drawsTheLibrariesSheetForAProjectWithNoLibrary() async throws {
        let useCases = TestDependencies()
        useCases.project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        let session = LibrarySession(useCases: useCases, root: "/work", onChange: {})

        let sheet = try #require(draw(LibrariesSheet(session: session, dismiss: {})))

        #expect(hasContent(sheet))
    }

    @Test func drawsTheQuestionBeforeRemovingALibraryInUse() async throws {
        let session = await aLibrarySession(usingTheLibrary: true)
        session.remove(label: "acme", isForced: false)

        let sheet = try #require(draw(LibrariesSheet(session: session, dismiss: {})))

        #expect(session.removalInUse == ["payments"])
        #expect(hasContent(sheet))
    }

    // MARK: the command line tool

    /// An application bundle that carries the executable, and a home, so the
    /// sheet draws its real states without touching the user's own.
    private func aCommandLineTool(carryingTheHelper: Bool) throws -> CommandLineTool {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("command-line-render-\(UUID().uuidString)")
        let app = root.appendingPathComponent("threatmodeller.app")
        let home = root.appendingPathComponent("home")
        let helpers = app.appendingPathComponent("Contents/Resources/threatmodeller-cli")
        try FileManager.default.createDirectory(at: helpers, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        if carryingTheHelper {
            try "binary".write(
                to: helpers.appendingPathComponent("threatmodeller"),
                atomically: true,
                encoding: .utf8
            )
        }
        return CommandLineTool(bundle: app, home: home, path: "/usr/bin")
    }

    @Test func drawsTheCommandLineToolSheet() async throws {
        let tool = try aCommandLineTool(carryingTheHelper: true)

        let sheet = try #require(draw(
            CommandLineToolSheet(tool: tool, dismiss: {}),
            width: 560,
            height: 340
        ))

        #expect(hasContent(sheet))
    }

    @Test func drawsTheSheetForABuildThatCarriesNoCommand() async throws {
        let tool = try aCommandLineTool(carryingTheHelper: false)

        let sheet = try #require(draw(
            CommandLineToolSheet(tool: tool, dismiss: {}),
            width: 560,
            height: 340
        ))

        #expect(hasContent(sheet))
    }

    /// The message is in the toolbar, and the floating panel is the same size
    /// whether a message is set or not, so nothing on the canvas moves.
    @Test func drawsTheSamePanelWithAMessageAndWithout() async throws {
        let session = await aDrawnProject()
        let panel = WorkflowPanel(session: session, stage: .constant(.architecture))
        let quiet = NSHostingView(rootView: panel).fittingSize

        session.compileReport()

        #expect(session.lastActionMessage?.hasPrefix("Report: ") == true)
        #expect(NSHostingView(rootView: panel).fittingSize == quiet)
        let drawn = try #require(draw(panel, width: 900, height: 120))
        #expect(hasContent(drawn))
    }

    /// The window draws the message where the load stage draws, and draws it
    /// no longer once the wait ends.
    @Test func drawsTheMessageInTheWindowUntilTheWaitEnds() async throws {
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
        let timer = FakeCoalescer()
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults(),
            messageTimer: timer
        )
        await session.open(root: "/work")

        session.compileReport()
        #expect(session.toolbarMessage != nil)
        expectDrawn(ProjectWindow(session: session), "the project window with the message")

        timer.fire()

        #expect(session.toolbarMessage == nil)
        expectDrawn(ProjectWindow(session: session), "the project window after the message")
    }

    @Test func drawsTheNoticeWhenTheFilesChangedUnderAnUnsavedModel() async throws {
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
        await session.open(root: "/work")
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

    @Test func drawsTheWelcomeWindow() async throws {
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

    @Test func drawsTheWelcomeWindowWithNoCatalogue() async throws {
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

    @Test func drawsTheCanvas() async {
        expectDrawn(CanvasView(session: aModel(), canvas: CanvasState()), "the canvas")
    }

    @Test func drawsThePalette() async {
        expectDrawn(
            PaletteView(session: aModel(), canvas: CanvasState()),
            width: 300,
            height: 700,
            "the palette"
        )
    }

    /// The sidebar draws its whole content inside a `ScrollView`, which
    /// `ImageRenderer` cannot see into, so this one is drawn by AppKit.
    @Test func drawsTheThreatSidebar() async throws {
        let drawn = try #require(
            hostedDrawing(of: ThreatSidebar(session: aModel()), width: 400, height: 700)
        )

        #expect(hasContent(drawn.image), "the threat sidebar drew a blank rectangle")
    }

    /// The list holds its order while a person answers it, so the sidebar
    /// draws three states: in order, out of order with the Reorder button, and
    /// in order again after Reorder.
    @Test func drawsTheThreatSidebarBeforeAndAfterAReorder() async throws {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-ec2", x: 400, y: 0)

        let inOrder = try #require(
            hostedDrawing(of: ThreatSidebar(session: session), width: 400, height: 700)
        )
        #expect(hasContent(inOrder.image), "the threat sidebar drew a blank rectangle")
        #expect(session.rowsOutOfOrder == 0)

        let control = try #require(session.threats.first?.controls.first)
        session.setControl(key: control.key, implemented: true)
        #expect(session.rowsOutOfOrder > 0)
        let outOfOrder = try #require(
            hostedDrawing(of: ThreatSidebar(session: session), width: 400, height: 700)
        )
        #expect(hasContent(outOfOrder.image), "the sidebar with the Reorder button drew blank")

        session.resortThreats()
        let reordered = try #require(
            hostedDrawing(of: ThreatSidebar(session: session), width: 400, height: 700)
        )
        #expect(hasContent(reordered.image), "the reordered sidebar drew blank")
        #expect(session.rowsOutOfOrder == 0)
    }

    /// A node and a zone mid-edit: the field replaces the name where the name
    /// was, on the element itself.
    @Test func drawsANodeAndAZoneMidEdit() async throws {
        let session = aModel()
        let component = try #require(session.canvas.components.first)
        let zone = try #require(session.canvas.zones.first)

        expectDrawn(
            ComponentNodeView(
                component: component,
                risk: nil,
                isSelected: true,
                onSelect: { _ in },
                onDragChanged: { _ in },
                onDragEnded: { _ in },
                onAnchorDragChanged: { _ in },
                onAnchorDragEnded: { _ in },
                zoneName: nil,
                isEditingName: true
            ),
            width: 240,
            height: 160,
            "a node mid-edit"
        )

        expectDrawn(
            ZoneView(
                zone: zone,
                risk: nil,
                size: CGSize(width: 400, height: 300),
                isSelected: true,
                onSelect: { _ in },
                onDragChanged: { _, _ in },
                onDragEnded: { _, _ in },
                isEditingName: true
            ),
            width: 420,
            height: 320,
            "a zone mid-edit"
        )
    }

    @Test func drawsTheNodePanel() async throws {
        let session = aModel()
        let component = try #require(session.canvas.components.first)

        expectDrawn(
            ComponentPanel(session: session, component: component),
            width: 900,
            height: 60,
            "the node panel"
        )
    }

    @Test func drawsTheZonePanel() async throws {
        let session = aModel()
        let zone = try #require(session.canvas.zones.first)

        expectDrawn(
            ZonePanel(session: session, zone: zone),
            width: 900,
            height: 60,
            "the zone panel"
        )
    }

    @Test func drawsTheConnectionPanel() async throws {
        let session = aModel()
        session.addAtDefaultPoint(technologyId: "aws-ec2")
        let components = session.canvas.components
        session.connect(
            sourceComponentId: try #require(components.first).id,
            targetComponentId: try #require(components.last).id
        )
        let connection = try #require(session.canvas.connections.first)

        expectDrawn(
            ConnectionPanel(session: session, connection: connection),
            width: 900,
            height: 60,
            "the connection panel"
        )
    }

    @Test func drawsTheCompensatingControlSheet() async throws {
        let session = aModel()
        let threat = try #require(session.threats.first)

        expectDrawn(
            CompensatingControlSheet(threat: threat, session: session),
            width: 460,
            height: 420,
            "the compensating control sheet"
        )
    }

    @Test func drawsTheDiagnosticsSheet() async {
        expectDrawn(
            DiagnosticsSheet(
                fileName: "payments.arch",
                diagnostics: [
                    Diagnostic(severity: .error, line: 3, column: 5, message: "kind is \"secret\""),
                    Diagnostic(severity: .warning, line: 9, column: 1, message: "an empty zone"),
                    Diagnostic(severity: .warning, line: 12, column: 3, message: "the flow names no kind")
                ],
                dismiss: {},
                path: "/work/threatmodel/payments.arch"
            ),
            width: 560,
            height: 380,
            "the diagnostics sheet"
        )
    }

    /// The sheet lists the policy rules beside the diagnostics: each rule
    /// marked kept or breached, and a breach in the words the check prints.
    @Test func drawsTheDiagnosticsSheetWithPolicyRules() async {
        expectDrawn(
            DiagnosticsSheet(
                fileName: "payments.arch",
                diagnostics: [
                    Diagnostic(severity: .warning, line: 9, column: 1, message: "an empty zone")
                ],
                dismiss: {},
                path: "/work/threatmodel/payments.arch",
                policyRules: [
                    ReportPolicyRule(
                        name: "system_requires_owner",
                        asks: "the file states an owner",
                        breaches: ["this system states no owner"]
                    ),
                    ReportPolicyRule(
                        name: "accepted_requires_owner",
                        asks: "every accepted risk names an owner",
                        breaches: []
                    )
                ]
            ),
            width: 560,
            height: 380,
            "the diagnostics sheet with policy rules"
        )
    }

    @Test func drawsTheSamplesBrowser() async {
        expectDrawn(
            SampleBrowser(session: aModel(), canvas: CanvasState()),
            width: 480,
            height: 620,
            "the samples browser"
        )
    }

    /// The browser draws the diagram of the sample a person picked.
    @Test func drawsTheSamplesBrowserWithASampleHighlighted() async throws {
        let session = aModel()
        let sample = try #require(session.samples.first)
        let drawn = try #require(session.samplePicture(sample.id))
        let picture = CanvasHitTest.contentRect(
            components: drawn.components,
            zones: drawn.zones
        )

        expectDrawn(
            CanvasPicture(
                components: drawn.components,
                connections: drawn.connections,
                zones: drawn.zones,
                risks: [:],
                guards: [:],
                origin: picture.origin,
                size: picture.size
            )
            .scaleEffect(SampleBrowser.previewScale(of: picture.size), anchor: .topLeading)
            .frame(
                width: SampleBrowser.previewSize.width,
                height: SampleBrowser.previewSize.height,
                alignment: .topLeading
            )
            .background(Color(nsColor: .textBackgroundColor)),
            width: SampleBrowser.previewSize.width,
            height: SampleBrowser.previewSize.height,
            "the sample preview"
        )
    }

    @Test func drawsTheTechnologyEditor() async {
        expectDrawn(
            CustomTechnologyEditor(session: aModel(), technologyId: nil),
            width: 520,
            height: 560,
            "the technology editor"
        )
    }

    @Test func drawsTheAboutWindow() async {
        expectDrawn(
            AboutWindow(
                catalogue: ViewCatalogueVersionResponse(
                    repository: "jib1337/threat-model-library",
                    tag: "v1.0.1",
                    technologyCount: 286
                ),
                version: AboutVersion(version: "1.0", build: "1")
            ),
            width: 460,
            height: 400,
            "the About window"
        )
    }

    /// The window states the libraries the project reads, and states so when
    /// it reads none.
    @Test func drawsTheAboutWindowWithItsLibraries() async {
        expectDrawn(
            AboutWindow(
                catalogue: ViewCatalogueVersionResponse(
                    repository: "threat-catalogue",
                    tag: "v1.0.1",
                    technologyCount: 277
                ),
                libraries: [
                    ListedLibrary(
                        label: "acme",
                        name: "Acme Platform",
                        repository: "git@example.internal:acme/elements.git",
                        tag: "v1.2.0",
                        matchesLock: true
                    )
                ]
            ),
            width: 520,
            height: 420,
            "the about window with a library"
        )
    }

    /// The window states the ATT&CK data this machine holds, and states so
    /// when it holds none.
    @Test func drawsTheAboutWindowWithItsAttackData() async {
        expectDrawn(
            AboutWindow(
                catalogue: ViewCatalogueVersionResponse(
                    repository: "threat-catalogue",
                    tag: "v1.0.1",
                    technologyCount: 277
                ),
                attack: .held(
                    tag: "v18.1",
                    groups: 189,
                    techniques: 823,
                    writtenAt: Date(timeIntervalSince1970: 1_700_000_000)
                ),
                verify: .doesNotMatch(tag: "v18.1", fileName: "groups.json")
            ),
            width: 520,
            height: 480,
            "the about window with the attack data"
        )
    }

    @Test func drawsTheAboutWindowOfAReleasedBuild() async {
        expectDrawn(
            AboutWindow(
                catalogue: ViewCatalogueVersionResponse(
                    repository: "jib1337/threat-model-library",
                    tag: "v1.0.1",
                    technologyCount: 286
                ),
                version: AboutVersion(
                    version: "1.0.2",
                    build: "412",
                    releaseName: "v1.0.2-beta-dd164bf"
                )
            ),
            width: 460,
            height: 420,
            "the About window of a released build"
        )
    }

    // MARK: the data flow diagram shapes

    @Test func drawsEachDiagramShape() async {
        for shapeId in ["actor", "process", "store"] {
            expectDrawn(
                aNode(
                    shapeId: shapeId,
                    risk: ElementRisk(
                        sourceId: "component:c1",
                        openCount: 3,
                        totalCount: 4,
                        highestLevelId: "high"
                    ),
                    zoneName: "Private Zone"
                ),
                width: 200,
                height: 180,
                "the \(shapeId) node"
            )
        }
    }

    @Test func drawsANodeThatRaisesNoThreat() async {
        expectDrawn(
            aNode(shapeId: "process", risk: nil),
            width: 200,
            height: 180,
            "a node with no threats"
        )
    }

    @Test func drawsAFlowWithItsLabelAndItsOpenThreatCount() async {
        let boxes = [
            "a": ComponentBox(x: 0, y: 0, shape: .process),
            "b": ComponentBox(x: 400, y: 200, shape: .store)
        ]

        expectDrawn(
            ConnectionsLayer(
                origin: .zero,
                connections: [
                    ViewedConnection(
                        id: "f1",
                        sourceComponentId: "a",
                        targetComponentId: "b",
                        kindId: "network",
                        description: "HTTPS"
                    )
                ],
                boxes: boxes,
                componentsById: [:],
                zones: [],
                risks: [
                    "connection:f1": ElementRisk(
                        sourceId: "connection:f1",
                        openCount: 2,
                        totalCount: 3,
                        highestLevelId: "critical"
                    )
                ],
                guards: ["connection:f1": [EdgeGuard(label: "WAF", isAssumed: false)]],
                outOfScopeComponentIds: [],
                selectedConnectionIds: [],
                preview: nil
            ),
            width: 600,
            height: 400,
            "a flow with a label"
        )
    }

    @Test func drawsAPrivilegeZoneWithItsChipAndItsCount() async {
        expectDrawn(
            ZoneView(
                zone: ViewedZone(
                    id: "z1",
                    name: "Kernel",
                    customName: "Kernel",
                    networkZoneId: "private",
                    networkTypeId: "generic",
                    riskReductionEnabled: true,
                    riskReductionPercent: 20,
                    x: 0,
                    y: 0,
                    width: 400,
                    height: 300,
                    boundaryId: "privilege"
                ),
                risk: ElementRisk(
                    sourceId: "zone:z1",
                    openCount: 4,
                    totalCount: 6,
                    highestLevelId: "critical"
                ),
                size: CGSize(width: 400, height: 300),
                isSelected: false,
                onSelect: { _ in },
                onDragChanged: { _, _ in },
                onDragEnded: { _, _ in }
            ),
            width: 400,
            height: 300,
            "a privilege zone"
        )
    }

    @Test func drawsAWholeDiagramWithTheRiskItCarries() async {
        let session = aModel()

        expectDrawn(
            CanvasPicture(
                components: session.canvas.components,
                connections: session.canvas.connections,
                zones: session.canvas.zones,
                risks: session.elementRisks,
                guards: session.elementGuards,
                origin: .zero,
                size: CGSize(width: 900, height: 700)
            ),
            "the whole diagram"
        )
    }

    /// Two zones with a flow between them, so the layer draws the trust
    /// boundary marks as well as the link.
    private func aCrossedModel() -> ThreatModelSession {
        let session = ThreatModelSession(useCases: TestDependencies())
        _ = session.addZone(x: 40, y: 60, width: 320, height: 380)
        _ = session.addZone(x: 480, y: 60, width: 340, height: 380)
        session.add(technologyId: "actor-user", x: 100, y: 200)
        session.add(technologyId: "aws-ec2", x: 560, y: 200)
        let ids = session.canvas.components.map(\.id)
        if ids.count == 2 {
            session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])
        }
        return session
    }

    @Test func drawsTheTrustBoundaryMarkWhereAFlowCrossesAZoneEdge() async {
        let session = aCrossedModel()

        #expect(session.canvas.components.compactMap(\.zoneId).count == 2)
        expectDrawn(
            CanvasPicture(
                components: session.canvas.components,
                connections: session.canvas.connections,
                zones: session.canvas.zones,
                risks: session.elementRisks,
                guards: session.elementGuards,
                origin: .zero,
                size: CGSize(width: 900, height: 520)
            ),
            width: 900,
            height: 520,
            "a diagram with a crossed trust boundary"
        )
    }

    @Test func namesWhatGuardsACrossedTrustBoundary() async {
        let session = aCrossedModel()
        let flowId = session.canvas.connections.first?.id ?? ""

        expectDrawn(
            CanvasPicture(
                components: session.canvas.components,
                connections: session.canvas.connections,
                zones: session.canvas.zones,
                risks: session.elementRisks,
                guards: [
                    "connection:\(flowId)": [
                        EdgeGuard(label: "WAF", isAssumed: false),
                        EdgeGuard(label: "API Gateway", isAssumed: true),
                        EdgeGuard(label: "Bastion", isAssumed: false)
                    ]
                ],
                origin: .zero,
                size: CGSize(width: 900, height: 520)
            ),
            width: 900,
            height: 520,
            "a guarded crossing"
        )
    }

    @Test func saysSoWhereNothingGuardsACrossedTrustBoundary() async {
        let session = aCrossedModel()

        expectDrawn(
            CanvasPicture(
                components: session.canvas.components,
                connections: session.canvas.connections,
                zones: session.canvas.zones,
                risks: session.elementRisks,
                guards: [:],
                origin: .zero,
                size: CGSize(width: 900, height: 520)
            ),
            width: 900,
            height: 520,
            "an unguarded crossing"
        )
    }

    // MARK: the mitigates mark

    /// Every sampled pixel of a drawn view, so one picture is compared with
    /// another. A mark that differs changes some of these.
    private func pixels(
        of view: some View,
        width: Double,
        height: Double
    ) -> [String]? {
        guard let image = draw(view, width: width, height: height) else { return nil }
        var read: [String] = []
        for x in stride(from: 0, to: image.pixelsWide, by: 2) {
            for y in stride(from: 0, to: image.pixelsHigh, by: 2) {
                guard let colour = image.colorAt(x: x, y: y) else { continue }
                read.append(
                    String(
                        format: "%.2f,%.2f,%.2f",
                        colour.redComponent,
                        colour.greenComponent,
                        colour.blueComponent
                    )
                )
            }
        }
        return read
    }

    private func aMitigatedComponent(_ id: String, x: Double) -> ViewedComponent {
        ViewedComponent(
            id: id,
            technologyId: "aws-ec2",
            name: "Gateway",
            customName: nil,
            providerId: "aws",
            categoryId: "compute",
            x: x,
            y: 120,
            sensitivityId: "internal",
            threatsDisabled: false,
            isUnknownTechnology: false,
            zoneId: nil
        )
    }

    private func aMitigatesEdge(status: String) -> ViewedMitigation {
        ViewedMitigation(
            sourceComponentId: "c1",
            targetComponentId: "c2",
            threatIds: ["t1"],
            reducesRiskBy: 40,
            status: status
        )
    }

    private func aLayer(
        connections: [ViewedConnection],
        mitigations: [ViewedMitigation]
    ) -> ConnectionsLayer {
        let components = [aMitigatedComponent("c1", x: 40), aMitigatedComponent("c2", x: 440)]
        return ConnectionsLayer(
            origin: .zero,
            connections: connections,
            boxes: CanvasHitTest.boxes(for: components, selected: [], dragTranslation: .zero),
            componentsById: Dictionary(uniqueKeysWithValues: components.map { ($0.id, $0) }),
            zones: [],
            risks: [:],
            guards: [:],
            outOfScopeComponentIds: [],
            selectedConnectionIds: [],
            selectedComponentIds: [],
            mitigations: mitigations,
            preview: nil
        )
    }

    private var aFlowBetweenTheSamePair: [ViewedConnection] {
        [ViewedConnection(id: "k1", sourceComponentId: "c1", targetComponentId: "c2")]
    }

    @Test func drawsAMitigatesEdge() async {
        expectDrawn(
            aLayer(connections: [], mitigations: [aMitigatesEdge(status: "adopted")]),
            width: 640,
            height: 400,
            "a mitigates edge"
        )
    }

    /// A flow and a mitigates edge run between the same two components. The
    /// two pictures differ, so the mark for an edge is not the mark for a
    /// flow.
    @Test func drawsAMitigatesEdgeDifferentlyFromAFlow() async throws {
        let flow = try #require(
            pixels(
                of: aLayer(connections: aFlowBetweenTheSamePair, mitigations: []),
                width: 640,
                height: 400
            )
        )
        let edge = try #require(
            pixels(
                of: aLayer(connections: [], mitigations: [aMitigatesEdge(status: "adopted")]),
                width: 640,
                height: 400
            )
        )

        #expect(flow != edge)
    }

    @Test func drawsAnAssumedEdgeDifferentlyFromAnAdoptedOne() async throws {
        let adopted = try #require(
            pixels(
                of: aLayer(connections: [], mitigations: [aMitigatesEdge(status: "adopted")]),
                width: 640,
                height: 400
            )
        )
        let assumed = try #require(
            pixels(
                of: aLayer(connections: [], mitigations: [aMitigatesEdge(status: "assumed")]),
                width: 640,
                height: 400
            )
        )

        #expect(adopted != assumed)
    }

    /// The edge is removed, and the canvas draws no mark for it. The picture
    /// is then the picture of a model that never held one.
    @Test func drawsNoMarkForARemovedEdge() async throws {
        let removed = try #require(
            pixels(of: aLayer(connections: [], mitigations: []), width: 640, height: 400)
        )
        let never = try #require(
            pixels(of: aLayer(connections: [], mitigations: []), width: 640, height: 400)
        )
        let held = try #require(
            pixels(
                of: aLayer(connections: [], mitigations: [aMitigatesEdge(status: "adopted")]),
                width: 640,
                height: 400
            )
        )

        #expect(removed == never)
        #expect(removed != held)
    }

    /// The exported picture draws the same layer the canvas draws, so a
    /// mitigates edge reaches the image a report carries.
    @Test func theExportedPictureShowsTheMitigatesMark() async throws {
        let components = [aMitigatedComponent("c1", x: 40), aMitigatedComponent("c2", x: 440)]
        let without = try #require(
            pixels(
                of: CanvasPicture(
                    components: components,
                    connections: [],
                    zones: [],
                    risks: [:],
                    guards: [:],
                    mitigations: [],
                    origin: .zero,
                    size: CGSize(width: 640, height: 400)
                ),
                width: 640,
                height: 400
            )
        )
        let with = try #require(
            pixels(
                of: CanvasPicture(
                    components: components,
                    connections: [],
                    zones: [],
                    risks: [:],
                    guards: [:],
                    mitigations: [aMitigatesEdge(status: "adopted")],
                    origin: .zero,
                    size: CGSize(width: 640, height: 400)
                ),
                width: 640,
                height: 400
            )
        )

        #expect(without != with)
    }
}
