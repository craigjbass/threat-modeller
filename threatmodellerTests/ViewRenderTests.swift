import DiagramRendering
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

    /// True when the picture holds more than one pixel value, which is what
    /// tells a view that drew its content from a view that drew a blank
    /// rectangle.
    ///
    /// A pixel value is the colour and the alpha together. A view that draws
    /// no background of its own draws text on nothing, so every pixel reads
    /// one colour and only the alpha says which pixel the view drew. A
    /// machine with no screen leaves the untouched pixels at one colour, so a
    /// check that reads the colour alone calls such a view blank.
    private func hasContent(_ image: NSBitmapImageRep) -> Bool {
        var seen: Set<String> = []
        let across = stride(from: 4, to: image.pixelsWide - 4, by: max(1, image.pixelsWide / 40))
        let down = stride(from: 4, to: image.pixelsHigh - 4, by: max(1, image.pixelsHigh / 40))

        for x in across {
            for y in down {
                guard let colour = image.colorAt(x: x, y: y) else { continue }
                seen.insert(
                    String(
                        format: "%.2f,%.2f,%.2f,%.2f",
                        colour.redComponent,
                        colour.greenComponent,
                        colour.blueComponent,
                        colour.alphaComponent
                    )
                )
                if seen.count > 1 { return true }
            }
        }
        return false
    }

    /// Draws a view the way AppKit draws it, then states it drew something.
    ///
    /// `ImageRenderer` draws nothing inside a `ScrollView`, and every
    /// selection editor is a scrolling column, so those go through the
    /// hosted drawing path instead.
    private func expectHosted(
        _ view: some View,
        width: Double = 360,
        height: Double = 700,
        _ what: String
    ) {
        guard let drawn = hostedDrawing(of: view, width: width, height: height) else {
            Issue.record("\(what) drew nothing at all")
            return
        }
        #expect(hasContent(drawn.image), "\(what) drew a blank rectangle")
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

    private func aViewedComponent(
        shapeId: String,
        statusId: String = "live",
        isUser: Bool = false
    ) -> ViewedComponent {
        ViewedComponent(
            id: "c1",
            technologyId: isUser ? "user" : "aws-ec2",
            name: "Web Server",
            customName: nil,
            providerId: isUser ? "" : "aws",
            categoryId: isUser ? "" : "compute",
            x: 0,
            y: 0,
            sensitivityId: "confidential",
            threatsDisabled: false,
            isUnknownTechnology: false,
            zoneId: nil,
            runsAsId: "user",
            shapeId: shapeId,
            shapeOverrideId: nil,
            statusId: statusId,
            isUser: isUser,
            role: isUser ? "Operator" : "",
            threatActorId: isUser ? "insider" : nil
        )
    }

    private func aNode(
        shapeId: String,
        risk: ElementRisk?,
        zoneName: String? = nil,
        statusId: String = "live",
        isUser: Bool = false,
        classificationColour: Color? = nil
    ) -> ComponentNodeView {
        ComponentNodeView(
            component: aViewedComponent(shapeId: shapeId, statusId: statusId, isUser: isUser),
            risk: risk,
            isSelected: false,
            onSelect: { _ in },
            onDragChanged: { _ in },
            onDragEnded: { _ in },
            onAnchorDragChanged: { _ in },
            onAnchorDragEnded: { _ in },
            zoneName: zoneName,
            classificationColour: classificationColour
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

    /// The Report stage draws the sections of a model that has something to
    /// say.
    @Test func drawsTheReportStage() async throws {
        let project = await aDrawnProject()
        let model = try #require(project.model)

        expectDrawn(
            ReportStage(project: project, session: model, stage: .constant(.report)),
            "the report stage"
        )
    }

    /// The Report stage draws a model with nothing on it. Every section the
    /// report writes nothing for is left out, and the page still draws.
    @Test func drawsTheReportStageOfAnEmptyModel() async throws {
        let project = await anEmptyProject()

        expectDrawn(
            ReportStage(
                project: project,
                session: ThreatModelSession(useCases: TestDependencies()),
                stage: .constant(.report)
            ),
            "the report stage of an empty model"
        )
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

    /// #146: the checkbox toggle draws no trailing inset of its own, so
    /// the settings row needs a real gap between the toggle and the
    /// picker, wider than the sum of each control's own drawn width. This
    /// draws the toggle alone, the picker alone, and the row of both, and
    /// states a column of background pixels sits between them in the row.
    @Test func drawsAGapBetweenTheAutoSyncToggleAndThePointerPicker() async throws {
        let window = ProjectWindow(session: await aDrawnProject())
        let marker = Color(red: 1, green: 0, blue: 1)

        func isMarker(_ image: NSBitmapImageRep, _ x: Int, _ y: Int) -> Bool {
            guard let colour = image.colorAt(x: x, y: y) else { return false }
            return colour.redComponent > 0.9 && colour.greenComponent < 0.1 && colour.blueComponent > 0.9
        }

        func drawnBounds(of view: some View) throws -> (first: Int, last: Int, image: NSBitmapImageRep) {
            let image = try #require(
                draw(
                    view.padding(20).frame(width: 320, height: 100).background(marker),
                    width: 320,
                    height: 100
                )
            )
            let drawn = (0..<image.pixelsWide).filter { x in
                (0..<image.pixelsHigh).contains { isMarker(image, x, $0) == false }
            }
            let first = try #require(drawn.first, "drew nothing")
            let last = try #require(drawn.last, "drew nothing")
            return (first, last, image)
        }

        let toggle = try drawnBounds(of: window.autoSyncToggle)
        let picker = try drawnBounds(of: window.pointerModePicker)
        let row = try drawnBounds(of: window.settingsRow)

        let toggleWidth = toggle.last - toggle.first + 1
        let pickerWidth = picker.last - picker.first + 1
        let rowWidth = row.last - row.first + 1

        #expect(
            rowWidth >= toggleWidth + pickerWidth + 8,
            "the row is \(rowWidth) wide, the toggle \(toggleWidth) and the picker \(pickerWidth)"
        )

        // A column of background pixels sits between where the toggle's own
        // width ends and where the picker's own width starts, inside the row.
        let searchStart = row.first + toggleWidth
        let searchEnd = row.last - pickerWidth
        guard searchStart <= searchEnd else {
            Issue.record("the row leaves no room to look for a gap between the toggle and the picker")
            return
        }
        let gapColumn = (searchStart...searchEnd).first { x in
            (0..<row.image.pixelsHigh).allSatisfy { y in isMarker(row.image, x, y) }
        }
        #expect(gapColumn != nil, "no background column sits between the toggle and the picker")
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

    // MARK: the right sidebar

    // The column draws one of two views: the default content, the editor for
    // the one selected element, or the multi-selection view.

    @Test func drawsTheRightSidebarWithItsDefaultContent() {
        expectHosted(
            SelectionSidebar(session: aModel(), canvas: CanvasState()),
            width: 360,
            height: 700,
            "the sidebar with the default content"
        )
    }

    @Test func drawsTheRightSidebarWithAComponentEditor() throws {
        let session = aModel()
        let component = try #require(session.canvas.components.first)
        let canvas = CanvasState()
        canvas.select(componentId: component.id, addingToSelection: false)

        expectHosted(
            SelectionSidebar(session: session, canvas: canvas),
            width: 360,
            height: 700,
            "the sidebar with a component editor"
        )
    }

    @Test func drawsTheRightSidebarWithTheMultiSelectionView() {
        let session = aModel()
        session.addAtDefaultPoint(technologyId: "aws-rds")
        let canvas = CanvasState()
        canvas.select(componentIds: session.canvas.components.map(\.id))

        expectHosted(
            SelectionSidebar(session: session, canvas: canvas),
            width: 360,
            height: 700,
            "the sidebar with the multi-selection view"
        )
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

    // MARK: a report picture

    /// A mermaid diagram block draws a picture on the Report stage. The
    /// picture is the SVG the reader writes, drawn as an image.
    @Test func drawsAMermaidDiagramBlock() throws {
        let drawing = try #require(
            MermaidDrawing.drawing(of: "flowchart LR\n  user[Person] --> api[API]")
        )

        expectDrawn(
            ReportSvgPicture(label: "Login", svg: SvgWriter.svg(of: drawing)),
            width: 400,
            height: 300,
            "the mermaid diagram block"
        )
    }

    /// The whole diagram, drawn on the Report stage the way the export draws
    /// it.
    @Test func drawsTheReportsDataFlowPicture() throws {
        let session = aModel()
        let picture = ReportDataFlowPicture(session: session).picture

        expectDrawn(picture, width: 900, height: 700, "the report data flow picture")
    }

    // MARK: the tag filter control

    /// `aModel()` states no tag, so the control shows the disabled hint row
    /// in place of a tag list, and still draws on the toolbar.
    @Test func theFilterControlShowsADisabledHintRowWithNoTags() async {
        let view = CanvasView(session: aModel(), canvas: CanvasState())

        #expect(view.tagFilterHintRow == "No tags yet. Add a tag on the component panel.")
        expectDrawn(view, "the canvas with the tag filter control and no tags")
    }

    @Test func theFilterLabelReadsFilterWhenNothingNarrowsTheDiagram() async {
        let view = CanvasView(session: aModel(), canvas: CanvasState())

        #expect(view.tagFilterLabel == "Filter")
        #expect(view.isClearFilterEnabled == false)
    }

    @Test func theFilterLabelJoinsThePickedTagsByCommas() async {
        let canvas = CanvasState()
        canvas.pick(tag: "payments")
        canvas.pick(tag: "pci")
        let view = CanvasView(session: aModel(), canvas: canvas)

        #expect(view.tagFilterLabel == "payments, pci")
        #expect(view.isClearFilterEnabled)
    }

    /// The new control is a `Picker` submenu, not a `Stepper`, and the same
    /// binding the control writes through sets the depth on the canvas.
    @Test func settingNeighboursThroughTheControlWritesTheDepthOnTheCanvas() async {
        let canvas = CanvasState()
        let view = CanvasView(session: aModel(), canvas: canvas)

        view.neighbourDepth.wrappedValue = 2

        #expect(canvas.tagFilter.neighbourDepth == 2)
    }

    @Test func turningFocusOnWithNoTagsNamesTheComponentAndEnablesClearFilter() async throws {
        let session = aModel()
        let component = try #require(session.canvas.components.first)
        let componentId = component.id
        let componentName = component.name
        let canvas = CanvasState()
        let view = CanvasView(session: session, canvas: canvas)

        canvas.focus(componentId: componentId)

        #expect(view.tagFilterLabel == "Focus: \(componentName)")
        #expect(view.isClearFilterEnabled)

        canvas.clearTagFilter()

        #expect(canvas.focusedComponentId == nil)
        #expect(canvas.tagFilter.narrow(session.canvas).components.count == session.canvas.components.count)
    }

    /// A pixel test proves the badge itself differs, not only the state
    /// behind it.
    @Test func drawsADifferentBadgeWhileTheFilterNarrowsTheDiagram() async throws {
        let unfiltered = try #require(
            pixels(of: CanvasView(session: aModel(), canvas: CanvasState()), width: 900, height: 700)
        )

        let narrowedCanvas = CanvasState()
        narrowedCanvas.pick(tag: "payments")
        let narrowed = try #require(
            pixels(of: CanvasView(session: aModel(), canvas: narrowedCanvas), width: 900, height: 700)
        )

        #expect(unfiltered != narrowed)
    }

    /// #155: Focus on a component draws the zone it sits in, so the boundary
    /// still reads right. The other case draws the same component with no
    /// zone at all, so the pixels prove the outline is what changed.
    @Test func drawsTheZoneAFocusedComponentSitsIn() async throws {
        let session = ThreatModelSession(useCases: TestDependencies())
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 400, height: 300))
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let canvas = CanvasState()
        canvas.focus(componentId: try #require(session.canvas.components.first).id)

        #expect(canvas.drawn(in: session.canvas).zones.map(\.id) == [zoneId])
        let withZone = try #require(
            pixels(of: CanvasView(session: session, canvas: canvas), width: 900, height: 700)
        )

        let bareSession = ThreatModelSession(useCases: TestDependencies())
        bareSession.add(technologyId: "aws-ec2", x: 100, y: 100)
        let bareCanvas = CanvasState()
        bareCanvas.focus(componentId: try #require(bareSession.canvas.components.first).id)
        let withoutZone = try #require(
            pixels(of: CanvasView(session: bareSession, canvas: bareCanvas), width: 900, height: 700)
        )

        #expect(withZone != withoutZone)
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

    /// The Threats stage builds `ThreatSidebar(session:, focus: .likelihood,
    /// project:)`. With the project passed, the sheet "How often…" opens is
    /// `LikelihoodSheet`, drawn with real content, not the empty sheet a
    /// missing project once left.
    @Test func drawsTheLikelihoodSheetFromTheThreatsStage() async throws {
        let project = await aDrawnProject()
        let model = try #require(project.model)
        let threat = try #require(model.threats.first)

        let sidebar = try #require(
            hostedDrawing(
                of: ThreatSidebar(session: model, focus: .likelihood, project: project),
                width: 420,
                height: 700
            )
        )
        #expect(hasContent(sidebar.image), "the Threats stage sidebar drew a blank rectangle")

        let sheet = try #require(
            hostedDrawing(
                of: LikelihoodSheet(threat: threat, session: model, project: project),
                width: 460,
                height: 560
            )
        )
        #expect(hasContent(sheet.image), "the likelihood sheet drew a blank rectangle")
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

        expectHosted(
            ComponentPanel(session: session, component: component),
            width: 360,
            height: 700,
            "the node panel"
        )
    }

    @Test func drawsTheZonePanel() async throws {
        let session = aModel()
        let zone = try #require(session.canvas.zones.first)

        expectHosted(
            ZonePanel(session: session, zone: zone),
            width: 360,
            height: 700,
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

        expectHosted(
            ConnectionPanel(session: session, connection: connection),
            width: 360,
            height: 700,
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

    /// The result sheet a Terraform import shows, in the words
    /// `threatmodeller import terraform` prints for it.
    @Test func drawsTheTerraformImportSheet() async {
        expectDrawn(
            TerraformImportSheet(
                result: TerraformImportResult(
                    path: "/work/threatmodel/payments.arch",
                    lines: [
                        "added aws-instance-api",
                        "removed aws-s3-bucket-old, which the state no longer holds",
                        "2 resources have no mapping: aws_cloudwatch_metric_alarm (2)",
                        "imported 7 components, 2 zones and 3 flows into" +
                            " /work/threatmodel/payments.arch"
                    ]
                ),
                dismiss: {}
            ),
            width: 520,
            height: 380,
            "the Terraform import sheet"
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

    // MARK: the mark for a proposed component

    /// A proposed component and a live one draw different pictures: the
    /// proposed outline is broken and the chip row holds a Proposed chip.
    @Test func drawsAProposedComponentDifferentlyFromALiveOne() async throws {
        let live = try #require(
            pixels(
                of: aNode(shapeId: "process", risk: nil, statusId: "live"),
                width: 200,
                height: 180
            )
        )
        let proposed = try #require(
            pixels(
                of: aNode(shapeId: "process", risk: nil, statusId: "proposed"),
                width: 200,
                height: 180
            )
        )

        #expect(live != proposed)
    }

    /// A component that states no status draws the picture a live component
    /// draws, so every file written before the attribute draws unchanged.
    @Test func drawsAComponentWithNoStatusAsALiveOne() async throws {
        let unstated = try #require(
            pixels(of: aNode(shapeId: "process", risk: nil), width: 200, height: 180)
        )
        let live = try #require(
            pixels(
                of: aNode(shapeId: "process", risk: nil, statusId: "live"),
                width: 200,
                height: 180
            )
        )

        #expect(unstated == live)
    }

    // MARK: the mark for a user

    /// A user draws with the actor shape, and its chip row tells it from a
    /// technology drawn with the same shape.
    @Test func drawsAUserDifferentlyFromATechnologyWithTheActorShape() async throws {
        expectDrawn(
            aNode(shapeId: "actor", risk: nil, isUser: true),
            width: 200,
            height: 180,
            "the user node"
        )
        let technology = try #require(
            pixels(of: aNode(shapeId: "actor", risk: nil), width: 200, height: 180)
        )
        let user = try #require(
            pixels(of: aNode(shapeId: "actor", risk: nil, isUser: true), width: 200, height: 180)
        )

        #expect(technology != user)
    }

    @Test func drawsANodeThatRaisesNoThreat() async {
        expectDrawn(
            aNode(shapeId: "process", risk: nil),
            width: 200,
            height: 180,
            "a node with no threats"
        )
    }

    /// A library states a colour for one of its classification levels. The
    /// session carries that colour, and the node's sensitivity chip paints
    /// it, instead of the quiet grey every chip painted before.
    @Test func drawsTheSensitivityChipInTheColourALibraryStates() throws {
        let app = TestDependencies()
        app.project.put(
            """
            library "hmg" {
              name = "Government Scheme"

              classification "official" {
                name   = "Official"
                colour = "#ff0000"
              }
            }
            """,
            at: "/work/threatmodel/library/hmg.lib"
        )
        guard case .loaded(let libraries, _) = app.loadLibraries()
            .execute(LoadLibrariesRequest(root: "/work")) else {
            Issue.record("expected the library to load")
            return
        }
        app.useLibraries(libraries)

        let session = ThreatModelSession(useCases: app)
        let colourHex = try #require(
            session.classificationChoices.first { $0.id == "official" }?.colour
        )
        #expect(colourHex == "#ff0000")

        let coloured = try #require(
            draw(
                aNode(
                    shapeId: "process",
                    risk: nil,
                    classificationColour: RiskPalette.colour(fromHex: colourHex)
                ),
                width: 200,
                height: 180
            )
        )
        let plain = try #require(draw(aNode(shapeId: "process", risk: nil), width: 200, height: 180))

        #expect(hasReddishPixel(coloured), "the chip did not draw the library's colour")
        #expect(hasReddishPixel(plain) == false, "the default chip already reads red")
    }

    /// True when a pixel reads with more red than green or blue, the mark of
    /// a chip painted in the library's red rather than the grey default,
    /// which reads equal in every channel.
    private func hasReddishPixel(_ image: NSBitmapImageRep) -> Bool {
        for x in stride(from: 0, to: image.pixelsWide, by: 2) {
            for y in stride(from: 0, to: image.pixelsHigh, by: 2) {
                guard let colour = image.colorAt(x: x, y: y) else { continue }
                if colour.redComponent - colour.greenComponent > 0.15,
                   colour.redComponent - colour.blueComponent > 0.15 {
                    return true
                }
            }
        }
        return false
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

    // MARK: a selected join on the tree canvas

    /// An editor holding a goal fed by one step, with no project to write to.
    private func aDrawnTree() -> (TreeEditor, TreeCanvasState, TreeGraph.Edge) {
        let editor = TreeEditor()
        editor.open(
            SourceAttackTree(
                id: "t",
                name: "T",
                description: nil,
                raisesRiskBy: 10,
                goal: SourceTreeTarget(threatId: "exfiltration", sourceKind: "component", sourceId: "db"),
                root: .step(SourceTreeStep(
                    target: SourceTreeTarget(threatId: "ssrf", sourceKind: "component", sourceId: "api"),
                    note: nil
                ))
            ),
            threats: []
        )
        let ids = editor.graph.nodes.map(\.id)
        return (editor, TreeCanvasState(), TreeGraph.Edge(from: ids[1], to: ids[0]))
    }

    private func aTreeCanvas(_ editor: TreeEditor, _ canvas: TreeCanvasState) -> TreeCanvas {
        TreeCanvas(editor: editor, canvas: canvas, elements: [], bound: nil)
    }

    @Test func drawsTheTreeCanvas() async {
        let (editor, canvas, _) = aDrawnTree()

        expectDrawn(aTreeCanvas(editor, canvas), "the tree canvas")
    }

    /// An editor holding one tree, laid out from the file.
    private func aTreeCanvas(holding root: SourceTreeNode) -> TreeCanvas {
        let editor = TreeEditor()
        editor.open(
            SourceAttackTree(
                id: "t",
                name: "T",
                description: nil,
                raisesRiskBy: 10,
                goal: SourceTreeTarget(threatId: "exfiltration", sourceKind: "component", sourceId: "db"),
                root: root
            ),
            threats: []
        )
        return aTreeCanvas(editor, TreeCanvasState())
    }

    private func aStep(_ threat: String) -> SourceTreeNode {
        .step(SourceTreeStep(
            target: SourceTreeTarget(threatId: threat, sourceKind: "component", sourceId: "api"),
            note: nil
        ))
    }

    /// A chain draws as a line of nodes joined end to end, and an `all_of`
    /// as a fan under one junction. Both draw, and they draw differently.
    @Test func drawsAChainAsALineAndAnAllOfAsAFan() async throws {
        let line = aTreeCanvas(holding: .then([aStep("a"), aStep("b"), aStep("c")]))
        let fan = aTreeCanvas(holding: .all([aStep("a"), aStep("b"), aStep("c")]))

        expectDrawn(line, "the chain")
        expectDrawn(fan, "the fan")

        let linePixels = try #require(pixels(of: line, width: 1200, height: 700))
        let fanPixels = try #require(pixels(of: fan, width: 1200, height: 700))
        #expect(linePixels != fanPixels)
    }

    /// A selected join draws a different picture from an unselected one, so a
    /// person sees which join Delete removes.
    @Test func drawsASelectedJoinDifferentlyFromAnUnselectedOne() async throws {
        let (editor, canvas, edge) = aDrawnTree()
        let unselected = try #require(pixels(of: aTreeCanvas(editor, canvas), width: 900, height: 700))

        let (other, chosen, chosenEdge) = aDrawnTree()
        chosen.select(chosenEdge, addingToSelection: false)
        let selected = try #require(pixels(of: aTreeCanvas(other, chosen), width: 900, height: 700))

        #expect(edge == chosenEdge)
        #expect(unselected != selected)
    }

    // MARK: a box waiting for an element

    /// A box draws, and a canvas holding one draws differently from the
    /// same canvas without it.
    @Test func drawsABoxWaitingForAnElement() async throws {
        let (editor, canvas, _) = aDrawnTree()
        let without = try #require(pixels(of: aTreeCanvas(editor, canvas), width: 900, height: 700))

        let (other, chosen, _) = aDrawnTree()
        #expect(other.drop("placeholder", at: CGPoint(x: 300, y: 300), elements: []) != nil)
        expectDrawn(aTreeCanvas(other, chosen), "the box")
        let with = try #require(pixels(of: aTreeCanvas(other, chosen), width: 900, height: 700))

        #expect(without != with)
    }

    /// A marked sidebar row draws differently from an unmarked one, so a
    /// person sees which elements the selected node reaches.
    @Test func drawsAMarkedSidebarRowDifferentlyFromAnUnmarkedOne() throws {
        let element = TreeElement(kind: "component", sourceId: "api", name: "API", threats: [])
        let marked = TreeElementRow(row: RankedElement(element: element, isConnectable: true), isRanked: true)
        let unmarked = TreeElementRow(row: RankedElement(element: element, isConnectable: false), isRanked: true)

        expectDrawn(marked, width: 260, height: 44, "a marked element row")
        expectDrawn(unmarked, width: 260, height: 44, "an unmarked element row")

        let markedPixels = try #require(pixels(of: marked, width: 260, height: 44))
        let unmarkedPixels = try #require(pixels(of: unmarked, width: 260, height: 44))
        #expect(markedPixels != unmarkedPixels)
    }

    // MARK: how much of the canvas the diagram covers

    /// How far the toolbar band reaches down the canvas. The toolbar floats
    /// over the top of every diagram, and it is the same picture in each, so
    /// a measurement of the diagram starts below it.
    private static let toolbarBand = 80

    /// The rectangle the diagram covers, below the toolbar band, or nil when
    /// the canvas drew nothing but its background.
    ///
    /// The background is read from the bottom right corner, which no diagram
    /// in this file reaches.
    private func drawnBounds(
        of view: some View,
        width: Double,
        height: Double
    ) -> CGRect? {
        guard let image = draw(view, width: width, height: height),
              let background = image.colorAt(x: image.pixelsWide - 2, y: image.pixelsHigh - 2)
        else { return nil }

        var left = image.pixelsWide
        var right = -1
        var top = image.pixelsHigh
        var bottom = -1
        for x in stride(from: 0, to: image.pixelsWide, by: 2) {
            for y in stride(from: Self.toolbarBand, to: image.pixelsHigh, by: 2) {
                guard let colour = image.colorAt(x: x, y: y),
                      Self.differs(colour, from: background) else { continue }
                left = min(left, x)
                right = max(right, x)
                top = min(top, y)
                bottom = max(bottom, y)
            }
        }
        guard right >= 0 else { return nil }
        return CGRect(x: left, y: top, width: right - left, height: bottom - top)
    }

    /// True when two sampled pixels are different colours. The tolerance
    /// covers the anti-aliasing at the edge of a filled rectangle.
    private static func differs(_ one: NSColor, from other: NSColor) -> Bool {
        abs(one.redComponent - other.redComponent) > 0.02
            || abs(one.greenComponent - other.greenComponent) > 0.02
            || abs(one.blueComponent - other.blueComponent) > 0.02
            || abs(one.alphaComponent - other.alphaComponent) > 0.02
    }

    /// #156: a Focus lays the drawn set out on its own, so the picture covers
    /// less of the canvas than the full layout's own coordinates did. Both
    /// canvases draw at the same transform, so the two rectangles are read off
    /// the same picture size.
    @Test func aFocusDrawsASmallerPictureOnceTheDrawnSetIsLaidOut() async throws {
        let session = ThreatModelSession(useCases: TestDependencies())
        _ = session.addZone(x: 100, y: 120, width: 700, height: 480)
        session.add(technologyId: "aws-ec2", x: 600, y: 400)
        let componentId = try #require(session.canvas.components.first).id

        // No layout collaborator: this canvas keeps the model's coordinates,
        // which is what the canvas drew before #156.
        let keeping = CanvasState()
        keeping.focus(componentId: componentId)
        let before = try #require(
            drawnBounds(of: CanvasView(session: session, canvas: keeping), width: 900, height: 700)
        )

        let laidOut = CanvasState()
        laidOut.layouts = session
        laidOut.visibleSize = CGSize(width: 900, height: 700)
        laidOut.focus(componentId: componentId)
        laidOut.transform = CanvasTransform()
        let after = try #require(
            drawnBounds(of: CanvasView(session: session, canvas: laidOut), width: 900, height: 700)
        )

        #expect(after.width * after.height < before.width * before.height)
    }

    // MARK: the MITRE id field

    /// A session holding the ATT&CK matrix this machine synchronised, so the
    /// field searches real rows.
    private func aSessionHoldingTheMatrix() -> ThreatModelSession {
        let useCases = TestDependencies()
        useCases.attackData.put(
            """
            {
              "release": "v19.2",
              "techniques": [
                {
                  "id": "T1190",
                  "name": "Exploit Public-Facing Application",
                  "tactics": ["initial-access"],
                  "subtechnique": false
                },
                {
                  "id": "T1078",
                  "name": "Valid Accounts",
                  "tactics": ["defense-evasion"],
                  "subtechnique": false
                },
                {
                  "id": "T1059.001",
                  "name": "PowerShell",
                  "tactics": ["execution"],
                  "subtechnique": true
                }
              ]
            }
            """,
            fileName: AttackDataLocation.techniquesFileName
        )
        return ThreatModelSession(useCases: useCases)
    }

    private func aMitreIdField(
        _ session: ThreatModelSession,
        ids: [String],
        typed: String
    ) -> MitreIdField {
        MitreIdField(
            title: "ATT&CK techniques this actor uses",
            identifier: "render-mitre-ids",
            ids: .constant(ids),
            search: { text, kind in session.searchAttackData(text, kind: kind) },
            synchronise: {},
            typed: typed
        )
    }

    @Test func drawsTheMitreIdFieldWithNothingInIt() {
        expectDrawn(
            aMitreIdField(aSessionHoldingTheMatrix(), ids: [], typed: "")
                .padding(20),
            width: 520,
            height: 200,
            "the empty MITRE id field"
        )
    }

    @Test func drawsTheMitreIdFieldWithTokens() {
        expectDrawn(
            aMitreIdField(
                aSessionHoldingTheMatrix(),
                ids: ["T1190", "T1078", "T9999"],
                typed: ""
            )
            .padding(20),
            width: 520,
            height: 200,
            "the MITRE id field with tokens"
        )
    }

    @Test func drawsTheMitreIdFieldWithTheSearchListOpen() {
        let field = aMitreIdField(aSessionHoldingTheMatrix(), ids: [], typed: "t10")

        #expect(field.rows.isEmpty == false)
        expectDrawn(field.padding(20), width: 520, height: 300, "the MITRE id field searching")
    }

    /// With no matrix on this machine the field states how to synchronise and
    /// draws the button that runs it.
    @Test func drawsTheMitreIdFieldWithNoSynchronisedData() {
        let session = ThreatModelSession(useCases: TestDependencies())
        let field = aMitreIdField(session, ids: ["T1190"], typed: "")

        #expect(field.holdsData == false)
        expectDrawn(field.padding(20), width: 520, height: 220, "the MITRE id field with no data")
    }

    // MARK: the id token field

    /// Issue #179: the control `Uses`, `Reaches` and `Holds` share.
    private func anIdTokenField(
        ids: [String],
        choices: [IdTokenField.Choice] = ViewRenderTests.clientChoices,
        isOpen: Bool = false,
        search: String = ""
    ) -> IdTokenField {
        IdTokenField(
            identifier: "render-id-tokens",
            ids: .constant(ids),
            choices: choices,
            emptyMessage: "No component to pick yet. Add one on the canvas.",
            isOpen: .constant(isOpen),
            search: .constant(search)
        )
    }

    private static let clientChoices = [
        IdTokenField.Choice(id: "browser", name: "Web Browser", icon: "circle.fill"),
        IdTokenField.Choice(id: "mobile", name: "Mobile App", icon: "circle.fill"),
        IdTokenField.Choice(id: "terminal", name: "Terminal", icon: "circle.fill")
    ]

    @Test func drawsTheIdTokenFieldWithThreeTokens() {
        expectDrawn(
            anIdTokenField(ids: ["browser", "mobile", "terminal"]).padding(20),
            width: 520,
            height: 200,
            "the id token field with three tokens"
        )
    }

    @Test func drawsTheIdTokenFieldWithTheListOpen() {
        expectDrawn(
            anIdTokenField(ids: ["browser"], isOpen: true).padding(20),
            width: 520,
            height: 300,
            "the id token field with the list open"
        )
    }

    /// The empty state: the caller's own choices are empty, so the field
    /// says so instead of drawing a control with nothing to offer.
    @Test func drawsTheIdTokenFieldWithNoChoice() {
        expectDrawn(
            anIdTokenField(ids: [], choices: []).padding(20),
            width: 520,
            height: 100,
            "the id token field with no choice"
        )
    }

    // MARK: the architecture sidebar

    /// A model holding one assumption and one mitigates edge, which is what
    /// the sidebar keeps after the System sheets take the other editors.
    private func aSidebarModel() -> ThreatModelSession {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-waf", x: 0, y: 0)
        session.add(technologyId: "aws-ec2", x: 400, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.setAssumption(
            label: "network-segmented",
            text: "The network is segmented.",
            owner: "platform"
        )
        if ids.count == 2 {
            session.setMitigatesEdge(
                from: ids[0],
                to: ids[1],
                threatIds: ["credential-theft"],
                reducesRiskBy: 80,
                status: "assumed"
            )
        }
        return session
    }

    /// The sidebar keeps the assumptions, the risk tolerance and the mitigates
    /// list, and nothing else. The assumptions header comes first, so it is
    /// visible with no scroll.
    @Test func drawsTheSidebarWithTheAssumptionsHeaderNearTheTop() async throws {
        let session = aSidebarModel()

        // The panel is a scrolling column, so it draws through the hosted
        // path, the way every other scrolling editor in this file draws.
        expectHosted(AssumptionsPanel(session: session), width: 320, height: 640, "the architecture sidebar")

        let above = NSHostingView(rootView: AssumptionsPanel(session: session).aboveTheAssumptions)
        above.frame = CGRect(x: 0, y: 0, width: 320, height: 0)
        let header = above.fittingSize.height + AssumptionsPanel.topPadding

        #expect(
            header < 640,
            Comment(rawValue: "the assumptions header sits \(header) points down the sidebar")
        )
    }

    // MARK: the layout preview

    /// The preview a person watches while the layout search runs.
    ///
    /// The skeleton drew a plain rectangle for each component and no flow at
    /// all, because a layout report holds geometry and nothing else. The
    /// preview draws the real diagram, so the name is inside the node and the
    /// flow is routed across the gap between two nodes.
    @Test func thePreviewDrawsTheComponentNamesAndARoutedFlow() throws {
        let named = try previewPicture(named: true, joined: false)
        let unnamed = try previewPicture(named: false, joined: false)
        let joined = try previewPicture(named: true, joined: true)

        #expect(hasContent(named))
        #expect(differences(named, unnamed) > 0, "the preview drew no component name")

        // The band between the two nodes. Nothing but a routed flow draws
        // there: the nodes sit at the two ends of the picture.
        let middle = (joined.pixelsWide / 2 - 20)..<(joined.pixelsWide / 2 + 20)
        #expect(
            differences(joined, named, columns: middle) > 0,
            "the preview routed no flow between the two components"
        )
    }

    /// A two component model, drawn at the coordinates one report gives.
    private func previewPicture(named: Bool, joined: Bool) throws -> NSBitmapImageRep {
        let subject = LayoutSubject(
            components: [
                aPreviewComponent(id: "api", name: named ? "Orders API" : "", x: 0),
                aPreviewComponent(id: "db", name: named ? "Orders store" : "", x: 700)
            ],
            connections: joined
                ? [ViewedConnection(id: "api->db", sourceComponentId: "api", targetComponentId: "db")]
                : [],
            zones: []
        )
        let layout = LayOutModelResponse(
            components: subject.components.map { LaidOutComponent(id: $0.id, x: $0.x, y: $0.y) },
            zones: []
        )
        return try #require(
            hostedDrawing(
                of: FormingPicture(subject: subject, layout: layout),
                width: 640,
                height: 420
            )
        ).image
    }

    private func aPreviewComponent(id: String, name: String, x: Double) -> ViewedComponent {
        ViewedComponent(
            id: id,
            technologyId: "aws-ec2",
            name: name,
            customName: name.isEmpty ? nil : name,
            providerId: "aws",
            categoryId: "compute",
            x: x,
            y: 0,
            sensitivityId: "confidential",
            threatsDisabled: false,
            isUnknownTechnology: false,
            zoneId: nil
        )
    }

    /// How many pixels of two pictures of the same size read differently.
    private func differences(
        _ one: NSBitmapImageRep,
        _ other: NSBitmapImageRep,
        columns: Range<Int>? = nil
    ) -> Int {
        var count = 0
        for x in columns ?? 0..<one.pixelsWide {
            for y in 0..<one.pixelsHigh {
                guard let left = one.colorAt(x: x, y: y), let right = other.colorAt(x: x, y: y) else {
                    continue
                }
                if abs(left.redComponent - right.redComponent) > 0.02
                    || abs(left.greenComponent - right.greenComponent) > 0.02
                    || abs(left.blueComponent - right.blueComponent) > 0.02 {
                    count += 1
                }
            }
        }
        return count
    }
}
