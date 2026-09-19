import AppKit
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// What a click does when it goes through a real window.
///
/// #177: the palette on the Architecture stage took no input at all. Every
/// column kept its frame and `hitTest` named no cover, because a window-modal
/// sheet is its own window and the content view never sees it. These tests
/// send the click AppKit sends and read what the model holds afterwards.
@MainActor
struct WindowTakesInputTests {
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

    private func splitView(in view: NSView) -> NSSplitView? {
        firstView(of: NSSplitView.self, in: view)
    }

    /// The window a person sees the Architecture stage in, with the palette
    /// shown.
    private func anArchitectureWindow(
        _ project: ProjectSession,
        _ model: ThreatModelSession
    ) -> NSWindow {
        hostedWindow(
            of: ProjectColumns(
                project: project,
                session: model,
                canvas: CanvasState(),
                stage: .constant(.architecture)
            )
        )
    }

    /// A double click on a palette row places a component.
    ///
    /// This is the test #122 lacked: the flow tests called the session, so a
    /// palette that answered no click still passed them.
    @Test func aDoubleClickOnAPaletteRowPlacesAComponent() async throws {
        let project = await aDrawnProject()
        let model = try #require(project.model)
        let window = anArchitectureWindow(project, model)
        let content = try #require(window.contentView)
        let split = try #require(splitView(in: content))
        let palette = try #require(split.arrangedSubviews.first)
        let list = try #require(firstView(of: NSTableView.self, in: palette))
        #expect(list.numberOfRows > 1, "the palette drew \(list.numberOfRows) rows")

        let row = list.convert(list.rect(ofRow: 1), to: nil)
        let point = NSPoint(x: row.midX, y: row.midY)
        let answer = content.hitTest(point)
        #expect(
            answer.map { isInside($0, palette) } == true,
            "the palette row at \(point) answered \(viewChain(from: answer))"
        )

        let before = model.canvas.components.count
        click(window, at: point, count: 1)
        click(window, at: point, count: 2)

        #expect(
            model.canvas.components.count == before + 1,
            "the double click left \(model.canvas.components.count) components, not \(before + 1)"
        )
    }

    /// A single click opens a category, so the technologies under it show.
    @Test func aClickOnACategoryRowOpensIt() async throws {
        let project = await aDrawnProject()
        let model = try #require(project.model)
        let window = anArchitectureWindow(project, model)
        let content = try #require(window.contentView)
        let split = try #require(splitView(in: content))
        let palette = try #require(split.arrangedSubviews.first)
        let list = try #require(firstView(of: NSTableView.self, in: palette))
        let before = list.numberOfRows
        let category = try #require(Self.categoryRow(in: list))

        let row = list.convert(list.rect(ofRow: category), to: nil)
        click(window, at: NSPoint(x: row.midX, y: row.midY), count: 1)
        settle(window)

        #expect(
            list.numberOfRows > before,
            "the click on row \(category) left \(list.numberOfRows) rows, from \(before)"
        )
    }

    /// The first row that is neither a section header nor the User row, which
    /// is a category a click opens. The palette draws the categories closed,
    /// so it is the first row of its height after the Users section.
    private static func categoryRow(in list: NSTableView) -> Int? {
        (0..<list.numberOfRows).first { row in
            list.rowView(atRow: row, makeIfNecessary: true)?
                .subviews.contains { "\(type(of: $0))".contains("CellView") } == true
                && row > 1
        }
    }

    /// A sheet asked for with nothing to draw still draws something.
    ///
    /// A window-modal sheet whose body draws nothing presents a 470 by 80
    /// window with no content view subviews. It takes every click in the
    /// window, it shows no control that closes it, and `hitTest` on the
    /// content view answers the column under it as though nothing were
    /// there. That is what made the palette take no input.
    @Test func aSystemSheetWithNoModelDrawsSomething() async throws {
        let session = ProjectSession(
            useCases: TestDependencies(),
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        let window = hostedWindow(of: ProjectWindow(session: session), width: 1000, height: 700)

        session.systemSheet = .assets
        settle(window, 1)

        let sheet = try #require(window.attachedSheet, "the System sheet did not open")
        let drawn = try #require(sheet.contentView)
        #expect(
            drawn.subviews.isEmpty == false,
            "the sheet drew nothing at \(drawn.frame) and takes every click in the window"
        )
    }

    /// The `.arch` text for a system named "broken" whose file does not
    /// parse. `choose` and `open` reach for it by its file name.
    private let brokenSystemArch = "system \"Broken\" {"

    /// The `.arch` text for a system named "payments" that parses.
    private let workingSystemArch = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    /// A project holding one system that parses, "payments", and one that
    /// does not, "broken", so a test can switch between a drawn model and no
    /// model in the same root.
    private func aProjectWithAWorkingAndABrokenSystem() -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(workingSystemArch, at: "/work/threatmodel/payments.arch")
        useCases.project.put(brokenSystemArch, at: "/work/threatmodel/broken.arch")
        let session = ProjectSession(useCases: useCases, watcher: FakeProjectWatcher(), defaults: aTestDefaults())
        return (session, useCases)
    }

    /// The `terraform show -json` golden state `ProjectSessionTests` reads,
    /// copied to its own temporary file so two tests never race on one path.
    private static func terraformStateFile() throws -> String {
        let text = try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("ThreatModelKit/Tests/Goldens/terraform-aws-state.json"),
            encoding: .utf8
        )
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("terraform-aws-state-\(UUID().uuidString).json")
        try text.write(to: path, atomically: true, encoding: .utf8)
        return path.path
    }

    /// Waits for this to answer true, checked every tenth of a second, for
    /// at most two seconds, and then gives up. A sheet that never presents
    /// on this runner does not spin a run loop for the length of the whole
    /// suite: `#expect` after this call states plainly what did not happen.
    private func pollsFor(_ seconds: TimeInterval = 2, _ condition: () -> Bool) {
        let deadline = Date().addingTimeInterval(seconds)
        while condition() == false, Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        }
    }

    /// A sheet is up: `window.attachedSheet` is not nil within two seconds.
    private func verifiesASheetIsUp(_ window: NSWindow, _ label: String) {
        pollsFor { window.attachedSheet != nil }
        #expect(window.attachedSheet != nil, "\(label): no sheet opened")
    }

    /// A window that hosts one piece of content at a time, its content
    /// swapped in place rather than a fresh `NSWindow` built for each: this
    /// test checks seven sheets' content on top of six project windows
    /// already open in the same run, and a machine already carrying that
    /// many windows answers a seventh, eighth and ninth new one less and
    /// less reliably.
    @MainActor
    private final class ContentWindow {
        private let controller = NSHostingController(rootView: AnyView(EmptyView()))
        let window: NSWindow

        init() {
            controller.sizingOptions = []
            window = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 500, height: 400),
                styleMask: [.titled, .closable, .resizable, .miniaturizable, .fullSizeContentView],
                backing: .buffered,
                defer: false
            )
            window.contentViewController = controller
            if NSApp.activationPolicy() != .regular { NSApp.setActivationPolicy(.regular) }
            NSApp.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
        }

        func shows(_ view: some View) {
            controller.rootView = AnyView(view)
        }
    }

    /// This view draws something and holds a control that closes it: shown
    /// on its own, in a window nothing presents it as a sheet in, Return
    /// runs the dismiss this view was built with.
    ///
    /// A rendered picture of a sheet's content is not a reliable read in
    /// this runner: a view that draws nothing still samples dozens of
    /// distinct colours once dithering is counted, close to as many as a
    /// view with a real icon, a line of text and a button draws. Pressing
    /// the one keyboard shortcut every close control on every sheet in this
    /// window carries is not fooled by dithering: nothing answers Return
    /// unless a real, focusable control is there to answer it, so a miss
    /// here is drawing nothing, not a rendering artefact. `NSWindow.attachedSheet`
    /// does not draw its content in this runner, so this shows the same
    /// content the sheet builds, directly, the way `ProjectWindow`'s own
    /// static content functions let it, rather than reading what is inside
    /// a real, hosted sheet.
    private func verifiesTheContentDrawsSomethingAndCloses(
        in contentWindow: ContentWindow,
        _ label: String,
        content: (@escaping () -> Void) -> some View
    ) {
        var closed = false
        contentWindow.shows(content({ closed = true }))
        settle(contentWindow.window, 0.5)
        pressReturn(contentWindow.window)
        pollsFor { closed }
        #expect(closed, "\(label): Return did not run the sheet's close control")
    }

    /// A double click on the palette's second row places a component. Run
    /// once a sheet is closed, this states the #177 symptom from the other
    /// side: the window takes a click again once the sheet comes down.
    private func paletteAnswersAClick(in window: NSWindow, model: ThreatModelSession) throws {
        let before = model.canvas.components.count

        // A point read once, before the loop, goes stale the moment a
        // retry's own settle reflows the window: a stray sheet closing, or
        // a notice above the columns changing height, moves the palette
        // under it. Every attempt below re-reads the row's own point fresh,
        // the way a person looks again before a second click.
        func currentPaletteRowPoint() throws -> NSPoint {
            let content = try #require(window.contentView)
            let split = try #require(splitView(in: content))
            let palette = try #require(split.arrangedSubviews.first)
            let list = try #require(firstView(of: NSTableView.self, in: palette))
            let row = list.convert(list.rect(ofRow: 1), to: nil)
            return NSPoint(x: row.midX, y: row.midY)
        }

        // A machine under load from other tests running at the same time
        // can space the two clicks of a double click further apart than
        // AppKit reads as one, leave the window not key yet, or leave a
        // sheet this test already closed still attached, so a miss is
        // retried, clearing a stray sheet first, before it is read as the
        // palette taking no input.
        var lastPoint = NSPoint.zero
        for _ in 0..<5 where model.canvas.components.count == before {
            if let stray = window.attachedSheet {
                window.endSheet(stray)
                settle(window, 0.5)
            }
            window.makeKeyAndOrderFront(nil)
            settle(window, 0.3)
            let point = try currentPaletteRowPoint()
            lastPoint = point
            click(window, at: point, count: 1)
            click(window, at: point, count: 2)
            settle(window, 1)
        }

        if model.canvas.components.count == before {
            let content = try #require(window.contentView)
            let answer = content.hitTest(lastPoint)
            print(
                "PALETTE DEBUG miss: point=\(lastPoint) hit=\(viewChain(from: answer)) "
                    + "isKey=\(window.isKeyWindow) attachedSheet=\(String(describing: window.attachedSheet))"
            )
        }

        #expect(
            model.canvas.components.count == before + 1,
            "the palette left \(model.canvas.components.count) components after the sheet closed, not \(before + 1)"
        )
    }

    /// Every sheet `ProjectWindow` holds draws something when the value it
    /// reads is nil, offers a control that closes it, and leaves the palette
    /// answering a click once it is gone.
    ///
    /// `ProjectWindow` presents seven sheets: the System sheet
    /// (`.sheet(item: systemSheet)`), Diagnostics, Check Summary, Terraform
    /// Import, History, Planned Work and Libraries. The last five hold an
    /// `if let value { ... } else { NothingToShowSheet(...) }`, each drawn
    /// through `ProjectWindow`'s own static content functions;
    /// `ProjectWindowMissingValueTests` (#256) already proves those five
    /// draw something distinct with nothing to show, and
    /// `NothingToShowSheetTests` already proves `NothingToShowSheet`'s own
    /// control closes it on Return. This test adds what neither states:
    /// Diagnostics and Check Summary hold no nil branch and no coverage of
    /// their own, and no test states that the palette answers a click again
    /// once any of the seven sheets comes down.
    ///
    /// Every open and close here writes the session property its own
    /// control writes, the way `aSystemSheetWithNoModelDrawsSomething` opens
    /// the assets sheet, and every wait for `attachedSheet` gives up after
    /// two seconds rather than run for as long as the suite allows.
    @Test func noSheetInTheProjectWindowDrawsNothing() async throws {
        let contentWindow = ContentWindow()

        // The System sheet: the session property the System menu and its
        // toolbar control both write.
        let freshUseCases = TestDependencies()
        let freshSession = ProjectSession(
            useCases: freshUseCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        let freshWindow = hostedWindow(of: ProjectWindow(session: freshSession), width: 1400, height: 900)

        freshSession.systemSheet = .assets
        verifiesASheetIsUp(freshWindow, "System sheet")
        verifiesTheContentDrawsSomethingAndCloses(in: contentWindow, "System sheet") { dismiss in
            ProjectWindow.systemSheetContent(kind: .assets, model: nil, dismiss: dismiss)
        }
        freshSession.systemSheet = nil
        pollsFor { freshWindow.attachedSheet == nil }
        if freshWindow.attachedSheet != nil { pollsFor { freshWindow.attachedSheet == nil } }
        #expect(freshWindow.attachedSheet == nil, "System sheet: still up after closing")

        // The History sheet: the History button stays disabled while there
        // is no history to read, so nothing ever presents it with
        // `history == nil` through a click; the session property it writes
        // is the way in, the same as the System sheet's.
        freshSession.isShowingHistory = true
        verifiesASheetIsUp(freshWindow, "History sheet")
        verifiesTheContentDrawsSomethingAndCloses(in: contentWindow, "History sheet") { dismiss in
            ProjectWindow.historySheetContent(history: nil, dismiss: dismiss)
        }
        freshSession.isShowingHistory = false
        pollsFor { freshWindow.attachedSheet == nil }
        if freshWindow.attachedSheet != nil { pollsFor { freshWindow.attachedSheet == nil } }
        #expect(freshWindow.attachedSheet == nil, "History sheet: still up after closing")

        freshUseCases.project.put(workingSystemArch, at: "/first/threatmodel/payments.arch")
        await freshSession.open(root: "/first")
        let freshModel = try #require(freshSession.model)
        settle(freshWindow, 1)
        try paletteAnswersAClick(in: freshWindow, model: freshModel)
        freshWindow.close()

        // Diagnostics: opening on a system that does not parse leaves an
        // error diagnostic, and the window presents the sheet on its own,
        // the way a parse fault interrupts a person mid-edit. Its own
        // window, so its own state never carries into the next sheet's.
        // Diagnostics has no session flag: its Close button carries
        // `.keyboardShortcut(.defaultAction)`, so Return runs it, the same
        // as `NothingToShowSheet`'s own Close does.
        let (diagnosticsProject, _) = aProjectWithAWorkingAndABrokenSystem()
        let diagnosticsWindow = hostedWindow(
            of: ProjectWindow(session: diagnosticsProject),
            width: 1400,
            height: 900
        )
        await diagnosticsProject.open(root: "/work", preferring: "broken")
        verifiesASheetIsUp(diagnosticsWindow, "Diagnostics sheet")
        verifiesTheContentDrawsSomethingAndCloses(in: contentWindow, "Diagnostics sheet") { dismiss in
            DiagnosticsSheet(
                fileName: diagnosticsProject.diagnosticsFileName ?? "",
                diagnostics: diagnosticsProject.diagnostics,
                dismiss: dismiss
            )
        }
        pressReturn(try #require(diagnosticsWindow.attachedSheet))
        pollsFor { diagnosticsWindow.attachedSheet == nil }
        if diagnosticsWindow.attachedSheet != nil { pollsFor { diagnosticsWindow.attachedSheet == nil } }
        #expect(diagnosticsWindow.attachedSheet == nil, "Diagnostics sheet: still up after Return")

        await diagnosticsProject.choose("payments")
        settle(diagnosticsWindow, 1)
        let diagnosticsModel = try #require(diagnosticsProject.model)
        try paletteAnswersAClick(in: diagnosticsWindow, model: diagnosticsModel)
        diagnosticsWindow.close()

        // Check Summary: driven straight from the session, the way the
        // toolbar control's own `.disabled` guard never runs for this test,
        // so a plain working project is enough; a broken sibling system
        // would also leave an error diagnostic that opens the Diagnostics
        // sheet at the same time, over this one.
        let checkSummaryUseCases = TestDependencies()
        checkSummaryUseCases.project.put(workingSystemArch, at: "/work/threatmodel/payments.arch")
        let checkSummaryProject = ProjectSession(
            useCases: checkSummaryUseCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        let checkSummaryWindow = hostedWindow(
            of: ProjectWindow(session: checkSummaryProject),
            width: 1400,
            height: 900
        )
        await checkSummaryProject.open(root: "/work")
        checkSummaryProject.isShowingCheckSummary = true
        verifiesASheetIsUp(checkSummaryWindow, "Check Summary sheet")
        verifiesTheContentDrawsSomethingAndCloses(in: contentWindow, "Check Summary sheet") { dismiss in
            CheckSummarySheet(systems: checkSummaryProject.checkedSystems, dismiss: dismiss)
        }
        checkSummaryProject.isShowingCheckSummary = false
        pollsFor { checkSummaryWindow.attachedSheet == nil }
        if checkSummaryWindow.attachedSheet != nil { pollsFor { checkSummaryWindow.attachedSheet == nil } }
        #expect(checkSummaryWindow.attachedSheet == nil, "Check Summary sheet: still up after closing")

        settle(checkSummaryWindow, 1)
        let checkSummaryModel = try #require(checkSummaryProject.model)
        try paletteAnswersAClick(in: checkSummaryWindow, model: checkSummaryModel)
        checkSummaryWindow.close()

        // Planned Work: opened with a model present, then the project
        // closes entirely, so `session.model` goes nil while the sheet
        // stays on screen, the way #177 found it rather than the way a
        // disabled button prevents reaching it in the first place.
        let plannedWorkUseCases = TestDependencies()
        plannedWorkUseCases.project.put(workingSystemArch, at: "/work/threatmodel/payments.arch")
        let plannedWorkProject = ProjectSession(
            useCases: plannedWorkUseCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        let plannedWorkWindow = hostedWindow(
            of: ProjectWindow(session: plannedWorkProject),
            width: 1400,
            height: 900
        )
        await plannedWorkProject.open(root: "/work")
        plannedWorkProject.isShowingPlannedWork = true
        pollsFor { plannedWorkWindow.attachedSheet != nil }
        #expect(plannedWorkWindow.attachedSheet != nil, "Planned Work sheet: did not open")

        await plannedWorkProject.open(root: "/nowhere")
        settle(plannedWorkWindow, 0.5)
        verifiesASheetIsUp(plannedWorkWindow, "Planned Work sheet, no model")
        verifiesTheContentDrawsSomethingAndCloses(in: contentWindow, "Planned Work sheet, no model") { dismiss in
            ProjectWindow.plannedWorkSheetContent(project: plannedWorkProject, model: nil, dismiss: dismiss)
        }
        plannedWorkProject.isShowingPlannedWork = false
        pollsFor { plannedWorkWindow.attachedSheet == nil }
        if plannedWorkWindow.attachedSheet != nil { pollsFor { plannedWorkWindow.attachedSheet == nil } }
        #expect(plannedWorkWindow.attachedSheet == nil, "Planned Work sheet: still up after closing")

        await plannedWorkProject.open(root: "/work")
        settle(plannedWorkWindow, 1)
        let plannedWorkModel = try #require(plannedWorkProject.model)
        try paletteAnswersAClick(in: plannedWorkWindow, model: plannedWorkModel)
        plannedWorkWindow.close()

        // Libraries: the same loss of the project leaves `session.root` nil
        // while the sheet stays on screen.
        let librariesUseCases = TestDependencies()
        librariesUseCases.project.put(workingSystemArch, at: "/work/threatmodel/payments.arch")
        let librariesProject = ProjectSession(
            useCases: librariesUseCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        let librariesWindow = hostedWindow(of: ProjectWindow(session: librariesProject), width: 1400, height: 900)
        await librariesProject.open(root: "/work")
        librariesProject.isShowingLibraries = true
        pollsFor { librariesWindow.attachedSheet != nil }
        #expect(librariesWindow.attachedSheet != nil, "Libraries sheet: did not open")

        await librariesProject.open(root: "/nowhere")
        settle(librariesWindow, 0.5)
        verifiesASheetIsUp(librariesWindow, "Libraries sheet, no project")
        verifiesTheContentDrawsSomethingAndCloses(in: contentWindow, "Libraries sheet, no project") { dismiss in
            ProjectWindow.librariesSheetContent(session: librariesProject, root: nil, dismiss: dismiss)
        }
        librariesProject.isShowingLibraries = false
        pollsFor { librariesWindow.attachedSheet == nil }
        if librariesWindow.attachedSheet != nil { pollsFor { librariesWindow.attachedSheet == nil } }
        #expect(librariesWindow.attachedSheet == nil, "Libraries sheet: still up after closing")

        await librariesProject.open(root: "/work")
        settle(librariesWindow, 1)
        let librariesModel = try #require(librariesProject.model)
        try paletteAnswersAClick(in: librariesWindow, model: librariesModel)
        librariesWindow.close()

        // Terraform Import: a real import presents the result sheet on its
        // own; dismissing the result while the sheet stays up leaves it
        // with nothing to show, the way closing the project out from under
        // Planned Work and Libraries did.
        let terraformUseCases = TestDependencies()
        terraformUseCases.project.put(workingSystemArch, at: "/work/threatmodel/payments.arch")
        let terraformProject = ProjectSession(
            useCases: terraformUseCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        let terraformWindow = hostedWindow(of: ProjectWindow(session: terraformProject), width: 1400, height: 900)
        await terraformProject.open(root: "/work")
        let stateFile = try Self.terraformStateFile()
        await terraformProject.importTerraform(fileAt: stateFile)
        pollsFor { terraformWindow.attachedSheet != nil }
        #expect(terraformWindow.attachedSheet != nil, "Terraform Import sheet: did not open")

        terraformProject.dismissTerraformImportResult()
        settle(terraformWindow, 0.5)
        verifiesASheetIsUp(terraformWindow, "Terraform Import sheet, no result")
        verifiesTheContentDrawsSomethingAndCloses(in: contentWindow, "Terraform Import sheet, no result") { dismiss in
            ProjectWindow.terraformImportSheetContent(result: nil, dismiss: dismiss)
        }
        terraformProject.isShowingTerraformImport = false
        pollsFor { terraformWindow.attachedSheet == nil }
        if terraformWindow.attachedSheet != nil { pollsFor { terraformWindow.attachedSheet == nil } }
        #expect(terraformWindow.attachedSheet == nil, "Terraform Import sheet: still up after closing")
        terraformWindow.close()

        // A window opened fresh over the same session, its sheet already
        // closed, still takes a click: the same session `importTerraform`
        // and the sheet's own close left behind, read through a window
        // that never carried the sheet's own AppKit lifecycle.
        let secondTerraformWindow = hostedWindow(
            of: ProjectWindow(session: terraformProject),
            width: 1400,
            height: 900
        )
        settle(secondTerraformWindow, 1)
        let terraformModel = try #require(terraformProject.model)
        try paletteAnswersAClick(in: secondTerraformWindow, model: terraformModel)
        secondTerraformWindow.close()
        contentWindow.window.close()
    }

    /// Moves the pointer to a point in window coordinates.
    private func movePointer(_ window: NSWindow, to point: NSPoint) {
        window.acceptsMouseMovedEvents = true
        guard let event = NSEvent.mouseEvent(
            with: .mouseMoved,
            location: point,
            modifierFlags: [],
            timestamp: ProcessInfo.processInfo.systemUptime,
            windowNumber: window.windowNumber,
            context: nil,
            eventNumber: 0,
            clickCount: 0,
            pressure: 0
        ) else { return }
        window.sendEvent(event)
        settle(window, 0.3)
    }

    /// The palette takes a click while the canvas holds the pointer.
    ///
    /// The canvas installs `NSEvent` local monitors for the wheel, the
    /// middle button and the Space key while it is on screen. A monitor that
    /// answered nil for a press would swallow it everywhere in the
    /// application, the palette included. None of the three does: the wheel
    /// and the middle button answer nil only while the pointer is over the
    /// canvas, and the Space monitor always passes the key on.
    @Test func thePaletteTakesAClickWhileTheCanvasHoldsThePointer() async throws {
        let project = await aDrawnProject()
        let model = try #require(project.model)
        let canvas = CanvasState()
        let window = hostedWindow(
            of: ProjectColumns(
                project: project,
                session: model,
                canvas: canvas,
                stage: .constant(.architecture)
            )
        )
        let content = try #require(window.contentView)
        let split = try #require(splitView(in: content))
        let palette = try #require(split.arrangedSubviews.first)
        let canvasColumn = split.arrangedSubviews[1]
        let canvasFrame = canvasColumn.convert(canvasColumn.bounds, to: nil)
        let paletteEdge = palette.convert(palette.bounds, to: nil).maxX

        movePointer(
            window,
            to: NSPoint(x: (paletteEdge + canvasFrame.maxX) / 2, y: canvasFrame.midY)
        )

        let list = try #require(firstView(of: NSTableView.self, in: palette))
        let row = list.convert(list.rect(ofRow: 1), to: nil)
        let point = NSPoint(x: row.midX, y: row.midY)
        let before = model.canvas.components.count
        click(window, at: point, count: 1)
        click(window, at: point, count: 2)

        #expect(
            model.canvas.components.count == before + 1,
            "with the pointer over the canvas the double click left \(model.canvas.components.count) components"
        )
    }

    /// The layout preview leaves the palette taking clicks.
    ///
    /// The window draws the preview in place of the columns while the search
    /// runs, never over them, so no view of the preview can take a click
    /// meant for the palette. Once the preview is dropped the palette
    /// answers again.
    @Test func theLayoutPreviewLeavesThePaletteTakingClicks() async throws {
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
        let project = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await project.open(root: "/work")
        let model = try #require(project.model)

        let drawn = useCases.viewThreatModel().execute(ViewThreatModelRequest())
        let subject = LayoutSubject(
            components: drawn.components,
            connections: drawn.connections,
            zones: drawn.zones
        )
        useCases.layoutProgress?.describe(subject)
        _ = project.watchTheLayout()
        useCases.layoutProgress?.report(
            LayOutModelResponse(
                components: subject.components.map { LaidOutComponent(id: $0.id, x: $0.x, y: $0.y) },
                zones: subject.zones.map {
                    LaidOutZone(id: $0.id, x: $0.x, y: $0.y, width: $0.width, height: $0.height)
                }
            )
        )
        project.stopWatchingTheLayout()
        await Task.yield()
        await Task.yield()
        #expect(project.layoutPreview != nil, "the preview did not draw")

        let window = hostedWindow(of: ProjectWindow(session: project), width: 1200, height: 800)
        let content = try #require(window.contentView)
        #expect(
            splitView(in: content) == nil,
            "the preview drew beside the columns rather than in place of them"
        )

        project.forgetTheLayoutPreview()
        settle(window, 1)
        let split = try #require(splitView(in: content), "the columns did not come back")
        let palette = try #require(split.arrangedSubviews.first)
        let list = try #require(firstView(of: NSTableView.self, in: palette))
        let row = list.convert(list.rect(ofRow: 1), to: nil)
        let point = NSPoint(x: row.midX, y: row.midY)
        let before = model.canvas.components.count
        click(window, at: point, count: 1)
        click(window, at: point, count: 2)

        #expect(
            model.canvas.components.count == before + 1,
            "after the preview the double click left \(model.canvas.components.count) components"
        )
    }
}
