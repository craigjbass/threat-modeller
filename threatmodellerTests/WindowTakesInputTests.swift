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
