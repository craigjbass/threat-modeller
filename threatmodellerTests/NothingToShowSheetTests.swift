import AppKit
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The image a view draws at a stated size, or nil.
@MainActor
private func draw(_ view: some View, width: Double = 380, height: Double = 140) -> NSBitmapImageRep? {
    let renderer = ImageRenderer(content: view.frame(width: width, height: height))
    renderer.scale = 1
    guard let image = renderer.cgImage else { return nil }
    return NSBitmapImageRep(cgImage: image)
}

/// Every sampled pixel of a drawn view, so one picture is compared with
/// another. Text that changed moves some of these.
@MainActor
private func pixels(of view: some View, width: Double = 380, height: Double = 140) -> [String]? {
    guard let image = draw(view, width: width, height: height) else { return nil }
    var read: [String] = []
    for x in stride(from: 0, to: image.pixelsWide, by: 2) {
        for y in stride(from: 0, to: image.pixelsHigh, by: 2) {
            guard let colour = image.colorAt(x: x, y: y) else { continue }
            read.append(
                String(
                    format: "%.2f,%.2f,%.2f,%.2f",
                    colour.redComponent,
                    colour.greenComponent,
                    colour.blueComponent,
                    colour.alphaComponent
                )
            )
        }
    }
    return read
}

/// What `NothingToShowSheet` draws: the name of the missing value, in the
/// words the caller passed, and the one control that closes the sheet.
@MainActor
struct NothingToShowSheetTests {
    @Test func nothingToShowSheetDrawsTheNameOfWhatIsMissing() throws {
        let shortName = try #require(
            pixels(of: NothingToShowSheet(says: "Nothing here.", dismiss: {}))
        )
        let longName = try #require(
            pixels(of: NothingToShowSheet(
                says: "The Terraform import result has gone from the session entirely.",
                dismiss: {}
            ))
        )

        #expect(
            shortName != longName,
            "the sheet drew the same picture for two different missing-thing names"
        )
    }

    @Test func pressingTheSheetsDefaultControlClosesIt() throws {
        var closed = false
        let sheet = NothingToShowSheet(says: "Nothing here.", dismiss: { closed = true })
        let window = hostedWindow(of: sheet, width: 480, height: 200)
        let press = try #require(
            NSEvent.keyEvent(
                with: .keyDown,
                location: .zero,
                modifierFlags: [],
                timestamp: ProcessInfo.processInfo.systemUptime,
                windowNumber: window.windowNumber,
                context: nil,
                characters: "\r",
                charactersIgnoringModifiers: "\r",
                isARepeat: false,
                keyCode: 36
            ),
            "could not build the Return key press"
        )

        window.sendEvent(press)
        RunLoop.current.run(until: Date().addingTimeInterval(0.2))

        #expect(closed, "pressing Return, the control's default action, did not close the sheet")
    }

    /// `NothingToShowSheet` holds three rows, an icon, one line of text and
    /// one button, each the `VStack`'s own 14-point spacing apart. A second
    /// button adds a whole extra row, so the sheet's own natural height,
    /// drawn with the text held fixed, states the control count without
    /// counting AppKit views: this runner does not draw a `Button`'s AppKit
    /// view at all until the window is on a real, key, trusted-accessibility
    /// screen, so no view-count or accessibility-tree read of a hosted
    /// window sees it here.
    @Test func nothingToShowSheetHoldsExactlyOneControl() throws {
        let sheet = NothingToShowSheet(says: "Nothing here.", dismiss: {})
        let renderer = ImageRenderer(content: sheet)
        renderer.scale = 1
        let image = try #require(renderer.cgImage, "the sheet drew nothing")

        #expect(
            image.height < 180,
            "the sheet drew \(image.height) points tall for an icon, one line of text and one button; a second button adds a whole row and would draw taller"
        )
    }
}

/// Each sheet `ProjectWindow` presents with nothing to show names its own
/// missing value. #256: the structural test that scanned `ProjectWindow.swift`
/// for the five `.sheet(` sites is gone; these drive the window itself.
@MainActor
struct ProjectWindowMissingValueTests {
    private func aSession() -> ProjectSession {
        ProjectSession(
            useCases: TestDependencies(),
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
    }

    /// Each of the five sheets the project window presents opens, the way
    /// `aSystemSheetWithNoModelDrawsSomething` opens the assets sheet: by
    /// writing the session state the control writes, not by clicking a
    /// toolbar button. A hosted, on-screen `NSWindow.attachedSheet` does not
    /// draw its content in this runner (proved by rendering the same sheet
    /// at two different message lengths and reading back identical pixels
    /// both times), so this test opens each sheet for real, to prove the
    /// control reaches it, and separately draws the same content the sheet
    /// draws, through the window's own content-building functions, to read
    /// the words.
    @Test func eachSheetInTheProjectWindowNamesItsOwnMissingValue() async throws {
        let session = aSession()
        let window = hostedWindow(of: ProjectWindow(session: session), width: 1000, height: 700)

        session.systemSheet = .assets
        settle(window, 1)
        #expect(window.attachedSheet != nil, "the System sheet did not open with no model")
        session.systemSheet = nil
        settle(window, 0.3)

        session.isShowingPlannedWork = true
        settle(window, 1)
        #expect(window.attachedSheet != nil, "the Planned Work sheet did not open with no model")
        session.isShowingPlannedWork = false
        settle(window, 0.3)

        session.isShowingLibraries = true
        settle(window, 1)
        #expect(window.attachedSheet != nil, "the Libraries sheet did not open with no project")
        session.isShowingLibraries = false
        settle(window, 0.3)

        session.isShowingHistory = true
        settle(window, 1)
        #expect(window.attachedSheet != nil, "the History sheet did not open with no history")
        session.isShowingHistory = false
        settle(window, 0.3)

        let pictures = [
            try #require(pixels(of: ProjectWindow.systemSheetContent(
                kind: .assets, model: nil, dismiss: {}
            ))),
            try #require(pixels(of: ProjectWindow.plannedWorkSheetContent(
                project: session, model: nil, dismiss: {}
            ))),
            try #require(pixels(of: ProjectWindow.librariesSheetContent(
                session: session, root: nil, dismiss: {}
            ))),
            try #require(pixels(of: ProjectWindow.historySheetContent(
                history: nil, dismiss: {}
            ))),
            try #require(pixels(of: ProjectWindow.terraformImportSheetContent(
                result: nil, dismiss: {}
            )))
        ]
        let blank = try #require(pixels(of: NothingToShowSheet(says: "", dismiss: {})))

        for picture in pictures {
            #expect(picture != blank, "a sheet with nothing to show drew the same picture as an empty missing-value name")
        }
        for first in 0..<pictures.count {
            for second in (first + 1)..<pictures.count {
                #expect(
                    pictures[first] != pictures[second],
                    "sheet \(first) and sheet \(second) drew the same missing-value picture"
                )
            }
        }
    }
}
