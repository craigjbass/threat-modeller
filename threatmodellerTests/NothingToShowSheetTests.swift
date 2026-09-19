import AppKit
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// What `NothingToShowSheet` draws: the name of the missing value, in the
/// words the caller passed, and the one control that closes the sheet.
@MainActor
struct NothingToShowSheetTests {
    /// The image a view draws at a stated size, or nil.
    private func draw(_ view: some View, width: Double = 380, height: Double = 140) -> NSBitmapImageRep? {
        let renderer = ImageRenderer(content: view.frame(width: width, height: height))
        renderer.scale = 1
        guard let image = renderer.cgImage else { return nil }
        return NSBitmapImageRep(cgImage: image)
    }

    /// Every sampled pixel of a drawn view, so one picture is compared with
    /// another. Text that changed moves some of these.
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
}
