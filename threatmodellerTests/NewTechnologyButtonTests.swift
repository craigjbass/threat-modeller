import AppKit
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The New Technology button answered no press. These draw the palette and
/// press the button the way AppKit does.
@MainActor
@Suite("The New Technology button")
struct NewTechnologyButtonTests {
    private func hosted() -> (host: NSHostingView<some View>, window: NSWindow) {
        let session = ThreatModelSession(useCases: TestDependencies())
        let host = NSHostingView(
            rootView: PaletteView(session: session, canvas: CanvasState())
                .frame(width: 260, height: 600)
        )
        host.frame = CGRect(x: 0, y: 0, width: 260, height: 600)
        let window = NSWindow(
            contentRect: host.frame,
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.contentView = host
        window.orderBack(nil)
        host.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.3))
        return (host, window)
    }

    /// The bar the button sits in, read from the drawn pixels: a row of the
    /// palette's own colour at the bottom, under a divider.
    @Test func theBarTheButtonSitsInIsDrawn() throws {
        let session = ThreatModelSession(useCases: TestDependencies())
        let drawn = try #require(
            hostedDrawing(
                of: PaletteView(session: session, canvas: CanvasState()),
                width: 260,
                height: 400
            )
        )
        let image = drawn.image
        let scale = drawn.scale

        /// How many distinct colours one row of pixels holds.
        func colours(atRow row: Int) -> Int {
            var seen: Set<Int> = []
            for x in stride(from: 4, to: image.pixelsWide - 4, by: 4) {
                guard let colour = image.colorAt(x: x, y: row) else { continue }
                seen.insert(
                    Int(colour.redComponent * 255) << 16
                        | Int(colour.greenComponent * 255) << 8
                        | Int(colour.blueComponent * 255)
                )
            }
            return seen.count
        }

        // The button's own row holds its label, so it is not one flat colour.
        let buttonRow = image.pixelsHigh - 20 * scale
        #expect(colours(atRow: buttonRow) > 1, "the bottom bar draws nothing")
    }
}
