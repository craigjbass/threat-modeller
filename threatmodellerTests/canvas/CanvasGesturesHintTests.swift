import AppKit
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Whether the canvas draws `canvas-gestures-hint`.
///
/// The hint is the only thing an empty canvas draws at its own centre, so
/// this reads that centre back from a real hosting view, the way
/// `CanvasViewportTests` reads the canvas drawing layer.
@MainActor
struct CanvasGesturesHintTests {
    private static let width: CGFloat = 600
    private static let height: CGFloat = 400

    /// Draws the canvas with no zoom-to-fit, so a component the test places
    /// far from the origin stays far from the origin, off the picture.
    private func drawing(of session: ThreatModelSession) -> (image: NSBitmapImageRep, scale: Int)? {
        let canvas = CanvasState()
        canvas.fitsOnNextAppearance = false
        return hostedDrawing(
            of: CanvasView(session: session, canvas: canvas),
            width: Self.width,
            height: Self.height
        )
    }

    /// True when the region holds more than one colour, which tells drawn
    /// text from bare canvas.
    private func holdsSomething(
        _ image: NSBitmapImageRep,
        columns: Range<Int>,
        rows: Range<Int>
    ) -> Bool {
        var first: NSColor?
        for x in columns {
            for y in rows {
                guard let read = image.colorAt(x: x, y: y) else { continue }
                guard let known = first else { first = read; continue }
                if abs(known.redComponent - read.redComponent) > 0.02
                    || abs(known.greenComponent - read.greenComponent) > 0.02
                    || abs(known.blueComponent - read.blueComponent) > 0.02 {
                    return true
                }
            }
        }
        return false
    }

    /// The band across the canvas centre, where the hint's two lines sit.
    private func theCentreBand(_ scale: Int) -> (columns: Range<Int>, rows: Range<Int>) {
        (
            (Int(Self.width) / 2 - 200) * scale ..< (Int(Self.width) / 2 + 200) * scale,
            (Int(Self.height) / 2 - 40) * scale ..< (Int(Self.height) / 2 + 40) * scale
        )
    }

    @Test func anEmptyCanvasDrawsTheGesturesHintNamingDragShiftDragAndPinch() throws {
        let session = ThreatModelSession(useCases: TestDependencies())
        let (image, scale) = try #require(drawing(of: session))
        let band = theCentreBand(scale)

        #expect(
            holdsSomething(image, columns: band.columns, rows: band.rows),
            "the empty canvas drew nothing at its own centre"
        )
    }

    @Test func aCanvasHoldingOneComponentDrawsNoGesturesHint() throws {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 5000, y: 5000)
        let (image, scale) = try #require(drawing(of: session))
        let band = theCentreBand(scale)

        #expect(
            holdsSomething(image, columns: band.columns, rows: band.rows) == false,
            "the canvas drew the gestures hint though it holds a component"
        )
    }
}
