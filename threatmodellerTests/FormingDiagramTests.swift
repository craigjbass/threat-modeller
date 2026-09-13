import AppKit
import SwiftUI
import Testing
import ThreatModelKit
@testable import threatmodeller

/// What a person watches while a large model opens.
@MainActor
struct FormingDiagramTests {
    private func aLayout(components: Int, zones: Int) -> LayOutModelResponse {
        LayOutModelResponse(
            components: (0..<components).map { index in
                LaidOutComponent(
                    id: "c\(index)",
                    x: 60 + Double(index % 3) * 260,
                    y: 60 + Double(index / 3) * 160
                )
            },
            zones: (0..<zones).map { index in
                LaidOutZone(id: "z\(index)", x: 20, y: 20 + Double(index) * 320, width: 700, height: 300)
            }
        )
    }

    /// True when the picture holds more than one colour, which tells a drawn
    /// diagram from a blank rectangle.
    private func hasContent(_ image: NSBitmapImageRep) -> Bool {
        var first: NSColor?
        for x in stride(from: 2, to: image.pixelsWide - 2, by: 4) {
            for y in stride(from: 2, to: image.pixelsHigh - 2, by: 4) {
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

    @Test func drawsTheShapeOfADiagramThatIsStillForming() throws {
        let drawn = try #require(
            hostedDrawing(
                of: FormingDiagram(layout: aLayout(components: 9, zones: 2))
                    .background(Color(nsColor: .textBackgroundColor)),
                width: 520,
                height: 320
            )
        )

        #expect(hasContent(drawn.image))
    }

    /// A search that has placed nothing yet draws nothing, rather than
    /// dividing by a zero extent.
    @Test func drawsNothingBeforeAnythingIsPlaced() throws {
        let drawn = try #require(
            hostedDrawing(
                of: FormingDiagram(layout: aLayout(components: 0, zones: 0))
                    .background(Color(nsColor: .textBackgroundColor)),
                width: 520,
                height: 320
            )
        )

        #expect(hasContent(drawn.image) == false)
    }
}
