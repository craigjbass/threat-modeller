import AppKit
import SwiftUI
import Testing
import ThreatModelKit
@testable import threatmodeller

/// What the canvas draws once the user pans past the origin.
///
/// Panning has no limit of its own: `CanvasTransform.panned(by:)` adds the
/// step and keeps it. What the user meets is the drawing layer, so these tests
/// pan a model into view and read back what was painted.
@MainActor
struct CanvasViewportTests {
    private static let canvasWidth: CGFloat = 1000
    private static let canvasHeight: CGFloat = 600

    /// Two components on one line, the width of a slot and a gap apart, and a
    /// flow between them.
    private func aModel(at x: Double, _ y: Double) -> ThreatModelSession {
        guard let useCases = try? Dependencies() else {
            fatalError("the bundled catalogue did not load")
        }
        let session = ThreatModelSession(useCases: useCases)
        session.add(technologyId: "aws-ec2", x: x, y: y)
        session.add(technologyId: "aws-ec2", x: x + 400, y: y)
        let ids = session.canvas.components.map(\.id)
        if ids.count == 2 {
            session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])
        }
        return session
    }

    /// The canvas with the model point `x, y` brought to view point `200, 200`.
    private func canvasDrawing(of session: ThreatModelSession, bringing x: Double, _ y: Double) -> (image: NSBitmapImageRep, scale: Int)? {
        let canvas = CanvasState()
        canvas.transform = CanvasTransform(
            pan: CGSize(width: 200 - x, height: 200 - y),
            zoom: 1
        )
        return hostedDrawing(
            of: CanvasView(session: session, canvas: canvas),
            width: Self.canvasWidth,
            height: Self.canvasHeight
        )
    }

    /// True when the region holds more than one colour, which tells something
    /// drawn from bare canvas.
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

    /// The band between the two nodes, where only the flow runs. The first
    /// node fills view x 200 to 360 and the second starts at view x 600.
    private func theBandBetweenTheNodes(_ scale: Int) -> (columns: Range<Int>, rows: Range<Int>) {
        ((380 * scale)..<(580 * scale), (170 * scale)..<(300 * scale))
    }

    /// The first node itself, a little inside its own slot.
    private func theFirstNode(_ scale: Int) -> (columns: Range<Int>, rows: Range<Int>) {
        ((210 * scale)..<(350 * scale), (205 * scale)..<(265 * scale))
    }

    // MARK: the control, on the side of the origin the canvas already drew

    @Test func drawsANodeTheUserPannedToAtAPositiveCoordinate() throws {
        let session = aModel(at: 1000, 1000)

        let drawn = try #require(canvasDrawing(of: session, bringing: 1000, 1000))

        let node = theFirstNode(drawn.scale)
        #expect(holdsSomething(drawn.image, columns: node.columns, rows: node.rows))
    }

    @Test func drawsAFlowTheUserPannedToAtAPositiveCoordinate() throws {
        let session = aModel(at: 1000, 1000)

        let drawn = try #require(canvasDrawing(of: session, bringing: 1000, 1000))

        let band = theBandBetweenTheNodes(drawn.scale)
        #expect(holdsSomething(drawn.image, columns: band.columns, rows: band.rows))
    }

    // MARK: the same model, back past the origin

    @Test func drawsANodeTheUserPannedToAtANegativeCoordinate() throws {
        let session = aModel(at: -1000, -1000)

        let drawn = try #require(canvasDrawing(of: session, bringing: -1000, -1000))

        let node = theFirstNode(drawn.scale)
        #expect(holdsSomething(drawn.image, columns: node.columns, rows: node.rows))
    }

    @Test func drawsAFlowTheUserPannedToAtANegativeCoordinate() throws {
        let session = aModel(at: -1000, -1000)

        let drawn = try #require(canvasDrawing(of: session, bringing: -1000, -1000))

        let band = theBandBetweenTheNodes(drawn.scale)
        #expect(holdsSomething(drawn.image, columns: band.columns, rows: band.rows))
    }
}
