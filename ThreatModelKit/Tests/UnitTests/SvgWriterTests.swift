import Foundation
import Testing
import DiagramRendering
import ThreatModelKit

@Suite("Writing a drawing as SVG")
struct SvgWriterTests {
    private func drawing(_ shapes: [DrawnShape]) -> DiagramDrawing {
        DiagramDrawing(
            origin: Point(x: 0, y: 0),
            size: Size(width: 200, height: 100),
            shapes: shapes
        )
    }

    @Test func opensAndClosesTheDocument() {
        let svg = SvgWriter.svg(of: drawing([]))

        #expect(svg.hasPrefix("<svg xmlns=\"http://www.w3.org/2000/svg\""))
        #expect(svg.contains("viewBox=\"0 0 200 100\""))
        #expect(svg.hasSuffix("</svg>\n"))
    }

    @Test func writesARectangle() {
        let svg = SvgWriter.svg(
            of: drawing([
                .rectangle(
                    Rect(x: 10, y: 20, width: 30, height: 40),
                    cornerRadius: 4,
                    DiagramStyle(stroke: .green, fill: .paper, width: 2)
                )
            ])
        )

        #expect(svg.contains("<rect x=\"10\" y=\"20\" width=\"30\" height=\"40\" rx=\"4\""))
        #expect(svg.contains("stroke=\"#33AD54\""))
        #expect(svg.contains("stroke-width=\"2\""))
    }

    @Test func writesADashedLine() {
        let svg = SvgWriter.svg(
            of: drawing([
                .path(
                    [.move(Point(x: 0, y: 0)), .line(Point(x: 10, y: 10))],
                    DiagramStyle(stroke: .quiet, width: 1, dash: [2, 5])
                )
            ])
        )

        #expect(svg.contains("<path d=\"M 0 0 L 10 10\""))
        #expect(svg.contains("stroke-dasharray=\"2 5\""))
    }

    @Test func writesACurve() {
        let svg = SvgWriter.svg(
            of: drawing([
                .path(
                    [
                        .move(Point(x: 0, y: 0)),
                        .cubic(
                            control1: Point(x: 10, y: 0),
                            control2: Point(x: 20, y: 30),
                            to: Point(x: 30, y: 30)
                        )
                    ],
                    DiagramStyle(stroke: .red)
                )
            ])
        )

        #expect(svg.contains("C 10 0 20 30 30 30"))
    }

    @Test func writesTextTheRightWayRound() {
        let svg = SvgWriter.svg(
            of: drawing([
                .text("EC2", at: Point(x: 50, y: 60), anchor: .centre, size: 12, bold: true, .ink)
            ])
        )

        #expect(svg.contains("text-anchor=\"middle\""))
        #expect(svg.contains("font-weight=\"600\""))
        #expect(svg.contains(">EC2</text>"))
    }

    @Test func escapesWhatWouldBreakTheDocument() {
        let svg = SvgWriter.svg(
            of: drawing([
                .text("a < b & c", at: Point(x: 0, y: 0), anchor: .leading, size: 10, bold: false, .ink)
            ])
        )

        #expect(svg.contains("a &lt; b &amp; c"))
    }

    @Test func writesANumberWithoutTrailingZeros() {
        let svg = SvgWriter.svg(
            of: drawing([
                .rectangle(
                    Rect(x: 1.5, y: 2.0, width: 3.25, height: 4),
                    cornerRadius: 0,
                    DiagramStyle(fill: .paper)
                )
            ])
        )

        #expect(svg.contains("x=\"1.5\""))
        #expect(svg.contains("y=\"2\""))
        #expect(svg.contains("width=\"3.25\""))
    }
}
