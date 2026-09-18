import Foundation
import Testing
import DiagramRendering
import ThreatModelKit

#if canImport(CoreGraphics) && canImport(ImageIO) && canImport(UniformTypeIdentifiers)
import CoreGraphics
import CoreText
import ImageIO

/// Reads a PNG `PngWriter` wrote back into pixels, so a test can state a rule
/// about the picture the same way `SvgWriterTests` reads text out of an SVG.
@Suite("Writing a drawing as PNG")
struct PngWriterTests {
    private func drawing(
        size: Size = Size(width: 200, height: 100),
        background: DiagramColour = .paper,
        _ shapes: [DrawnShape]
    ) -> DiagramDrawing {
        DiagramDrawing(origin: Point(x: 0, y: 0), size: size, background: background, shapes: shapes)
    }

    /// A decoded picture, one byte per red, green, blue and alpha component,
    /// row by row. Row `0` is the top of the picture, the same order the
    /// diagram's own coordinates use, so a test reads a pixel the way it
    /// reads a point in the drawing.
    private struct Bitmap {
        let width: Int
        let height: Int
        private let bytes: [UInt8]

        init?(png data: Data) {
            guard let source = CGImageSourceCreateWithData(data as CFData, nil),
                  let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else { return nil }

            let width = image.width
            let height = image.height
            var bytes = [UInt8](repeating: 0, count: width * height * 4)
            guard let context = CGContext(
                data: &bytes,
                width: width,
                height: height,
                bitsPerComponent: 8,
                bytesPerRow: width * 4,
                space: CGColorSpaceCreateDeviceRGB(),
                bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
            ) else { return nil }

            context.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))

            self.width = width
            self.height = height
            self.bytes = bytes
        }

        /// The colour at `(x, y)`, `y` counted down from the top the way the
        /// diagram counts it and the way `CGImageSourceCreateImageAtIndex`
        /// lays out the rows it decodes from a PNG file.
        func colour(x: Int, y: Int) -> (r: Int, g: Int, b: Int, a: Int) {
            let offset = (y * width + x) * 4
            return (Int(bytes[offset]), Int(bytes[offset + 1]), Int(bytes[offset + 2]), Int(bytes[offset + 3]))
        }

        /// How many pixels in the row at `y` are within `tolerance` of `ink`,
        /// which tells a bare row of background from a row a glyph's stroke
        /// crosses.
        func inkCount(row y: Int, near ink: (r: Int, g: Int, b: Int), tolerance: Int = 40) -> Int {
            var count = 0
            for x in 0..<width {
                let read = colour(x: x, y: y)
                if abs(read.r - ink.r) <= tolerance
                    && abs(read.g - ink.g) <= tolerance
                    && abs(read.b - ink.b) <= tolerance {
                    count += 1
                }
            }
            return count
        }
    }

    private func bytes(_ colour: DiagramColour) -> (r: Int, g: Int, b: Int) {
        (Int((colour.red * 255).rounded()), Int((colour.green * 255).rounded()), Int((colour.blue * 255).rounded()))
    }

    private func matches(_ pixel: (r: Int, g: Int, b: Int, a: Int), _ colour: DiagramColour, tolerance: Int = 30) -> Bool {
        let want = bytes(colour)
        return abs(pixel.r - want.r) <= tolerance
            && abs(pixel.g - want.g) <= tolerance
            && abs(pixel.b - want.b) <= tolerance
    }

    // MARK: the page rule

    @Test func aShapeAtTheTopOfTheDrawingIsAtTheTopOfTheBitmap() throws {
        let diagram = drawing(
            size: Size(width: 200, height: 100),
            background: .paper,
            [.rectangle(Rect(x: 0, y: 0, width: 200, height: 30), cornerRadius: 0, DiagramStyle(fill: .red))]
        )

        let data = try #require(PngWriter.png(of: diagram))
        let bitmap = try #require(Bitmap(png: data))
        let middleColumn = bitmap.width / 2

        #expect(
            matches(bitmap.colour(x: middleColumn, y: 10), .red),
            "the rectangle is missing from the top of the bitmap"
        )
        #expect(
            matches(bitmap.colour(x: middleColumn, y: bitmap.height - 10), .paper),
            "the background is missing from the bottom of the bitmap"
        )
    }

    // MARK: the text rule

    /// "T" draws a wide bar at the top of its cap height and only a narrow
    /// stem near its baseline, so a row near the top of the glyph and a row
    /// near its baseline tell an upright letter from a flipped one.
    @Test func aLabelReadsTheRightWayUp() throws {
        let size = 48.0
        let baseline = 80.0
        let diagram = drawing(
            size: Size(width: 200, height: 100),
            background: .paper,
            [.text("T", at: Point(x: 20, y: baseline), anchor: .leading, size: size, bold: false, .ink)]
        )

        let data = try #require(PngWriter.png(of: diagram))
        let bitmap = try #require(Bitmap(png: data))
        let ink = bytes(.ink)

        let nearTop = Int((baseline - size * 0.67) * PngWriter.scale)
        let nearBaseline = Int((baseline - 5) * PngWriter.scale)

        let topRow = bitmap.inkCount(row: nearTop, near: ink)
        let baselineRow = bitmap.inkCount(row: nearBaseline, near: ink)

        #expect(topRow > baselineRow * 2, "the top bar of the T is not wider than its stem near the baseline")
        #expect(topRow > 5, "no ink near the top of the glyph")
    }

    // MARK: the size rule

    @Test func theBitmapIsTheDrawingSizeTimesTheScale() throws {
        let diagram = drawing(size: Size(width: 150, height: 80), background: .paper, [])

        let data = try #require(PngWriter.png(of: diagram))
        let bitmap = try #require(Bitmap(png: data))

        #expect(bitmap.width == Int((150 * PngWriter.scale).rounded(.up)))
        #expect(bitmap.height == Int((80 * PngWriter.scale).rounded(.up)))
        // A scale of two gives twice the pixels of a scale of one, which is
        // the drawing's own size.
        #expect(bitmap.width == 150 * 2)
        #expect(bitmap.height == 80 * 2)
    }

    // MARK: the empty rule

    @Test func anEmptyDrawingStillWritesABackgroundColouredBitmap() throws {
        let background = DiagramColour(0.2, 0.4, 0.7)
        let diagram = drawing(size: Size(width: 40, height: 40), background: background, [])

        let data = try #require(PngWriter.png(of: diagram))
        let bitmap = try #require(Bitmap(png: data))

        #expect(matches(bitmap.colour(x: 20, y: 20), background))
        #expect(matches(bitmap.colour(x: 2, y: 2), background))
        #expect(matches(bitmap.colour(x: 78, y: 78), background))
    }
}
#endif
