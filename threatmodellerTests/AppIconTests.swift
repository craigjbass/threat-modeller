import AppKit
import Foundation
import Testing

/// What `scripts/make-icon.swift` draws, at every size the icon set asks for.
///
/// The mark used to be checked by eye. These figures are the drawing as it
/// stands: a change to the shield, the diagram or the field moves the mean of
/// the image, and the message says which size moved.
@Suite("The application mark")
struct AppIconTests {
    /// One size, and what the drawing gives for it. `whole` is the mean red,
    /// green, blue and alpha of every pixel; `centre` is the mean of the
    /// middle quarter, where the shield is.
    private struct Expected {
        let name: String
        let pixels: Int
        let whole: [Double]
        let centre: [Double]
    }

    /// The ten sizes `threatmodeller/Assets.xcassets/AppIcon.appiconset` asks
    /// for, and the drawing measured at each.
    private static let sizes: [Expected] = [
        Expected(name: "icon_16x16", pixels: 16,
                 whole: [0.254, 0.383, 0.558, 0.645], centre: [0.703, 0.773, 0.871, 1.000]),
        Expected(name: "icon_16x16@2x", pixels: 32,
                 whole: [0.252, 0.372, 0.537, 0.646], centre: [0.708, 0.777, 0.874, 1.000]),
        Expected(name: "icon_32x32", pixels: 32,
                 whole: [0.252, 0.372, 0.537, 0.646], centre: [0.708, 0.777, 0.874, 1.000]),
        Expected(name: "icon_32x32@2x", pixels: 64,
                 whole: [0.246, 0.357, 0.510, 0.646], centre: [0.708, 0.777, 0.874, 1.000]),
        Expected(name: "icon_128x128", pixels: 128,
                 whole: [0.243, 0.350, 0.497, 0.646], centre: [0.708, 0.777, 0.874, 1.000]),
        Expected(name: "icon_128x128@2x", pixels: 256,
                 whole: [0.242, 0.346, 0.490, 0.646], centre: [0.708, 0.777, 0.874, 1.000]),
        Expected(name: "icon_256x256", pixels: 256,
                 whole: [0.242, 0.346, 0.490, 0.646], centre: [0.708, 0.777, 0.874, 1.000]),
        Expected(name: "icon_256x256@2x", pixels: 512,
                 whole: [0.242, 0.346, 0.489, 0.646], centre: [0.708, 0.777, 0.874, 1.000]),
        Expected(name: "icon_512x512", pixels: 512,
                 whole: [0.242, 0.346, 0.489, 0.646], centre: [0.708, 0.777, 0.874, 1.000]),
        Expected(name: "icon_512x512@2x", pixels: 1024,
                 whole: [0.242, 0.345, 0.489, 0.646], centre: [0.708, 0.777, 0.874, 1.000])
    ]

    /// How far a mean may move before the drawing counts as changed. Two
    /// machines draw the same curve with slightly different edge pixels, and
    /// a real change to the mark moves a mean by far more than this.
    private static let tolerance = 0.02

    /// The repository, found from this file rather than from the working
    /// directory, which a test runner sets to its own place.
    private static var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    /// Runs the script in a directory of its own, so a test never writes over
    /// the icons the repository holds.
    private func drawnIcons() throws -> URL {
        let temporary = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("app-icon-\(UUID().uuidString)")
        let output = temporary
            .appendingPathComponent("threatmodeller/Assets.xcassets/AppIcon.appiconset")
        try FileManager.default.createDirectory(
            at: output,
            withIntermediateDirectories: true
        )

        let script = Self.repositoryRoot.appendingPathComponent("scripts/make-icon.swift")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["swift", script.path]
        process.currentDirectoryURL = temporary
        let said = Pipe()
        process.standardOutput = said
        process.standardError = said
        try process.run()
        let output_ = said.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        let said_ = String(decoding: output_, as: UTF8.self)
        #expect(
            process.terminationStatus == 0,
            "make-icon.swift exited with \(process.terminationStatus): \(said_)"
        )
        return output
    }

    @Test func theScriptDrawsEverySizeTheIconSetAsksFor() throws {
        let directory = try drawnIcons()

        for size in Self.sizes {
            let path = directory.appendingPathComponent("\(size.name).png")
            guard let data = try? Data(contentsOf: path),
                  let image = NSBitmapImageRep(data: data) else {
                Issue.record("\(size.name) was not drawn")
                continue
            }

            #expect(
                image.pixelsWide == size.pixels && image.pixelsHigh == size.pixels,
                "\(size.name) is \(image.pixelsWide) by \(image.pixelsHigh) pixels, not \(size.pixels)"
            )

            let measured = Self.means(of: image)
            #expect(measured.colours > 8, "\(size.name) is blank")

            for (index, channel) in ["red", "green", "blue", "alpha"].enumerated() {
                let whole = measured.whole[index]
                #expect(
                    abs(whole - size.whole[index]) <= Self.tolerance,
                    "\(size.name) changed: mean \(channel) is \(Self.rounded(whole)), not \(size.whole[index])"
                )
                let centre = measured.centre[index]
                #expect(
                    abs(centre - size.centre[index]) <= Self.tolerance,
                    "\(size.name) changed: mean \(channel) of the middle is \(Self.rounded(centre)), not \(size.centre[index])"
                )
            }
        }
    }

    /// The mean of every pixel, the mean of the middle quarter, and how many
    /// distinct colours the image holds. An image of one colour is blank.
    private static func means(
        of image: NSBitmapImageRep
    ) -> (whole: [Double], centre: [Double], colours: Int) {
        var whole = [Double](repeating: 0, count: 4)
        var centre = [Double](repeating: 0, count: 4)
        var centreCount = 0.0
        var colours: Set<Int> = []
        let width = image.pixelsWide
        let height = image.pixelsHigh

        for y in 0 ..< height {
            for x in 0 ..< width {
                guard let colour = image.colorAt(x: x, y: y) else { continue }
                let values = [
                    Double(colour.redComponent),
                    Double(colour.greenComponent),
                    Double(colour.blueComponent),
                    Double(colour.alphaComponent)
                ]
                for index in 0 ..< 4 { whole[index] += values[index] }
                colours.insert(
                    Int(values[0] * 255) << 24 | Int(values[1] * 255) << 16
                        | Int(values[2] * 255) << 8 | Int(values[3] * 255)
                )
                if x >= width / 4, x < width * 3 / 4, y >= height / 4, y < height * 3 / 4 {
                    for index in 0 ..< 4 { centre[index] += values[index] }
                    centreCount += 1
                }
            }
        }

        let pixels = Double(width * height)
        return (
            whole: whole.map { $0 / pixels },
            centre: centre.map { centreCount == 0 ? 0 : $0 / centreCount },
            colours: colours.count
        )
    }

    private static func rounded(_ value: Double) -> String {
        String(format: "%.3f", value)
    }
}
