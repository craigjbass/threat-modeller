import AppKit
import Foundation
import Testing
import ThreatModelKit

/// What `scripts/make-icon.swift` draws.
///
/// A change to the drawing used to be found by eye. This runs the script into
/// a temporary directory and states the pixel size, that the image is not
/// blank, and the checksum of each of the ten sizes, so a change fails the
/// build and names the size that changed.
///
/// WARNING: this test runs the script with `swift`, which reads AppKit, so it
/// runs on macOS only. The Linux job runs the package tests and never this
/// one.
@Suite("The application icon")
struct IconDrawingTests {
    /// The ten sizes the icon set asks for, and what each one draws today.
    /// A drawing change is a new checksum here, stated on purpose.
    private static let expected: [(name: String, pixels: Int, checksum: String)] = [
        ("icon_16x16", 16, "7cc0251252baea91468ff1895ed02188ad1a24984ac1a6e4599ba07a5f610aaa"),
        ("icon_16x16@2x", 32, "f42283a461df887806afd8e8d352197f56a6d829e49ee89b01b8c395d1ad222f"),
        ("icon_32x32", 32, "f42283a461df887806afd8e8d352197f56a6d829e49ee89b01b8c395d1ad222f"),
        ("icon_32x32@2x", 64, "7c9f2e00f3332605cc313c8f936b8d43c3a7717c6fa60abc3c460bf26ae333e6"),
        ("icon_128x128", 128, "2cc112b1d8dfd05b2dcd5b410e22cd24fc4a37b0571c2b5d02f51bb3a0162172"),
        ("icon_128x128@2x", 256, "ed585cfee85fcd31bf390a7a71e5c102466a80f40a4eab187b38d05fef942be9"),
        ("icon_256x256", 256, "ed585cfee85fcd31bf390a7a71e5c102466a80f40a4eab187b38d05fef942be9"),
        ("icon_256x256@2x", 512, "1bb2b4ac2dc7983a1cb3661b1d188cb7396e91f65918bf39a26b1800c096ce07"),
        ("icon_512x512", 512, "1bb2b4ac2dc7983a1cb3661b1d188cb7396e91f65918bf39a26b1800c096ce07"),
        ("icon_512x512@2x", 1024, "0fc9c0869785d506c4a0ddbc347cd80a0b91696e5522d601f37c73b7663aaa9a")
    ]

    /// The repository root, from this file's own path.
    private static var repository: String {
        (((#filePath as NSString).deletingLastPathComponent) as NSString)
            .deletingLastPathComponent
    }

    /// Runs the script into a directory of its own and answers what it wrote.
    private func drawn() throws -> [String: Data] {
        let work = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("threatmodeller-icon-\(UUID().uuidString)")
        let into = work.appendingPathComponent(
            "threatmodeller/Assets.xcassets/AppIcon.appiconset"
        )
        try FileManager.default.createDirectory(at: into, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["swift", "\(Self.repository)/scripts/make-icon.swift"]
        process.currentDirectoryURL = work
        process.standardOutput = Pipe()
        let errors = Pipe()
        process.standardError = errors
        try process.run()
        let said = String(
            decoding: errors.fileHandleForReading.readDataToEndOfFile(),
            as: UTF8.self
        )
        process.waitUntilExit()
        #expect(process.terminationStatus == 0, "the script exited \(process.terminationStatus): \(said)")

        var written: [String: Data] = [:]
        for size in Self.expected {
            let path = into.appendingPathComponent("\(size.name).png")
            written[size.name] = try? Data(contentsOf: path)
        }
        return written
    }

    /// The `sha256` of the bytes, through the checksum the lock files use.
    private func checksum(_ data: Data) -> String {
        LibraryLock.checksum(data.base64EncodedString())
    }

    @Test func drawsEverySizeTheIconSetAsksFor() throws {
        let written = try drawn()

        for size in Self.expected {
            let data = try #require(written[size.name], "\(size.name) was not drawn")
            let image = try #require(NSBitmapImageRep(data: data), "\(size.name) is not a picture")
            #expect(image.pixelsWide == size.pixels, "\(size.name) is \(image.pixelsWide) wide")
            #expect(image.pixelsHigh == size.pixels, "\(size.name) is \(image.pixelsHigh) high")
        }
    }

    @Test func drawsSomethingAtEverySize() throws {
        let written = try drawn()

        for size in Self.expected {
            let data = try #require(written[size.name])
            let image = try #require(NSBitmapImageRep(data: data))

            var seen: Set<String> = []
            for x in stride(from: 0, to: image.pixelsWide, by: max(1, image.pixelsWide / 16)) {
                for y in stride(from: 0, to: image.pixelsHigh, by: max(1, image.pixelsHigh / 16)) {
                    guard let colour = image.colorAt(x: x, y: y) else { continue }
                    seen.insert("\(colour.redComponent),\(colour.greenComponent),\(colour.blueComponent)")
                }
            }
            #expect(seen.count > 1, "\(size.name) drew one colour, so it drew nothing")
        }
    }

    /// The drawing is the drawing this repository states. A change here is a
    /// change to the mark, and the message names the size.
    @Test func drawsTheMarkThisRepositoryStates() throws {
        let written = try drawn()

        for size in Self.expected {
            let data = try #require(written[size.name])
            #expect(
                checksum(data) == size.checksum,
                "\(size.name) changed: it now checksums \(checksum(data))"
            )
        }
    }
}
