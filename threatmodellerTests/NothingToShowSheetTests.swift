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

    /// One control closes the sheet: the source holds one `Button`, and the
    /// key it binds as its default action closes the sheet when pressed.
    @Test func nothingToShowSheetHoldsOneControlThatClosesItAndPressingItClosesTheSheet() throws {
        let path = Self.sourcePath(of: "threatmodeller/project/NothingToShowSheet.swift")
        let source = try String(contentsOfFile: path, encoding: .utf8)
        let controlCount = source.components(separatedBy: "Button(").count - 1
        #expect(controlCount == 1, "the source holds \(controlCount) controls that could close the sheet, not 1")

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

    /// The five `.sheet(` sites in `ProjectWindow` each draw `NothingToShowSheet`
    /// with the words for their own missing value, read from the source so a
    /// copy-pasted or emptied name is caught without driving five live windows.
    @Test func eachSheetInTheProjectWindowNamesItsOwnMissingValue() throws {
        let path = Self.sourcePath(of: "threatmodeller/project/ProjectWindow.swift")
        let source = try String(contentsOfFile: path, encoding: .utf8)
        let lines = source.components(separatedBy: "\n")

        let sheetLines = lines.indices.filter { lines[$0].contains(".sheet(") }
        var found: [String] = []
        for (position, number) in sheetLines.enumerated() {
            let end = position + 1 < sheetLines.count ? sheetLines[position + 1] : lines.count
            let block = lines[(number + 1)..<end]
            guard block.contains(where: { $0.contains("NothingToShowSheet(") }) else { continue }
            guard let saysLine = block.first(where: { $0.contains("says:") }),
                  let text = Self.quoted(in: saysLine)
            else { continue }
            found.append(text)
        }

        #expect(found.count == 5, "found \(found.count) sheets naming a missing value, not 5: \(found)")
        #expect(found.allSatisfy { $0.isEmpty == false }, "one of the sheets names an empty missing value")
        #expect(Set(found).count == found.count, "two sheets name the same missing value: \(found)")
    }

    /// The text between the first two double quotes on the line, or nil.
    private static func quoted(in line: String) -> String? {
        guard let open = line.firstIndex(of: "\""),
              let close = line[line.index(after: open)...].firstIndex(of: "\"")
        else { return nil }
        return String(line[line.index(after: open)..<close])
    }

    /// Where the application's own source sits, from this file's path.
    private static func sourcePath(of file: String) -> String {
        let here = URL(fileURLWithPath: #filePath)
        return here
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent(file)
            .path
    }
}
