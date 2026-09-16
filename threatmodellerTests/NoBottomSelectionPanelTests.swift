import Foundation
import Testing
@testable import threatmodeller

/// The bottom panel is gone, and so is every mechanism that measured it or
/// lifted over it.
///
/// Six changes moved the bar under the canvas or measured it, and each left
/// the running application wrong. The editor now sits in the right sidebar,
/// as
/// `docs/superpowers/specs/2026-09-16-selection-editor-in-the-sidebar-design.md`
/// states. This reads the source and states that no file brings the bar back.
@Suite("Nothing draws under the canvas")
struct NoBottomSelectionPanelTests {
    /// The application's own source directory.
    private static let source = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("threatmodeller")

    /// The words that name the bottom panel and the room it took.
    private static let gone = [
        "selectionPanelHeight",
        "safeAreaInset(edge: .bottom)"
    ]

    @Test func noFileHoldsTheBottomPanelMechanisms() throws {
        let files = try FileManager.default.subpathsOfDirectory(atPath: Self.source.path)
            .filter { $0.hasSuffix(".swift") }
        #expect(files.isEmpty == false, "no Swift file found under \(Self.source.path)")

        for file in files {
            let text = try String(
                contentsOf: Self.source.appendingPathComponent(file),
                encoding: .utf8
            )
            for word in Self.gone {
                #expect(
                    text.contains(word) == false,
                    Comment(rawValue: "\(file) holds \(word)")
                )
            }
        }
    }
}
