import Foundation
import Testing
@testable import threatmodeller

/// What a palette row carries, so a press on it reaches the list and the
/// list starts the drag.
@MainActor
struct PaletteDragTests {
    @Test func aPaletteRowsDoubleClickRunsBesideTheDragRatherThanTakingThePress() throws {
        let path = Self.sourcePath(of: "threatmodeller/PaletteView.swift")
        let source = try String(contentsOfFile: path, encoding: .utf8)

        #expect(source.contains(".onTapGesture") == false, "a palette row takes the press with a tap gesture")
        #expect(
            source.components(separatedBy: ".simultaneousGesture(TapGesture(count: 2)").count == 3,
            "the two palette rows do not both carry the double click as a simultaneous gesture"
        )
    }

    private static func sourcePath(of relative: String) -> String {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent(relative)
            .path
    }
}
