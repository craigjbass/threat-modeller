import SwiftUI

/// One colour per risk level, named once.
///
/// Every colour is a system colour, so both themes work without a second set:
/// macOS supplies the light and the dark value for each. A view that shows
/// risk reads this and decides nothing itself.
nonisolated enum RiskPalette {
    static func colour(forLevelId levelId: String) -> Color {
        switch levelId {
        case "critical": .red
        case "high": .orange
        case "medium": .yellow
        case "low": .green
        default: .secondary
        }
    }

    /// The colour behind a tag or a badge. The same hue, quiet enough to read
    /// text on in either theme.
    static func background(forLevelId levelId: String) -> Color {
        colour(forLevelId: levelId).opacity(0.18)
    }

    /// A dot beside a threat that carries no level, so a row is never blank.
    static let unknown = Color.secondary

    /// The colour a library states as hex text, such as `#4c7a34`, or nil
    /// when the text is not six hex digits. A classification chip paints
    /// this colour the same way a risk chip paints `colour(forLevelId:)`:
    /// read once here, decided nowhere else.
    static func colour(fromHex hex: String) -> Color? {
        var text = hex
        if text.hasPrefix("#") { text.removeFirst() }
        guard text.count == 6, let value = UInt64(text, radix: 16) else { return nil }
        return Color(
            red: Double((value >> 16) & 0xFF) / 255,
            green: Double((value >> 8) & 0xFF) / 255,
            blue: Double(value & 0xFF) / 255
        )
    }
}
