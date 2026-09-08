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
}
