import SwiftUI

/// The three stages of the work, in the order an analyst does them.
///
/// A stage is a view of one model, not a mode: nothing is locked, and the
/// stage control moves between them at any time. What a stage changes is
/// which columns the window draws, so each stage shows the controls that
/// stage needs and leaves the rest out.
enum WorkStage: String, CaseIterable, Identifiable {
    /// Draw the system: the palette, the diagram, and what the system takes
    /// on trust.
    case architecture
    /// Read what the architecture raises, and say how often each one happens.
    case threats
    /// Answer the controls, and clear the answers the architecture no longer
    /// raises.
    case controls

    var id: String { rawValue }

    var label: String {
        switch self {
        case .architecture: "Architecture"
        case .threats: "Threats"
        case .controls: "Controls"
        }
    }

    var systemImage: String {
        switch self {
        case .architecture: "square.on.square"
        case .threats: "shield"
        case .controls: "checklist"
        }
    }
}
