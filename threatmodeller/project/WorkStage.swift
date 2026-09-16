import SwiftUI

/// The five stages of the work, in the order an analyst does them.
///
/// A stage is a view of one model, not a mode: nothing is locked, and the
/// stage control moves between them at any time. What a stage changes is
/// which columns the window draws, so each stage shows the controls that
/// stage needs and leaves the rest out.
enum WorkStage: String, CaseIterable, Identifiable {
    /// Draw the system: the palette, the diagram, and what the system takes
    /// on trust.
    case architecture
    /// Draw how an attacker reaches a threat: a tree of steps over the
    /// elements the architecture states.
    case attackTrees
    /// Read what the architecture raises, and say how often each one happens.
    case threats
    /// Answer the controls, and clear the answers the architecture no longer
    /// raises.
    case controls
    /// Read what the report says about the model as it stands, section by
    /// section, with no file written.
    case report

    var id: String { rawValue }

    var label: String {
        switch self {
        case .architecture: "Architecture"
        case .attackTrees: "Attack Trees"
        case .threats: "Threats"
        case .controls: "Controls"
        case .report: "Report"
        }
    }

    var systemImage: String {
        switch self {
        case .architecture: "square.on.square"
        case .attackTrees: "point.topleft.down.to.point.bottomright.curvepath"
        case .threats: "shield"
        case .controls: "checklist"
        case .report: "doc.richtext"
        }
    }
}

extension WorkStage {
    /// The four stages the work had before the Report stage.
    ///
    /// `WindowLayoutTests` draws the panel with these and with every stage, so
    /// a change to the stage control that widens the panel fails there.
    static let beforeTheReportStage: [WorkStage] = [
        .architecture, .attackTrees, .threats, .controls
    ]
}
