import SwiftUI
import ThreatModelKit

/// What the System menu offers, as a value.
///
/// The menu bar draws these rows and the toolbar control draws the same rows,
/// so the two entry points cannot drift. This is the pattern `ElementMenu` and
/// `TreeMenu` already use: a test reads the rows and runs one, and the row it
/// runs is the row a person clicks.
@MainActor
struct SystemMenu {
    let project: ProjectSession?

    /// The identifier of one row, for a test and for the accessibility tree.
    static func rowId(of kind: SystemSheetKind) -> String {
        "system-menu-\(kind.rawValue)"
    }

    var rows: [ElementMenu.Row] {
        let session = project?.model
        return SystemSheetKind.allCases.map { kind in
            .item(
                id: Self.rowId(of: kind),
                title: kind.rowTitle(in: session),
                isEnabled: session != nil
            ) {
                project?.systemSheet = kind
            }
        }
    }
}

/// Draws the sheet one System menu row opened.
struct SystemSheetView: View {
    let kind: SystemSheetKind
    let session: ThreatModelSession
    let dismiss: () -> Void

    var body: some View {
        switch kind {
        case .documentControl: DocumentControlSheet(session: session, dismiss: dismiss)
        case .assets: AssetsSheet(session: session, dismiss: dismiss)
        case .thirdParties: ThirdPartiesSheet(session: session, dismiss: dismiss)
        case .useCases: UseCasesSheet(session: session, dismiss: dismiss)
        case .exclusions: ExclusionsSheet(session: session, dismiss: dismiss)
        case .diagrams: DiagramsSheet(session: session, dismiss: dismiss)
        case .threatActors: ThreatActorsSheet(session: session, dismiss: dismiss)
        }
    }
}
