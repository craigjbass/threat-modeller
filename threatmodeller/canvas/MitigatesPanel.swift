import SwiftUI
import ThreatModelKit

/// The bar under the canvas while two nodes are selected.
///
/// One component can lower a threat on another: a gateway in front of a
/// service, a proxy in front of a store. The diagram cannot draw which
/// threats that covers, so the bar names the edge and a sheet writes it.
struct MitigatesPanel: View {
    let session: ThreatModelSession
    let source: ViewedComponent
    let target: ViewedComponent

    @State private var isWriting = false
    @State private var isReversed = false

    private var protector: ViewedComponent { isReversed ? target : source }
    private var protected: ViewedComponent { isReversed ? source : target }

    /// The edge these two already hold, in the direction the bar shows.
    private var existing: ViewedMitigation? {
        session.canvas.mitigations.first {
            $0.sourceComponentId == protector.id && $0.targetComponentId == protected.id
        }
    }

    var body: some View {
        HStack(spacing: 12) {
            Text("\(protector.name) lowers threats on \(protected.name)")
                .font(.callout)

            Button {
                isReversed.toggle()
            } label: {
                Image(systemName: "arrow.left.arrow.right")
            }
            .help("Swap which component protects the other.")
            .accessibilityIdentifier("swap-mitigates")

            if let existing {
                Text("\(existing.status.capitalized) \u{00B7} \(existing.reducesRiskBy)% on \(existing.threatIds.count)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 8)

            Button(existing == nil ? "Mitigates\u{2026}" : "Edit\u{2026}") {
                isWriting = true
            }
            .accessibilityIdentifier("mitigates")

            if existing != nil {
                Button("Remove", role: .destructive) {
                    session.removeMitigatesEdge(from: protector.id, to: protected.id)
                }
                .accessibilityIdentifier("remove-mitigates")
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
        .sheet(isPresented: $isWriting) {
            MitigatesSheet(
                session: session,
                protector: protector,
                protected: protected,
                existing: existing
            )
        }
        .accessibilityIdentifier("mitigates-panel")
    }
}
