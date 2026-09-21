import SwiftUI
import ThreatModelKit

/// The mitigates row of the multi-selection view, while two nodes are
/// selected.
///
/// One component can lower a threat on another: a gateway in front of a
/// service, a proxy in front of a store. The diagram cannot draw which
/// threats that covers, so the row names the edge and a sheet writes it.
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
        controls
            .sheet(isPresented: $isWriting) {
                writingSheet
            }
    }

    private var controls: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("\(protector.name) lowers threats on \(protected.name)")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)

            if let existing {
                Text(existing.status.capitalized)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 8) {
                Button {
                    isReversed.toggle()
                } label: {
                    Image(systemName: "arrow.left.arrow.right")
                }
                .help("Swap which component protects the other.")
                .accessibilityIdentifier("swap-mitigates")

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
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityIdentifier("mitigates-panel")
    }

    private var writingSheet: some View {
        MitigatesSheet(
            session: session,
            protector: protector,
            protected: protected,
            existing: existing
        )
    }
}
