import SwiftUI
import ThreatModelKit

/// The bar under the canvas, shown while exactly one flow is selected.
///
/// The kind decides which threats the flow raises, so the threat list changes
/// as the user changes the picker.
struct ConnectionPanel: View {
    let session: ThreatModelSession
    let connection: ViewedConnection

    private static let kinds = [
        ("network", "Network"),
        ("ipc", "Local IPC"),
        ("file", "File"),
        ("syscall", "System Call"),
        ("human", "Human")
    ]

    var body: some View {
        // The controls scroll sideways, the way the component panel's do: the
        // row is wider than a squeezed canvas column, and a row that does not
        // scroll draws its trailing controls under the neighbouring column.
        ScrollView(.horizontal) {
            controls
        }
        .scrollIndicators(.automatic)
        .background(.bar)
    }

    private var controls: some View {
        HStack(alignment: .center, spacing: 16) {
            Picker("Kind", selection: kind) {
                ForEach(Self.kinds, id: \.0) { Text($0.1).tag($0.0) }
            }
            .labelsHidden()
            .frame(width: 160)
            .accessibilityIdentifier("connection-kind")

            TextField("Description", text: description)
                .textFieldStyle(.roundedBorder)
                .frame(width: 280)
                .accessibilityIdentifier("connection-description")

            // What a flow carries names the assets, so a reader of the report
            // sees which asset a threat on this flow puts at risk.
            if session.canvas.systemAssets.isEmpty == false {
                Menu {
                    ForEach(session.canvas.systemAssets, id: \.id) { asset in
                        Toggle(asset.name, isOn: carries(asset.id))
                    }
                } label: {
                    Text(carriedLabel)
                }
                .frame(width: 200)
                .accessibilityIdentifier("connection-carries")
            }

            // The direction decides which threats the flow raises, so it is
            // changed here rather than by deleting the flow and drawing it
            // again, which loses the kind and the description.
            Button("Reverse Direction") { session.reverseConnection(connection.id) }
                .accessibilityIdentifier("reverse-connection")

            Spacer(minLength: 0)
        }
        .padding(.horizontal, CanvasView.windowEdgeMargin)
        .padding(.vertical, 8)
    }

    /// What the menu reads when it is closed.
    private var carriedLabel: String {
        guard connection.carries.isEmpty == false else { return "Carries nothing" }
        let names = connection.carries.compactMap { id in
            session.canvas.systemAssets.first { $0.id == id }?.name
        }
        return names.count == 1 ? "Carries \(names[0])" : "Carries \(names.count) assets"
    }

    private func carries(_ assetId: String) -> Binding<Bool> {
        Binding(
            get: { connection.carries.contains(assetId) },
            set: { wanted in
                var carried = connection.carries
                if wanted {
                    if carried.contains(assetId) == false { carried.append(assetId) }
                } else {
                    carried.removeAll { $0 == assetId }
                }
                session.setConnectionAssets(connectionId: connection.id, carries: carried)
            }
        )
    }

    private var kind: Binding<String> {
        Binding(
            get: { connection.kindId },
            set: { session.setConnectionProperties(connectionId: connection.id, kind: $0, description: connection.description) }
        )
    }

    private var description: Binding<String> {
        Binding(
            get: { connection.description ?? "" },
            set: { session.setConnectionProperties(connectionId: connection.id, kind: connection.kindId, description: $0) }
        )
    }
}
