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

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
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
