import SwiftUI
import ThreatModelKit

/// The editor in the right sidebar, shown while exactly one flow is selected.
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
        SelectionEditor(title: "This flow", identifier: "connection-panel") {
            controls
        }
    }

    @ViewBuilder
    private var controls: some View {
        SelectionField("Kind") {
            Picker("Kind", selection: kind) {
                ForEach(Self.kinds, id: \.0) { Text($0.1).tag($0.0) }
            }
            .labelsHidden()
            .accessibilityIdentifier("connection-kind")
        }

        SelectionField("Description") {
            TextField("Description", text: description)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("connection-description")
        }

        // What a flow carries names the assets, so a reader of the report
        // sees which asset a threat on this flow puts at risk.
        if session.canvas.systemAssets.isEmpty == false {
            SelectionField("Carries") {
                Menu {
                    ForEach(session.canvas.systemAssets, id: \.id) { asset in
                        Toggle(asset.name, isOn: carries(asset.id))
                    }
                } label: {
                    Text(carriedLabel)
                }
                .accessibilityIdentifier("connection-carries")
            }
        }

        // The tags a flow is filed under, as one line. The canvas tag
        // filter draws the view a tag names.
        SelectionField("Tags") {
            DeferredTextField(
                title: "Tags",
                text: tagsText,
                identifier: "connection-tags",
                write: { commitTags($0) }
            )
        }

        Divider()

        // The direction decides which threats the flow raises, so it is
        // changed here rather than by deleting the flow and drawing it
        // again, which loses the kind and the description.
        Button("Reverse Direction") { session.reverseConnection(connection.id) }
            .accessibilityIdentifier("reverse-connection")
    }

    /// The line the tag field shows: every tag the flow holds, separated by
    /// commas.
    var tagsText: String { TagFilter.text(from: connection.tags) }

    /// Writes what a person typed in the tag field. An empty line takes every
    /// tag off the flow.
    func commitTags(_ text: String) {
        session.setConnectionProperties(
            connectionId: connection.id,
            kind: connection.kindId,
            description: connection.description,
            tags: TagFilter.tags(from: text)
        )
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
