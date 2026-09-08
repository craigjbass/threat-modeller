import SwiftUI
import ThreatModelKit

/// Lists the examples this application ships.
///
/// Opening one replaces the model in front of the user, so the sheet says so
/// before it does it.
struct SampleBrowser: View {
    let session: ThreatModelSession
    /// The canvas drops its selection: the rows it held are gone.
    let canvas: CanvasState

    @Environment(\.dismiss) private var dismiss
    @State private var chosenId: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Open an Example")
                .font(.headline)

            Text("Opening an example replaces the model on this canvas. Undo takes it back.")
                .font(.callout)
                .foregroundStyle(.secondary)

            List(session.samples, id: \.id, selection: $chosenId) { sample in
                VStack(alignment: .leading, spacing: 2) {
                    Text(sample.name)
                    Text(sample.description)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
                .accessibilityIdentifier("sample-\(sample.id)")
                .onTapGesture(count: 2) { open(sample.id) }
                .tag(sample.id)
            }
            .frame(minHeight: 220)

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Open") {
                    guard let chosenId else { return }
                    open(chosenId)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(chosenId == nil)
                .accessibilityIdentifier("open-sample")
            }
        }
        .padding(16)
        .frame(width: 480, height: 360)
    }

    private func open(_ sampleId: String) {
        session.loadSample(sampleId)
        canvas.retainOnly(
            componentIds: Set(session.canvas.components.map(\.id)),
            connectionIds: Set(session.canvas.connections.map(\.id)),
            zoneIds: Set(session.canvas.zones.map(\.id))
        )
        dismiss()
    }
}
