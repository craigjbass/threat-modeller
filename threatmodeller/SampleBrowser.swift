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

            preview

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
        .frame(width: 480, height: 620)
    }

    /// The diagram of the highlighted sample, drawn from the sample's own
    /// document. A sample that cannot be read says so, and the browser stays
    /// usable.
    @ViewBuilder
    private var preview: some View {
        if let chosenId {
            if let drawn = session.samplePicture(chosenId) {
                let picture = CanvasHitTest.contentRect(
                    components: drawn.components,
                    zones: drawn.zones
                )
                CanvasPicture(
                    components: drawn.components,
                    connections: drawn.connections,
                    zones: drawn.zones,
                    risks: [:],
                    guards: [:],
                    origin: picture.origin,
                    size: picture.size
                )
                .scaleEffect(
                    Self.previewScale(of: picture.size),
                    anchor: .topLeading
                )
                .frame(width: Self.previewSize.width, height: Self.previewSize.height, alignment: .topLeading)
                .clipped()
                .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .textBackgroundColor)))
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .strokeBorder(Color.secondary.opacity(0.25), lineWidth: 1)
                )
                .accessibilityIdentifier("sample-preview-\(chosenId)")
            } else {
                Text("This example could not be read.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(
                        width: Self.previewSize.width,
                        height: Self.previewSize.height,
                        alignment: .center
                    )
                    .accessibilityIdentifier("sample-preview-unreadable")
            }
        } else {
            Text("Pick an example to see it.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(
                    width: Self.previewSize.width,
                    height: Self.previewSize.height,
                    alignment: .center
                )
                .accessibilityIdentifier("sample-preview-none")
        }
    }

    /// How big the picture is drawn.
    static let previewSize = CGSize(width: 448, height: 200)

    /// The scale that fits a picture of that size in the preview.
    static func previewScale(of size: CGSize) -> CGFloat {
        guard size.width > 0, size.height > 0 else { return 1 }
        return min(
            previewSize.width / size.width,
            previewSize.height / size.height,
            1
        )
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
