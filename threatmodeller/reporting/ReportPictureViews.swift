import AppKit
import SwiftUI
import ThreatModelKit

/// A picture the exporter drew, shown as it wrote it.
///
/// The bytes are the SVG the exporter writes into the report, so the stage and
/// the file cannot draw two different pictures. `NSImage` reads SVG, so the
/// window needs no renderer of its own.
///
/// The design is
/// `docs/superpowers/specs/2026-09-17-report-stage-pictures-design.md`.
struct ReportSvgPicture: View {
    let label: String
    let svg: String

    /// The picture as an image, or nil when the bytes are not a picture.
    static func image(of svg: String) -> NSImage? {
        let image = NSImage(data: Data(svg.utf8))
        guard let image, image.size.width > 0, image.size.height > 0 else { return nil }
        return image
    }

    var body: some View {
        if let image = Self.image(of: svg) {
            ReportPicture(image: image, label: label)
        } else {
            Text("This picture could not be drawn.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("report-picture-fault")
        }
    }
}

/// One drawn picture, fitted to the column and never scaled up.
struct ReportPicture: View {
    let image: NSImage
    let label: String

    var body: some View {
        Image(nsImage: image)
            .resizable()
            .aspectRatio(contentMode: .fit)
            // Never wider than the picture itself: a small picture stays
            // small rather than turning into a blurred one.
            .frame(maxWidth: image.size.width, maxHeight: image.size.height)
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityLabel(label)
            .accessibilityIdentifier("report-picture")
    }
}

/// The whole diagram, as the report embeds it.
///
/// The canvas draws it rather than the SVG, so the mitigates marks and the
/// status marks are the marks the window draws everywhere else. The area is
/// the area `ExportModelAsImage` states, which is the area the image export
/// writes, so the two pictures are the same pixels.
@MainActor
struct ReportDataFlowPicture: View {
    let session: ThreatModelSession

    /// The picture drawn once, and drawn again when the model changes. Drawing
    /// is a full layout pass over the diagram, so it does not run on every
    /// draw of the column.
    @State private var drawn: NSImage?

    /// The picture at the report's own size, before a column fits it.
    var picture: CanvasPicture {
        let area = session.imageArea()
        return CanvasPicture(
            components: session.canvas.components,
            connections: session.canvas.connections,
            zones: session.canvas.zones,
            risks: session.elementRisks,
            guards: session.elementGuards,
            mitigations: session.canvas.mitigations,
            origin: CGPoint(x: area.x, y: area.y),
            size: CGSize(width: area.width, height: area.height)
        )
    }

    /// The picture as PNG bytes, the way the image export writes them. A test
    /// reads this to state the stage and the export draw the same pixels.
    func pixels() -> Data? {
        try? CanvasImageRenderer().png(
            of: session.canvas,
            risks: session.elementRisks,
            guards: session.elementGuards,
            area: session.imageArea()
        )
    }

    /// What the picture is of. A change to any of it draws the picture again,
    /// so an answer given on another stage shows here.
    var signature: String {
        let area = session.imageArea()
        let places = session.canvas.components
            .map { "\($0.id):\($0.x),\($0.y):\($0.technologyId)" }
            .joined(separator: "|")
        let flows = session.canvas.connections
            .map { "\($0.id):\($0.sourceComponentId)>\($0.targetComponentId)" }
            .joined(separator: "|")
        let zones = session.canvas.zones
            .map { "\($0.id):\($0.x),\($0.y),\($0.width),\($0.height)" }
            .joined(separator: "|")
        let risks = session.elementRisks.keys.sorted().joined(separator: ",")
        let marks = session.canvas.mitigations
            .map { "\($0.sourceComponentId)>\($0.targetComponentId)" }
            .joined(separator: "|")
        return "\(area.x),\(area.y),\(area.width),\(area.height)|\(places)|\(flows)"
            + "|\(zones)|\(risks)|\(marks)"
    }

    var body: some View {
        Group {
            if let drawn {
                ReportPicture(image: drawn, label: "The data flow diagram")
                    .accessibilityIdentifier("report-data-flow")
            } else {
                Color.clear.frame(height: 1)
            }
        }
        .task(id: signature) { drawn = render() }
    }

    private func render() -> NSImage? {
        let renderer = ImageRenderer(content: picture)
        renderer.scale = CanvasImageRenderer.scale
        guard let image = renderer.cgImage else { return nil }
        let area = session.imageArea()
        return NSImage(
            cgImage: image,
            size: NSSize(width: area.width, height: area.height)
        )
    }
}
