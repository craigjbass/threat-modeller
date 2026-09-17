import SwiftUI
import ThreatModelKit

/// The diagram the layout search is drawing, fitted to the column.
///
/// The picture is the real diagram: the icons, the names, the zones and the
/// flows, routed through the same `ConnectionPath` the canvas uses, at the
/// coordinates the latest report gives. The subject comes from the use case
/// that runs the search, because the search itself holds geometry alone.
///
/// It reads no `CanvasState` and carries no gesture, so there is no
/// selection, no drag and no menu until the canvas takes over. The fit runs
/// on every redraw, so a plan that widens the picture still fits the column.
struct FormingPicture: View {
    let subject: LayoutSubject
    let layout: LayOutModelResponse

    /// The drawn set at the coordinates the report gives. An element the
    /// report does not name keeps the coordinates the subject has.
    private var drawn: DrawnDiagram {
        DrawnDiagram(
            components: subject.components,
            zones: subject.zones,
            connections: subject.connections
        )
        .placed(
            componentPositions: Dictionary(
                uniqueKeysWithValues: layout.components.map {
                    ($0.id, CGPoint(x: $0.x, y: $0.y))
                }
            ),
            zoneRects: Dictionary(
                uniqueKeysWithValues: layout.zones.map {
                    ($0.id, CGRect(x: $0.x, y: $0.y, width: $0.width, height: $0.height))
                }
            )
        )
    }

    var body: some View {
        GeometryReader { space in
            let picture = drawn
            let whole = FormingDiagram.rect(of: layout) ?? .zero
            let transform = CanvasTransform().fitting(whole, in: space.size)

            ZStack(alignment: .topLeading) {
                Color(nsColor: .textBackgroundColor)
                    .accessibilityIdentifier("forming-diagram")

                CanvasPicture(
                    components: picture.components,
                    connections: picture.connections,
                    zones: picture.zones,
                    risks: [:],
                    guards: [:],
                    origin: .zero,
                    size: CGSize(
                        width: max(whole.maxX, 1),
                        height: max(whole.maxY, 1)
                    )
                )
                .scaleEffect(transform.zoom, anchor: .topLeading)
                .offset(x: transform.pan.width, y: transform.pan.height)
            }
            .clipped()
        }
    }
}
