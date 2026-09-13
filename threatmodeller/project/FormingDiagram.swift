import SwiftUI
import ThreatModelKit

/// The diagram as the layout search last had it.
///
/// A layout response holds geometry and nothing else: an identifier and a
/// place for each component, and a rectangle for each zone. So this draws the
/// shape of the picture forming, not the picture. It is what a person watches
/// while a large model opens.
struct FormingDiagram: View {
    let layout: LayOutModelResponse

    /// The slot a component takes, which the core owns.
    private var slot: CGSize {
        CGSize(width: Component.size.width, height: Component.size.height)
    }

    /// Everything the layout placed, so the drawing can be scaled to fit.
    private var extent: CGRect {
        var rect: CGRect?
        for zone in layout.zones {
            rect = union(rect, CGRect(x: zone.x, y: zone.y, width: zone.width, height: zone.height))
        }
        for component in layout.components {
            rect = union(
                rect,
                CGRect(x: component.x, y: component.y, width: slot.width, height: slot.height)
            )
        }
        return rect ?? CGRect(x: 0, y: 0, width: 1, height: 1)
    }

    private func union(_ one: CGRect?, _ other: CGRect) -> CGRect {
        one.map { $0.union(other) } ?? other
    }

    var body: some View {
        GeometryReader { space in
            let whole = extent
            let scale = min(
                space.size.width / max(whole.width, 1),
                space.size.height / max(whole.height, 1)
            )

            Canvas { context, _ in
                context.scaleBy(x: scale, y: scale)
                context.translateBy(x: -whole.minX, y: -whole.minY)

                for zone in layout.zones {
                    context.stroke(
                        Path(
                            roundedRect: CGRect(
                                x: zone.x,
                                y: zone.y,
                                width: zone.width,
                                height: zone.height
                            ),
                            cornerRadius: 12
                        ),
                        with: .color(.secondary.opacity(0.5)),
                        lineWidth: 2 / scale
                    )
                }

                for component in layout.components {
                    context.fill(
                        Path(
                            roundedRect: CGRect(
                                x: component.x,
                                y: component.y,
                                width: slot.width,
                                height: slot.height
                            ),
                            cornerRadius: 6
                        ),
                        with: .color(.accentColor.opacity(0.35))
                    )
                }
            }
        }
        .accessibilityIdentifier("forming-diagram")
    }
}
