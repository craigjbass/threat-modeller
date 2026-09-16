import AppKit
import SwiftUI

/// What every selection panel under the diagram is.
enum SelectionPanel {
    /// The one height every selection panel draws at, at every column width.
    ///
    /// Each panel is one row of standard controls with eight points above and
    /// below. The floating workflow panel lifts by this number, so the number
    /// has to be one number: a panel that grew a second row in a narrow column
    /// would take that room from the diagram and leave the floating panel over
    /// its own controls.
    static let height: CGFloat = 40
}

/// The view a selection panel draws in.
///
/// The palette floats over the diagram column: the column's own view keeps the
/// whole width and states a leading safe area of the palette's width. SwiftUI
/// spreads a `ScrollView` across that safe area, wherever the panel is placed,
/// so the panel drew under the palette and ran wider than the column by the
/// palette's width. This view takes the frame SwiftUI's layout gives it, and
/// the panel inside it is hosted again with no safe area of its own, so the
/// scroller keeps to the part of the column a person sees.
final class SelectionPanelBarView: NSView {}

/// Draws a selection panel in a `SelectionPanelBarView`.
struct HostedSelectionPanel<Content: View>: NSViewRepresentable {
    let content: Content

    func makeNSView(context: Context) -> SelectionPanelBarView {
        let bar = SelectionPanelBarView()
        let host = NSHostingView(rootView: content)
        host.translatesAutoresizingMaskIntoConstraints = false
        bar.addSubview(host)
        NSLayoutConstraint.activate([
            host.leadingAnchor.constraint(equalTo: bar.leadingAnchor),
            host.trailingAnchor.constraint(equalTo: bar.trailingAnchor),
            host.topAnchor.constraint(equalTo: bar.topAnchor),
            host.bottomAnchor.constraint(equalTo: bar.bottomAnchor)
        ])
        context.coordinator.host = host
        return bar
    }

    func updateNSView(_ bar: SelectionPanelBarView, context: Context) {
        context.coordinator.host?.rootView = content
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    /// Keeps the hosting view, so a change of selection writes the new panel
    /// into the view that is already on screen.
    @MainActor
    final class Coordinator {
        var host: NSHostingView<Content>?
    }
}

extension View {
    /// Draws a selection panel as one row, as wide as the part of the diagram
    /// column a person sees.
    func fitsTheDiagramColumn(width: CGFloat) -> some View {
        HostedSelectionPanel(content: self)
            .frame(
                width: width > 0 ? width : nil,
                height: SelectionPanel.height
            )
    }
}
