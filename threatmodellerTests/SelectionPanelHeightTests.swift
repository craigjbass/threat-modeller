import AppKit
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The floating panel lifts by the height the selection panel reports. These
/// measure that number in a real window, against the height the panel draws
/// at, because a number short of the drawn height leaves the floating panel
/// over the controls.
@MainActor
@Suite("How tall the selection panel says it is")
struct SelectionPanelHeightTests {
    private func aModel() -> ThreatModelSession {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 40, y: 40)
        return session
    }

    /// The panel, hosted at the column's width, and how tall it comes out.
    private func drawnHeight(of panel: some View, width: CGFloat) -> CGFloat {
        let host = NSHostingView(rootView: panel)
        host.frame = CGRect(x: 0, y: 0, width: width, height: 0)
        return host.fittingSize.height
    }

    /// Which band sits at the very bottom of the diagram column: the room
    /// the floating panel keeps for itself, or the selection panel. The
    /// floating panel lifts from the bottom edge, so the order decides how
    /// far it must lift.
    @Test func saysWhichBandSitsAtTheBottomOfTheColumn() throws {
        let session = aModel()
        let canvas = CanvasState()
        let component = try #require(session.canvas.components.first)
        canvas.select(componentId: component.id, addingToSelection: false)

        let width = 700.0
        let height = 600.0
        let drawn = try #require(
            hostedDrawing(
                of: CanvasView(session: session, canvas: canvas)
                    .safeAreaInset(edge: .bottom, spacing: 0) {
                        Color.clear.frame(
                            height: WorkflowPanel.reservedHeight + WorkflowPanel.bottomMargin
                        )
                    },
                width: width,
                height: height
            )
        )
        let image = drawn.image
        let scale = drawn.scale

        /// How many distinct colours one row of pixels holds. A band of one
        /// colour is empty; a band holding controls is not.
        func colours(_ pointsFromTheBottom: Int) -> Int {
            let row = image.pixelsHigh - pointsFromTheBottom * scale
            guard row >= 0, row < image.pixelsHigh else { return 0 }
            var seen: Set<Int> = []
            for x in stride(from: 8, to: image.pixelsWide - 8, by: 4) {
                guard let colour = image.colorAt(x: x, y: row) else { continue }
                seen.insert(
                    Int(colour.redComponent * 255) << 16
                        | Int(colour.greenComponent * 255) << 8
                        | Int(colour.blueComponent * 255)
                )
            }
            return seen.count
        }

        // The selection panel holds pickers and a text field, so its rows
        // hold several colours. The room kept for the floating panel holds
        // nothing, so its rows hold one.
        let atTheBottom = colours(20)
        let aboveTheReservedRoom = colours(Int(WorkflowPanel.reservedHeight + WorkflowPanel.bottomMargin) + 24)

        #expect(
            atTheBottom == 1,
            Comment(rawValue: "the bottom band holds \(atTheBottom) colours")
        )
        #expect(
            aboveTheReservedRoom > 1,
            Comment(
                rawValue: "the band above the reserved room holds "
                    + "\(aboveTheReservedRoom) colours"
            )
        )
    }

    /// The floating panel clears the room kept for itself as well as the
    /// selection panel. Lifting by the panel's height alone left it over the
    /// controls.
    @Test func theFloatingPanelClearsTheRoomItSitsInAndThePanelAboveIt() {
        let column = CGRect(x: 0, y: 0, width: 700, height: 800)
        let floating = CGSize(width: 520, height: 52)
        let selectionHeight = 64.0

        let selection = WorkflowPanel.selectionPanelRect(in: column, height: selectionHeight)
        let panel = WorkflowPanel.rect(
            in: column,
            panelSize: floating,
            liftedBy: selectionHeight
        )

        #expect(panel.intersects(selection) == false)
        #expect(selection.minY - panel.maxY == WorkflowPanel.gapAboveSelectionPanel)
        #expect(
            column.maxY - selection.maxY == WorkflowPanel.reservedRoom,
            "the selection panel sits on the room kept for the floating panel"
        )
        #expect(
            WorkflowPanel.lift(over: 0) == WorkflowPanel.bottomMargin,
            "with no selection the panel keeps the margin"
        )
    }

    @Test func statesTheHeightTheComponentPanelDrawsAt() throws {
        let session = aModel()
        let canvas = CanvasState()
        let component = try #require(session.canvas.components.first)
        canvas.select(componentId: component.id, addingToSelection: false)

        let width = 700.0
        let host = NSHostingView(
            rootView: CanvasView(session: session, canvas: canvas)
                .frame(width: width, height: 600)
        )
        host.frame = CGRect(x: 0, y: 0, width: width, height: 600)
        let window = NSWindow(
            contentRect: host.frame,
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.contentView = host
        window.orderBack(nil)
        host.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.4))
        window.orderOut(nil)

        let reported = canvas.selectionPanelHeight
        let drawn = drawnHeight(
            of: ComponentPanel(session: session, component: component),
            width: width
        )

        #expect(reported > 0, "the canvas reports no selection panel height")
        #expect(
            reported >= drawn,
            Comment(rawValue: "the canvas reports \(reported) for a panel that draws at \(drawn)")
        )
    }
}
