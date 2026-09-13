import SwiftUI
import ThreatModelKit

/// Previews that show the layout faults of the graphical interface overhaul.
///
/// These exist so a fault can be seen, not only read. `screencapture` and
/// `System Events` are both refused on this machine, so a preview snapshot is
/// the only picture of a real view this project can take.
///
/// Each preview states the window size it stands for. A column the user
/// collapses is drawn by leaving that column out, which is the geometry the
/// user gets: the next column then starts at the window's leading edge.
enum LayoutPreview {
    /// A model with two components, one flow, and the threats they raise.
    @MainActor
    static func session() -> ThreatModelSession {
        guard let useCases = try? Dependencies() else {
            fatalError("the bundled catalogue did not load")
        }
        let session = ThreatModelSession(useCases: useCases)
        session.add(technologyId: "aws-ec2", x: 120, y: 120)
        session.add(technologyId: "aws-rds", x: 420, y: 260)
        let ids = session.canvas.components.map(\.id)
        if ids.count == 2 {
            session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])
        }
        return session
    }

    /// The same model with every catalogue mitigation turned on, which is the
    /// state the pathway panel grows tallest in.
    @MainActor
    static func sessionWithEveryMitigationOn() -> ThreatModelSession {
        let session = session()
        session.setPathwayMaster(true)
        for mitigation in session.pathwayMitigations.mitigations {
            session.setPathwayMitigation(
                id: mitigation.id,
                isEnabled: true,
                mode: mitigation.mode,
                reductionPercent: mitigation.reductionPercent
            )
        }
        return session
    }

    /// The same two components and flow, back past the origin, where the
    /// drawing layer used to stop.
    @MainActor
    static func sessionPastTheOrigin() -> ThreatModelSession {
        guard let useCases = try? Dependencies() else {
            fatalError("the bundled catalogue did not load")
        }
        let session = ThreatModelSession(useCases: useCases)
        session.add(technologyId: "aws-ec2", x: -1000, y: -1000)
        session.add(technologyId: "aws-rds", x: -600, y: -860)
        let ids = session.canvas.components.map(\.id)
        if ids.count == 2 {
            session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])
        }
        return session
    }

    /// The canvas panned so the model point `x, y` sits at view point 200, 200.
    @MainActor
    static func canvasBringing(_ x: Double, _ y: Double) -> CanvasState {
        let canvas = CanvasState()
        canvas.transform = CanvasTransform(
            pan: CGSize(width: 200 - x, height: 200 - y),
            zoom: 1
        )
        return canvas
    }

    /// The canvas state with the first component selected, which is what puts
    /// the bottom bar on screen.
    @MainActor
    static func canvasSelectingTheFirstComponent(of session: ThreatModelSession) -> CanvasState {
        let canvas = CanvasState()
        if let first = session.canvas.components.first {
            canvas.select(componentId: first.id, addingToSelection: false)
        }
        return canvas
    }
}

// MARK: fault 1, the pathway panel

#Preview("Sidebar, pathway collapsed, 380x700", traits: .fixedLayout(width: 380, height: 700)) {
    ThreatSidebar(session: LayoutPreview.session())
}

#Preview("Sidebar, pathway expanded, 380x700", traits: .fixedLayout(width: 420, height: 740)) {
    // The frame is the window the sidebar column really gets. Without it the
    // preview grows to whatever height the panel asks for, which hides the
    // squeeze this preview exists to show. The red border is that window.
    ThreatSidebar(session: LayoutPreview.sessionWithEveryMitigationOn(), pathwayExpanded: true)
        .frame(width: 380, height: 700)
        .border(Color.red, width: 2)
        .padding(20)
}

#Preview("Sidebar, pathway expanded, 300x500", traits: .fixedLayout(width: 340, height: 540)) {
    ThreatSidebar(session: LayoutPreview.sessionWithEveryMitigationOn(), pathwayExpanded: true)
        .frame(width: 300, height: 500)
        .border(Color.red, width: 2)
        .padding(20)
}

#Preview("Sidebar, pathway expanded, 300x600", traits: .fixedLayout(width: 340, height: 640)) {
    ThreatSidebar(session: LayoutPreview.sessionWithEveryMitigationOn(), pathwayExpanded: true)
        .frame(width: 300, height: 600)
        .border(Color.red, width: 2)
        .padding(20)
}

// MARK: faults 2 and 3, the window edge once the palette column is gone

#Preview("Canvas, palette collapsed, 1200x700", traits: .fixedLayout(width: 1200, height: 700)) {
    CanvasView(session: LayoutPreview.session(), canvas: CanvasState())
}

#Preview("Bottom bar, palette collapsed, 1200x700", traits: .fixedLayout(width: 1200, height: 700)) {
    let session = LayoutPreview.session()
    return CanvasView(
        session: session,
        canvas: LayoutPreview.canvasSelectingTheFirstComponent(of: session)
    )
}

// MARK: the viewport, panned back past the origin

#Preview("Canvas at a negative coordinate, 1000x600", traits: .fixedLayout(width: 1000, height: 600)) {
    CanvasView(
        session: LayoutPreview.sessionPastTheOrigin(),
        canvas: LayoutPreview.canvasBringing(-1000, -1000)
    )
}

// MARK: the whole window, for comparison

#Preview("Every column, 1400x800", traits: .fixedLayout(width: 1400, height: 800)) {
    let session = LayoutPreview.sessionWithEveryMitigationOn()
    return NavigationSplitView {
        PaletteView(session: session, canvas: CanvasState())
            .navigationSplitViewColumnWidth(min: 220, ideal: 260)
    } content: {
        CanvasView(session: session, canvas: CanvasState())
            .navigationSplitViewColumnWidth(min: 400, ideal: 700)
    } detail: {
        ThreatSidebar(session: session, pathwayExpanded: true)
            .navigationSplitViewColumnWidth(min: 300, ideal: 380)
    }
}
