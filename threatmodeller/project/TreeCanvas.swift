import AppKit
import SwiftUI
import ThreatModelKit

/// The canvas one tree is drawn on.
///
/// The design in
/// `docs/superpowers/specs/2026-09-16-attack-tree-stage-design.md` states the
/// shape: nodes laid out from the tree each time, edges stating what feeds
/// what, the goal told apart at a glance, and the same viewport the
/// architecture canvas has. This view holds layout. Gestures live in
/// `TreeCanvasGestures` and the menus in `TreeMenu`.
struct TreeCanvas: View {
    let editor: TreeEditor
    let canvas: TreeCanvasState
    /// The elements the list beside the canvas offers, for what a drop makes.
    let elements: [TreeElement]
    /// What the assessment bound for this tree, or nil while it is unwritten.
    let bound: BoundAttackTree?
    /// Which pointing device the person drives the canvas with. A preview
    /// takes the mode a new person starts in.
    var pointerMode: PointerMode = .standard

    /// True while the pointer is over this canvas, so a scroll anywhere else
    /// in the application moves nothing here.
    @State private var isPointerOver = false
    /// The monitor reading the scroll events, while this canvas is on screen.
    @State private var scrollMonitor: Any?
    /// The monitor reading the middle-button drag. A middle button reaches no
    /// SwiftUI gesture.
    @State private var middleButtonMonitor: Any?
    /// The monitor reading whether Space is held down. AppKit states no
    /// modifier flag for Space, so the canvas counts the key itself.
    @State private var spaceMonitor: Any?
    /// True while Space is held down over this canvas, so a drag pans.
    @State private var isSpaceDown = false
    /// Where the pointer last was on the canvas, in view coordinates, so a
    /// wheel zooms about the point the person is looking at.
    @State private var pointerViewPoint: CGPoint = .zero

    private var gestures: TreeCanvasGestures {
        TreeCanvasGestures(
            editor: editor,
            canvas: canvas,
            elements: elements,
            isSpaceDown: isSpaceDown
        )
    }

    private var menus: TreeMenu {
        TreeMenu(editor: editor, canvas: canvas, elements: elements)
    }

    var body: some View {
        GeometryReader { geometry in
            ZStack(alignment: .topLeading) {
                Color(nsColor: .textBackgroundColor)
                    .contentShape(Rectangle())
                    .accessibilityIdentifier("tree-canvas")
                    .gesture(backgroundTap)
                    .gesture(backgroundDrag)
                    .contextMenu { ElementMenuView(rows: menus.background()) }

                content
                    .scaleEffect(canvas.transform.zoom, anchor: .topLeading)
                    .offset(x: canvas.transform.pan.width, y: canvas.transform.pan.height)

                emptyCanvasHint
            }
            .onAppear { canvas.visibleSize = geometry.size }
            .onChange(of: geometry.size) { _, size in canvas.visibleSize = size }
        }
        .coordinateSpace(.named("tree-canvas"))
        .clipped()
        .pointerStyle(CanvasPointer.style(isDrawingZone: false, isPanning: canvas.isPanning))
        .onContinuousHover { phase in
            if case .active(let where_) = phase {
                isPointerOver = true
                pointerViewPoint = where_
            } else {
                isPointerOver = false
                isSpaceDown = false
            }
        }
        .onAppear { startReadingScrollEvents() }
        .onDisappear { stopReadingScrollEvents() }
        .focusable()
        .focusEffectDisabled()
        .onKeyPress(.escape) {
            canvas.cancel() ? .handled : .ignored
        }
        .onKeyPress(.delete) {
            gestures.deleteSelection()
            return .handled
        }
        .gesture(
            MagnifyGesture()
                .onChanged { value in
                    gestures.zoom(
                        by: 1 + (value.magnification - 1) * 0.3,
                        about: value.startLocation
                    )
                }
        )
        .dropDestination(for: String.self) { payloads, location in
            gestures.drop(payloads, at: location)
        }
    }

    // MARK: the gestures on open canvas

    private var backgroundTap: some Gesture {
        SpatialTapGesture(coordinateSpace: .named("tree-canvas")).onEnded { _ in
            gestures.backgroundTap()
        }
    }

    private var backgroundDrag: some Gesture {
        // One gesture that reads the shift key itself, the way the
        // architecture canvas does: a plain drag pans, a shift-drag draws the
        // marquee.
        DragGesture(minimumDistance: 2, coordinateSpace: .named("tree-canvas"))
            .onChanged { value in
                gestures.backgroundDragChanged(
                    from: value.startLocation,
                    to: value.location,
                    by: value.translation,
                    isShiftDown: NSEvent.modifierFlags.contains(.shift),
                    isSpaceDown: isSpaceDown
                )
            }
            .onEnded { _ in gestures.backgroundDragEnded() }
    }

    private func startReadingScrollEvents() {
        guard scrollMonitor == nil else { return }
        scrollMonitor = NSEvent.addLocalMonitorForEvents(matching: .scrollWheel) { event in
            guard isPointerOver else { return event }
            gestures.wheel(
                by: CGSize(width: event.scrollingDeltaX, height: event.scrollingDeltaY),
                at: pointerViewPoint,
                isShiftDown: event.modifierFlags.contains(.shift),
                mode: pointerMode
            )
            return nil
        }
        startReadingPanEvents()
    }

    /// Reads the two pans a mouse has: the middle-button drag, and Space held
    /// down while the primary button drags.
    private func startReadingPanEvents() {
        if middleButtonMonitor == nil {
            middleButtonMonitor = NSEvent.addLocalMonitorForEvents(
                matching: [.otherMouseDragged, .otherMouseUp]
            ) { event in
                guard isPointerOver, event.buttonNumber == CanvasView.middleButton else {
                    return event
                }
                if event.type == .otherMouseUp {
                    gestures.panStepEnded()
                } else {
                    gestures.panStep(by: CGSize(width: event.deltaX, height: event.deltaY))
                }
                return nil
            }
        }
        if spaceMonitor == nil {
            spaceMonitor = NSEvent.addLocalMonitorForEvents(
                matching: [.keyDown, .keyUp]
            ) { event in
                // The event is passed on either way: Space still types a
                // space, and still presses whatever holds the focus.
                if isPointerOver, event.keyCode == CanvasView.spaceKey {
                    isSpaceDown = event.type == .keyDown
                }
                return event
            }
        }
    }

    private func stopReadingScrollEvents() {
        if let scrollMonitor { NSEvent.removeMonitor(scrollMonitor) }
        scrollMonitor = nil
        if let middleButtonMonitor { NSEvent.removeMonitor(middleButtonMonitor) }
        middleButtonMonitor = nil
        if let spaceMonitor { NSEvent.removeMonitor(spaceMonitor) }
        spaceMonitor = nil
        isSpaceDown = false
    }

    // MARK: what is drawn

    private var content: some View {
        ZStack(alignment: .topLeading) {
            edgeLines
            joinLine

            ForEach(editor.graph.nodes) { node in
                TreeNodeView(
                    node: node,
                    isGoal: editor.graph.goalId == node.id,
                    isSelected: canvas.isSelected(node.id),
                    state: TreeStepState.state(of: node, in: bound),
                    size: gestures.size(of: node.id),
                    onSelect: { gestures.selectNode(node.id, addingToSelection: $0) },
                    onDragChanged: { gestures.nodeDragChanged(node.id, $0) },
                    onDragEnded: { gestures.nodeDragEnded($0) },
                    onJoinDragChanged: { gestures.joinDragChanged(node.id, $0) },
                    onJoinDragEnded: { gestures.joinDragEnded(node.id, $0) },
                    menu: { menus.node(node.id) },
                    onOpenMenu: { menus.selectBeforeMenu(node.id) }
                )
                .position(gestures.position(of: node.id))
            }

            ForEach(editor.pending) { item in
                PendingElementView(
                    item: item,
                    isSelected: canvas.isSelected(item.id),
                    onSelect: { gestures.selectNode(item.id, addingToSelection: $0) },
                    onDragChanged: { gestures.nodeDragChanged(item.id, $0) },
                    onDragEnded: { gestures.nodeDragEnded($0) },
                    onPick: { editor.pick($0, for: item.id) },
                    menu: { menus.pending(item.id) },
                    onOpenMenu: { menus.selectBeforeMenu(item.id) }
                )
                .position(gestures.position(of: item.id))
            }

            if let rect = canvas.marqueeRect {
                Rectangle()
                    .fill(Color.accentColor.opacity(0.12))
                    .overlay(Rectangle().strokeBorder(Color.accentColor, lineWidth: 1))
                    .frame(width: rect.width, height: rect.height)
                    .position(x: rect.midX, y: rect.midY)
                    .allowsHitTesting(false)
            }
        }
    }

    private var edgeLines: some View {
        Path { path in
            for edge in editor.graph.edges {
                let from = gestures.position(of: edge.from)
                let to = gestures.position(of: edge.to)
                let start = CGPoint(x: from.x + gestures.size(of: edge.from).width / 2, y: from.y)
                let end = CGPoint(x: to.x - gestures.size(of: edge.to).width / 2, y: to.y)
                path.move(to: start)
                path.addLine(to: end)

                // The head states what feeds what.
                let angle = atan2(end.y - start.y, end.x - start.x)
                for turn in [angle + .pi * 0.85, angle - .pi * 0.85] {
                    path.move(to: end)
                    path.addLine(to: CGPoint(
                        x: end.x + 10 * cos(turn),
                        y: end.y + 10 * sin(turn)
                    ))
                }
            }
        }
        .stroke(Color.secondary, lineWidth: 1.5)
        .allowsHitTesting(false)
    }

    @ViewBuilder
    private var joinLine: some View {
        if let joining = canvas.joining {
            Path { path in
                path.move(to: gestures.position(of: joining.from))
                path.addLine(to: joining.to)
            }
            .stroke(Color.accentColor, style: StrokeStyle(lineWidth: 1.5, dash: [4, 4]))
            .allowsHitTesting(false)
        }
    }

    /// What a canvas with nothing on it says. It names the gestures, because
    /// nothing else on screen does.
    @ViewBuilder
    private var emptyCanvasHint: some View {
        if editor.graph.nodes.isEmpty && editor.pending.isEmpty {
            VStack(spacing: 6) {
                Text(editor.isEditing ? "Drag an element here to start." : "Pick a tree, or add one.")
                    .font(.headline)
                Text("Drag the background to move the tree. "
                    + "Shift-drag to select. Pinch to zoom. "
                    + "Drag from a node's handle to join it to another.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            .multilineTextAlignment(.center)
            .padding(24)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .allowsHitTesting(false)
            .accessibilityIdentifier("tree-canvas-gestures-hint")
        }
    }
}

/// One node on the tree canvas: a step or a junction, the goal told apart by
/// a doubled border and the word GOAL, and the join handle a join drag
/// starts from.
private struct TreeNodeView: View {
    let node: TreeGraph.Node
    let isGoal: Bool
    let isSelected: Bool
    /// What the assessment says about the step, or nil while it is unwritten
    /// or a junction.
    let state: StepState?
    let size: CGSize
    let onSelect: (_ addingToSelection: Bool) -> Void
    let onDragChanged: (CGSize) -> Void
    let onDragEnded: (CGSize) -> Void
    let onJoinDragChanged: (CGPoint) -> Void
    let onJoinDragEnded: (CGPoint) -> Void
    let menu: () -> [ElementMenu.Row]
    let onOpenMenu: () -> Void

    @State private var isHovering = false

    var body: some View {
        ZStack {
            switch node.kind {
            case .step:
                step
            case .allOf, .anyOf:
                junction
            }

            if isHovering || isSelected {
                joinHandle
            }
        }
        .frame(width: size.width, height: size.height)
        .contentShape(Rectangle())
        .onHover { isHovering = $0 }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("tree-node-\(node.id)")
        .gesture(
            SpatialTapGesture().modifiers(.shift).onEnded { _ in onSelect(true) }
                .exclusively(before: SpatialTapGesture().onEnded { _ in onSelect(false) })
        )
        .gesture(
            DragGesture(minimumDistance: 3, coordinateSpace: .named("tree-canvas"))
                .onChanged { onDragChanged($0.translation) }
                .onEnded { onDragEnded($0.translation) }
        )
        .contextMenu {
            let rows = menu()
            ElementMenuView(rows: rows)
                .onAppear { onOpenMenu() }
        }
    }

    private var outline: Color {
        if isSelected { return .accentColor }
        return isGoal ? .accentColor : .secondary
    }

    private var step: some View {
        VStack(spacing: 2) {
            if isGoal {
                Text("GOAL")
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.secondary)
            }
            Text(node.title)
                .font(.callout.weight(.semibold))
                .lineLimit(1)
            HStack(spacing: 4) {
                Circle()
                    .fill(TreeStepState.colour(state))
                    .frame(width: 7, height: 7)
                    .help(TreeStepState.says(state))
                Text(node.subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.horizontal, 8)
        .frame(width: size.width, height: size.height)
        .background(RoundedRectangle(cornerRadius: 8).fill(.bar))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(outline, lineWidth: isSelected || isGoal ? 2 : 1)
        )
        .overlay(
            // The goal is told apart at a glance: a doubled border.
            RoundedRectangle(cornerRadius: 11)
                .strokeBorder(Color.accentColor, lineWidth: isGoal ? 1 : 0)
                .padding(-4)
        )
    }

    private var junction: some View {
        Text(node.title)
            .font(.caption.weight(.bold))
            .frame(width: size.width, height: size.height)
            .background(Capsule().fill(.bar))
            .overlay(Capsule().strokeBorder(outline, lineWidth: isSelected ? 2 : 1))
    }

    /// The handle at the right edge, where the edge leaves the node.
    private var joinHandle: some View {
        Circle()
            .fill(Color.accentColor)
            .frame(width: 9, height: 9)
            .position(x: size.width, y: size.height / 2)
            .gesture(
                DragGesture(minimumDistance: 1, coordinateSpace: .named("tree-canvas"))
                    .onChanged { onJoinDragChanged($0.location) }
                    .onEnded { onJoinDragEnded($0.location) }
            )
    }
}

/// An element dropped on the canvas that has not picked a threat yet.
private struct PendingElementView: View {
    let item: PendingElement
    let isSelected: Bool
    let onSelect: (_ addingToSelection: Bool) -> Void
    let onDragChanged: (CGSize) -> Void
    let onDragEnded: (CGSize) -> Void
    let onPick: (AssessedThreat) -> Void
    let menu: () -> [ElementMenu.Row]
    let onOpenMenu: () -> Void

    var body: some View {
        VStack(spacing: 2) {
            Text(item.element.name)
                .font(.callout)
                .lineLimit(1)
            if item.element.threats.isEmpty {
                Text("raises no threat")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Menu("Pick a threat") {
                    ForEach(item.element.threats, id: \.threatKey) { threat in
                        Button(threat.name) { onPick(threat) }
                    }
                }
                .font(.caption)
                .accessibilityIdentifier("pick-threat-\(item.element.payload)")
            }
        }
        .padding(.horizontal, 8)
        .frame(width: TreeLayout.nodeSize.width, height: TreeLayout.nodeSize.height)
        .background(RoundedRectangle(cornerRadius: 8).fill(.bar).opacity(0.8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(
                    isSelected ? Color.accentColor : .secondary,
                    style: StrokeStyle(lineWidth: isSelected ? 2 : 1, dash: [4, 3])
                )
        )
        .contentShape(Rectangle())
        .accessibilityIdentifier("tree-pending-\(item.id)")
        .gesture(
            SpatialTapGesture().modifiers(.shift).onEnded { _ in onSelect(true) }
                .exclusively(before: SpatialTapGesture().onEnded { _ in onSelect(false) })
        )
        .gesture(
            DragGesture(minimumDistance: 3, coordinateSpace: .named("tree-canvas"))
                .onChanged { onDragChanged($0.translation) }
                .onEnded { onDragEnded($0.translation) }
        )
        .contextMenu {
            let rows = menu()
            ElementMenuView(rows: rows)
                .onAppear { onOpenMenu() }
        }
    }
}

/// What the assessment says about one step, in a colour and a sentence.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated enum TreeStepState {
    /// The state the assessment bound for one node, or nil for a junction
    /// or a step not written yet.
    static func state(of node: TreeGraph.Node, in bound: BoundAttackTree?) -> StepState? {
        guard case .step(let target, _) = node.kind else { return nil }
        return bound?.steps.first { $0.key.value == TreeDraft.key(of: target) }?.state
    }

    static func colour(_ state: StepState?) -> Color {
        switch state {
        case .open: .orange
        case .closed: .green
        case .unbound: .red
        case nil: .secondary
        }
    }

    static func says(_ state: StepState?) -> String {
        switch state {
        case .open: "Open: nothing closes this step."
        case .closed: "Closed: a control answers this step."
        case .unbound: "Unbound: the model no longer raises this threat here."
        case nil: "Not written yet."
        }
    }
}
