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
    /// Which pointing device the person drives the canvas with, held by
    /// reference so the scroll monitor reads a later change. A preview takes
    /// the mode a new person starts in.
    var pointerMode: PointerModeBox = PointerModeBox()
    /// What installs and removes the scroll monitor. A test's fake counts
    /// how many are active.
    var eventMonitors: any LocalEventMonitoring = AppKitEventMonitoring()

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

    /// A click the canvas takes: it selects the join under the pointer, and
    /// clears the selection where no join sits.
    private var backgroundTap: some Gesture {
        SpatialTapGesture(coordinateSpace: .named("tree-canvas")).modifiers(.shift)
            .onEnded { gestures.canvasTap(at: $0.location, addingToSelection: true) }
            .exclusively(
                before: SpatialTapGesture(coordinateSpace: .named("tree-canvas"))
                    .onEnded { gestures.canvasTap(at: $0.location, addingToSelection: false) }
            )
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
        scrollMonitor = eventMonitors.addLocalMonitor(matching: .scrollWheel) { event in
            guard isPointerOver else { return event }
            gestures.wheel(
                by: CGSize(width: event.scrollingDeltaX, height: event.scrollingDeltaY),
                at: pointerViewPoint,
                isShiftDown: event.modifierFlags.contains(.shift),
                mode: pointerMode.mode
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
        if let scrollMonitor { eventMonitors.removeMonitor(scrollMonitor) }
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
                    isOutside: TreeConnectable.outsideJoin(from: node.id, in: editor.graph, elements: elements) != nil,
                    size: gestures.size(of: node.id),
                    reach: gestures.joinHandleReach,
                    onSelect: { gestures.selectNode(node.id, addingToSelection: $0) },
                    onDragChanged: { start, location, translation in
                        gestures.dragChanged(on: node.id, from: start, to: location, by: translation)
                    },
                    onDragEnded: { start, location, translation in
                        gestures.dragEnded(on: node.id, from: start, to: location, by: translation)
                    },
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

    /// Every join, each one a view of its own, so a click selects it and a
    /// secondary click opens its menu.
    private var edgeLines: some View {
        ForEach(gestures.edgeLines) { line in
            TreeEdgeView(
                line: line,
                isSelected: canvas.isSelected(line.edge),
                onTap: { location, addingToSelection in
                    gestures.canvasTap(at: location, addingToSelection: addingToSelection)
                },
                menu: { menus.edge(line.edge) },
                onOpenMenu: { menus.selectBeforeMenu(line.edge) }
            )
        }
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
    /// True for a step that feeds a node its element does not reach: no flow
    /// or zone joins the two. The join is written; the mark says so.
    let isOutside: Bool
    let size: CGSize
    /// How far the join handle's hit region reaches past the node's right
    /// edge, in model units. The node's own frame grows by it on both sides,
    /// so the whole region sits inside the view that reads the drag.
    let reach: CGFloat
    let onSelect: (_ addingToSelection: Bool) -> Void
    let onDragChanged: (_ start: CGPoint, _ location: CGPoint, _ translation: CGSize) -> Void
    let onDragEnded: (_ start: CGPoint, _ location: CGPoint, _ translation: CGSize) -> Void
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
            case .placeholder(let element):
                box(element)
            }

            if isHovering || isSelected {
                joinHandle
            }
        }
        .frame(width: size.width + reach * 2, height: size.height)
        .contentShape(Rectangle())
        .onHover { isHovering = $0 }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("tree-node-\(node.id)")
        .gesture(
            SpatialTapGesture().modifiers(.shift).onEnded { _ in onSelect(true) }
                .exclusively(before: SpatialTapGesture().onEnded { _ in onSelect(false) })
        )
        .gesture(
            // One drag gesture reads both: a drag that starts on the join
            // handle joins, and every other drag moves the selection.
            DragGesture(minimumDistance: 3, coordinateSpace: .named("tree-canvas"))
                .onChanged { onDragChanged($0.startLocation, $0.location, $0.translation) }
                .onEnded { onDragEnded($0.startLocation, $0.location, $0.translation) }
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
                if isOutside {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                        .help("No flow or zone joins this element to the one it feeds.")
                        .accessibilityIdentifier("tree-node-outside-\(node.id)")
                }
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

    /// A box waiting for an element, then a threat: a dashed outline, the
    /// element it holds or **Any element**, and what to do next.
    private func box(_ element: TreeElement?) -> some View {
        VStack(spacing: 2) {
            Text(node.title)
                .font(.callout.weight(.semibold))
                .lineLimit(1)
            Text(element == nil ? "Join it, then pick an element" : "Pick a threat")
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(.horizontal, 8)
        .frame(width: size.width, height: size.height)
        .background(RoundedRectangle(cornerRadius: 8).fill(.bar).opacity(0.8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(
                    isSelected ? Color.accentColor : .secondary,
                    style: StrokeStyle(lineWidth: isSelected ? 2 : 1, dash: [6, 4])
                )
        )
    }

    /// The handle at the right edge, where the edge leaves the node. It draws
    /// only: the node's own drag gesture reads where a drag started, so no
    /// gesture of the handle's own races it.
    private var joinHandle: some View {
        Circle()
            .fill(Color.accentColor)
            .frame(width: TreeLayout.joinHandleSize, height: TreeLayout.joinHandleSize)
            .position(x: reach + size.width, y: size.height / 2)
            .allowsHitTesting(false)
    }
}

/// One join on the tree canvas: the line, the head that states what feeds
/// what, and the region a click selects it in.
struct TreeEdgeView: View {
    let line: TreeEdgeLine
    let isSelected: Bool
    let onTap: (_ location: CGPoint, _ addingToSelection: Bool) -> Void
    let menu: () -> [ElementMenu.Row]
    let onOpenMenu: () -> Void

    var body: some View {
        line.drawnPath
            .stroke(
                isSelected ? Color.accentColor : Color.secondary,
                lineWidth: isSelected ? 3 : 1.5
            )
            .contentShape(line.hitPath)
            .accessibilityIdentifier("tree-edge-\(line.id)")
            .gesture(
                SpatialTapGesture(coordinateSpace: .named("tree-canvas")).modifiers(.shift)
                    .onEnded { onTap($0.location, true) }
                    .exclusively(
                        before: SpatialTapGesture(coordinateSpace: .named("tree-canvas"))
                            .onEnded { onTap($0.location, false) }
                    )
            )
            .contextMenu {
                ElementMenuView(rows: menu())
                    .onAppear { onOpenMenu() }
            }
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
