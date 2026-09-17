import AppKit
import SwiftUI
import ThreatModelKit

/// The diagram. Painting order per spec section 9: background, then every
/// connection in one `Canvas` pass, then the component views.
///
/// This view holds layout. Gestures live in `CanvasGestures` and hit testing
/// in `CanvasHitTest`.
struct CanvasView: View {
    /// The margin the canvas keeps from the window's edge. The palette column
    /// collapses, and the canvas then starts at that edge itself.
    static let windowEdgeMargin: CGFloat = 16

    let session: ThreatModelSession
    let canvas: CanvasState
    /// Which pointing device the person drives the canvas with. A preview and
    /// a drawing test take the mode a new person starts in.
    var pointerMode: PointerMode = .standard

    /// True while the pointer is over this canvas, so a scroll anywhere else
    /// in the application moves nothing here.
    @State private var isPointerOver = false
    /// The monitor reading the scroll events, while this canvas is on screen.
    @State private var scrollMonitor: Any?
    /// The monitor reading the middle-button drag, while this canvas is on
    /// screen. A middle button reaches no SwiftUI gesture.
    @State private var middleButtonMonitor: Any?
    /// The monitor reading whether Space is held down. AppKit states no
    /// modifier flag for Space, so the canvas counts the key itself.
    @State private var spaceMonitor: Any?
    /// True while Space is held down over this canvas, so a drag pans.
    @State private var isSpaceDown = false
    /// Where the pointer last was on the canvas, in view coordinates, so a
    /// wheel zooms about the point the person is looking at.
    @State private var pointerViewPoint: CGPoint = .zero

    private var gestures: CanvasGestures {
        CanvasGestures(session: session, canvas: canvas, isSpaceDown: isSpaceDown)
    }

    private var menus: ElementMenu {
        ElementMenu(session: session, canvas: canvas)
    }

    /// Where the pointer last was on the canvas, in model coordinates, so the
    /// background menu's Draw Zone starts where the click landed.
    @State private var pointerPoint: CGPoint = .zero

    /// What the pointer looks like over open canvas.
    private var pointer: PointerStyle? {
        CanvasPointer.style(isDrawingZone: canvas.isDrawingZone, isPanning: canvas.isPanning)
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

    /// The button number AppKit states for the middle button.
    static let middleButton = 2
    /// The key code AppKit states for Space.
    static let spaceKey: UInt16 = 49

    private func stopReadingScrollEvents() {
        if let scrollMonitor { NSEvent.removeMonitor(scrollMonitor) }
        scrollMonitor = nil
        if let middleButtonMonitor { NSEvent.removeMonitor(middleButtonMonitor) }
        middleButtonMonitor = nil
        if let spaceMonitor { NSEvent.removeMonitor(spaceMonitor) }
        spaceMonitor = nil
        isSpaceDown = false
    }

    /// The part of the model the canvas draws. `CanvasState.drawn(in:)` is
    /// the one function every reader calls, so the view, the gestures and
    /// the menus never disagree about what a person can see.
    var drawn: DrawnDiagram { canvas.drawn(in: session.canvas) }

    private var boxes: [String: ComponentBox] {
        CanvasHitTest.boxes(
            for: drawn.components,
            selected: canvas.selectedComponentIds,
            dragTranslation: canvas.dragTranslation ?? .zero
        )
    }

    var body: some View {
        // A GeometryReader takes the space the split view offers and never
        // reports its children's size back up. Without it the drawing layer,
        // which is thousands of points across, sizes the whole window.
        GeometryReader { geometry in
            ZStack(alignment: .topLeading) {
                Color(nsColor: .textBackgroundColor)
                    .contentShape(Rectangle())
                    // The identifier sits on the background, not on the whole
                    // canvas: an identifier on a container overwrites the
                    // identifier of every element inside it.
                    .accessibilityIdentifier("canvas")
                    // The double-click is read first: a single tap selects,
                    // and a double-click on a flow edits its label.
                    .gesture(gestures.backgroundDoubleTap)
                    .gesture(gestures.backgroundTap)
                    .gesture(gestures.backgroundDrag)
                    // A secondary click on a flow opens the flow's menu, and
                    // one on open canvas opens the canvas's own.
                    .contextMenu {
                        if let connectionId = gestures.connection(under: pointerPoint) {
                            ElementMenuView(rows: menus.connection(connectionId))
                                .onAppear { menus.selectBeforeMenu(connectionId: connectionId) }
                        } else {
                            ElementMenuView(rows: menus.background(at: pointerPoint))
                        }
                    }

                content
                    .scaleEffect(canvas.transform.zoom, anchor: .topLeading)
                    .offset(x: canvas.transform.pan.width, y: canvas.transform.pan.height)

                flowLabelField

                emptyCanvasHint

                // The toolbar is measured against the column's own width,
                // which this reader states. The ZStack around it is as wide as
                // the drawing layer inside it, which is thousands of points,
                // so a control that measures itself against the stack never
                // sees the column narrow.
                canvasToolbar(inColumnOfWidth: geometry.size.width)
            }
            // Zoom to Fit needs to know how much room there is.
            .onAppear { canvas.visibleSize = geometry.size }
            .onChange(of: geometry.size) { _, size in canvas.visibleSize = size }
            // An edit while a filter is on lays the narrowed set out again.
            // The verb writes the coordinates; the body only reads them.
            .onChange(of: session.revision) { canvas.layOutNarrowedSetAgain() }
        }
        .coordinateSpace(.named("canvas"))
        .clipped()
        // SwiftUI has no crosshair pointer; rectSelection is the one macOS
        // shows while a rectangle is being drawn. Over open canvas the pointer
        // is an open hand, and a closed hand while a pan is in flight, because
        // a plain drag moves the diagram.
        .pointerStyle(pointer)
        // A two finger scroll moves the diagram. SwiftUI hands a view no
        // scroll event, so the canvas reads the events the application gets
        // while the pointer is over it.
        .onContinuousHover { phase in
            if case .active(let where_) = phase {
                isPointerOver = true
                pointerViewPoint = where_
                pointerPoint = canvas.transform.modelPoint(where_)
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
        .onKeyPress(keys: [.leftArrow, .rightArrow, .upArrow, .downArrow]) { press in
            let step = press.modifiers.contains(.shift)
                ? CanvasGestures.fineNudgeStep
                : CanvasGestures.nudgeStep
            switch press.key {
            case .leftArrow: gestures.nudge(dx: -step, dy: 0)
            case .rightArrow: gestures.nudge(dx: step, dy: 0)
            case .upArrow: gestures.nudge(dx: 0, dy: -step)
            case .downArrow: gestures.nudge(dx: 0, dy: step)
            default: return .ignored
            }
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
        // The drop runs through the gestures, the way the tree canvas runs
        // its own, so a test drives the same code the drop runs.
        .dropDestination(for: String.self) { technologyIds, location in
            gestures.drop(technologyIds, at: location)
        }
        .sheet(
            isPresented: Binding(
                get: { canvas.isMerging },
                set: { if $0 == false { canvas.stopMerging() } }
            )
        ) {
            MergeSheet(session: session, canvas: canvas)
        }
    }

    private var content: some View {
        ZStack(alignment: .topLeading) {
            ForEach(drawn.zones, id: \.id) { zone in
                let rect = CanvasHitTest.rect(
                    for: zone,
                    drag: canvas.zoneDrag,
                    movingWith: canvas.selectedZoneIds
                )
                ZoneView(
                    zone: zone,
                    risk: session.elementRisks["zone:\(zone.id)"],
                    size: rect.size,
                    isSelected: canvas.isSelected(zoneId: zone.id),
                    onSelect: { canvas.select(zoneId: zone.id, addingToSelection: $0) },
                    onDragChanged: { gestures.zoneDragChanged(zone.id, handle: $0, translation: $1) },
                    onDragEnded: { gestures.zoneDragEnded(zone.id, handle: $0, translation: $1) },
                    isEditingName: canvas.isEditingName(.zone(zone.id)),
                    onStartEditingName: { canvas.startEditingName(.zone(zone.id)) },
                    onCommitName: { gestures.renameZone(zone.id, to: $0) },
                    onCancelName: { canvas.stopEditingName() },
                    menu: { menus.zone(zone.id) },
                    onOpenMenu: { menus.selectBeforeMenu(zoneId: zone.id) }
                )
                .position(x: rect.midX, y: rect.midY)
            }

            if let draft = canvas.zoneDraftRect {
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color.green.opacity(0.07))
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 2, dash: [6, 4]))
                    )
                    .frame(width: draft.width, height: draft.height)
                    .position(x: draft.midX, y: draft.midY)
                    .allowsHitTesting(false)
            }

            ConnectionsLayer(
                origin: contentRect.origin,
                connections: drawn.connections,
                boxes: boxes,
                componentsById: componentsById,
                zones: drawn.zones,
                risks: session.elementRisks,
                guards: session.elementGuards,
                outOfScopeComponentIds: outOfScopeComponentIds,
                selectedConnectionIds: canvas.selectedConnectionIds,
                selectedComponentIds: canvas.selectedComponentIds,
                mitigations: session.canvas.mitigations,
                preview: previewLine
            )
            .frame(width: contentRect.width, height: contentRect.height)
            // The layer starts back past the origin, so it is placed there
            // rather than at the origin the rest of this stack draws from.
            .offset(x: contentRect.minX, y: contentRect.minY)

            ForEach(drawn.components, id: \.id) { component in
                let componentBox = boxes[component.id] ?? ComponentBox(x: component.x, y: component.y)
                ComponentNodeView(
                    component: component,
                    risk: session.elementRisks["component:\(component.id)"],
                    isSelected: canvas.isSelected(componentId: component.id),
                    onSelect: { gestures.selectComponent(component.id, addingToSelection: $0) },
                    onDragChanged: { gestures.nodeDragChanged(component.id, $0) },
                    onDragEnded: { gestures.nodeDragEnded($0) },
                    onAnchorDragChanged: { gestures.anchorDragChanged(component.id, $0) },
                    onAnchorDragEnded: { gestures.anchorDragEnded(component.id, $0) },
                    zoneName: drawn.zones.first { $0.id == component.zoneId }?.name,
                    isEditingName: canvas.isEditingName(.component(component.id)),
                    onStartEditingName: { canvas.startEditingName(.component(component.id)) },
                    onCommitName: { gestures.renameComponent(component.id, to: $0) },
                    onCancelName: { canvas.stopEditingName() },
                    menu: { menus.component(component.id) },
                    onOpenMenu: { menus.selectBeforeMenu(componentId: component.id) }
                )
                .position(x: componentBox.centre.x, y: componentBox.centre.y)
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

    /// The field that edits a flow's label, drawn where the flow's label sits.
    @ViewBuilder
    private var flowLabelField: some View {
        if case .connection(let connectionId) = canvas.editingName,
           let rect = gestures.calloutRect(of: connectionId) {
            let connection = session.canvas.connections.first { $0.id == connectionId }
            InlineNameField(
                text: connection?.description ?? "",
                width: max(160, rect.width),
                identifier: "flow-label-field-\(connectionId)",
                commit: { gestures.labelConnection(connectionId, to: $0) },
                cancel: { canvas.stopEditingName() }
            )
            .scaleEffect(canvas.transform.zoom, anchor: .topLeading)
            .position(
                x: (rect.midX * canvas.transform.zoom) + canvas.transform.pan.width,
                y: (rect.midY * canvas.transform.zoom) + canvas.transform.pan.height
            )
        }
    }

    /// What a canvas with nothing on it says. It names the three gestures,
    /// because nothing else on screen does.
    @ViewBuilder
    private var emptyCanvasHint: some View {
        if session.canvas.components.isEmpty && session.canvas.zones.isEmpty {
            VStack(spacing: 6) {
                Text("Drag a technology here to start.")
                    .font(.headline)
                Text("Drag the background to move the diagram. "
                    + "Shift-drag to select. Pinch to zoom.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            .multilineTextAlignment(.center)
            .padding(24)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .allowsHitTesting(false)
            .accessibilityIdentifier("canvas-gestures-hint")
        }
    }

    /// The controls that float at the top of the diagram.
    ///
    /// The column they float over is as narrow as
    /// `ProjectColumns.minimumDiagramWidth`, and the person changes that width
    /// with the divider of the threats stage. The row with every word shown
    /// needs more room than the narrowest column has, so a column that cannot
    /// hold the words gets the icons alone. Without that the row ran past the
    /// column's trailing edge and drew over the threat sidebar.
    private func canvasToolbar(inColumnOfWidth width: CGFloat) -> some View {
        toolbarRow(showsWords: Self.toolbarShowsWords(inColumnOfWidth: width))
            // Collapsing the palette column puts the canvas at the window's
            // own leading edge, so this margin is all that stands between the
            // Draw zone control and that edge.
            .padding(CanvasView.windowEdgeMargin)
    }

    /// The width the row needs with every word shown: the two margins, the
    /// Draw zone control, the three zoom controls, the two dividers, the gaps
    /// and the tag filter menu.
    static let toolbarWordsWidth: CGFloat = 520

    /// True while the column is wide enough for the words.
    ///
    /// A column of nought is a column not measured yet. The words are the
    /// state the person reads first, so an unmeasured column shows them.
    static func toolbarShowsWords(inColumnOfWidth width: CGFloat) -> Bool {
        width <= 0 || width >= toolbarWordsWidth
    }

    private func toolbarRow(showsWords: Bool) -> some View {
        HStack(spacing: 8) {
            Button {
                canvas.isDrawingZone ? canvas.stopDrawingZone() : canvas.startDrawingZone()
            } label: {
                Label("Draw zone", systemImage: "rectangle.dashed")
            }
            .tint(canvas.isDrawingZone ? Color.accentColor : nil)
            .accessibilityIdentifier("draw-zone")

            Divider().frame(height: 16)

            Button { gestures.zoom(by: 1 / 1.25, about: CGPoint(x: 400, y: 300)) } label: {
                Image(systemName: "minus.magnifyingglass")
            }
            .accessibilityIdentifier("zoom-out")
            Button { canvas.transform = CanvasTransform() } label: {
                Image(systemName: "1.magnifyingglass")
            }
            .accessibilityIdentifier("zoom-reset")
            Button { gestures.zoom(by: 1.25, about: CGPoint(x: 400, y: 300)) } label: {
                Image(systemName: "plus.magnifyingglass")
            }
            .accessibilityIdentifier("zoom-in")

            tagFilterMenu(showsWords: showsWords)
        }
        .modifier(ControlWords(showsWords: showsWords))
        .buttonStyle(.bordered)
    }

    /// Narrows the diagram to the tags a person picks. Always on the
    /// toolbar, even while the model states no tag, so a person always finds
    /// Neighbours and Clear Filter without writing a tag first.
    private func tagFilterMenu(showsWords: Bool) -> some View {
        let tags = TagFilter.tags(in: session.canvas)

        return Group {
            Divider().frame(height: 16)

            Menu {
                if let tagFilterHintRow {
                    Button(tagFilterHintRow) {}
                        .disabled(true)
                } else {
                    ForEach(tags, id: \.self) { tag in
                        Toggle(tag, isOn: picked(tag))
                            .accessibilityIdentifier("tag-filter-\(tag)")
                    }
                }
                Divider()
                // A `Picker` inside a `Menu` draws as a submenu with a tick on
                // the chosen value. A `Stepper` inside a `Menu` draws no
                // control at all on macOS.
                Picker("Neighbours: \(canvas.tagFilter.neighbourDepth)", selection: neighbourDepth) {
                    ForEach(0...5, id: \.self) { depth in
                        Text("\(depth)").tag(depth)
                    }
                }
                .accessibilityIdentifier("tag-filter-neighbours")
                Divider()
                Button("Clear Filter") { canvas.clearTagFilter() }
                    .disabled(isClearFilterEnabled == false)
                    .accessibilityIdentifier("tag-filter-clear")
            } label: {
                Label(tagFilterLabel, systemImage: tagFilterIcon)
            }
            // One width for the words, so a long tag name never widens the
            // row, and the width of an icon for the narrow column.
            .frame(width: showsWords ? 180 : 56)
            .accessibilityIdentifier("tag-filter")
        }
    }

    /// The disabled row the menu shows in place of the tag list while the
    /// model states no tag, or nil while it states one and the tag list
    /// draws instead.
    var tagFilterHintRow: String? {
        TagFilter.tags(in: session.canvas).isEmpty
            ? "No tags yet. Add a tag on the component panel."
            : nil
    }

    /// What the closed menu reads, so a person knows what narrows the
    /// diagram without opening it: what Focus names, else the picked tags
    /// joined by commas, else that nothing narrows it.
    var tagFilterLabel: String {
        if let focusedComponentName {
            return "Focus: \(focusedComponentName)"
        }
        let picked = canvas.tagFilter.pickedTags.sorted()
        return picked.isEmpty ? "Filter" : picked.joined(separator: ", ")
    }

    /// The name the label states for Focus, or nil while Focus is off.
    private var focusedComponentName: String? {
        guard let focusedComponentId = canvas.focusedComponentId else { return nil }
        return session.canvas.components.first { $0.id == focusedComponentId }?.name
    }

    /// True while Clear Filter answers a click: a picked tag or Focus
    /// narrows the diagram. The same condition fills the menu's icon, so a
    /// person who sees fewer components knows why.
    var isClearFilterEnabled: Bool {
        canvas.tagFilter.isNarrowing || canvas.focusedComponentId != nil
    }

    private var tagFilterIcon: String {
        isClearFilterEnabled
            ? "line.3.horizontal.decrease.circle.fill"
            : "line.3.horizontal.decrease.circle"
    }

    private func picked(_ tag: String) -> Binding<Bool> {
        Binding(
            get: { canvas.tagFilter.isPicked(tag) },
            set: { _ in canvas.pick(tag: tag) }
        )
    }

    /// What the neighbours submenu reads and writes.
    var neighbourDepth: Binding<Int> {
        Binding(
            get: { canvas.tagFilter.neighbourDepth },
            set: { canvas.setNeighbourDepth($0) }
        )
    }

    /// Every drawn component by id, so the link layer can read the zone each
    /// end of a link sits in.
    private var componentsById: [String: ViewedComponent] {
        Dictionary(uniqueKeysWithValues: drawn.components.map { ($0.id, $0) })
    }

    /// The components the user turned threats off for. A flow either end of
    /// which is one of these is out of scope too.
    private var outOfScopeComponentIds: Set<String> {
        Set(drawn.components.filter(\.threatsDisabled).map(\.id))
    }

    /// The drawing layer follows the model, so a diagram that reaches far from
    /// the origin still draws its links, whichever way it reaches.
    private var contentRect: CGRect {
        CanvasHitTest.contentRect(
            components: drawn.components,
            zones: drawn.zones
        )
    }

    private var previewLine: (start: CGPoint, end: CGPoint)? {
        guard let drag = canvas.connectionDrag,
              let source = boxes[drag.sourceComponentId] else { return nil }
        return (start: source.centre, end: drag.currentPoint)
    }
}


/// What the pointer says the canvas will do.
///
/// A hand promises a drag that moves the diagram, so it is only right while a
/// plain drag pans. The zone tool draws a rectangle, and macOS shows the
/// rectangle pointer for that.
nonisolated enum CanvasPointer {
    /// Which pointer the canvas asks for. A name rather than the pointer
    /// itself, because `PointerStyle` states no equality and a test must be
    /// able to say which one it got.
    enum Kind: Equatable {
        case openHand
        case closedHand
        case rectangle
    }

    static func kind(isDrawingZone: Bool, isPanning: Bool) -> Kind {
        if isDrawingZone { return .rectangle }
        return isPanning ? .closedHand : .openHand
    }

    static func style(isDrawingZone: Bool, isPanning: Bool) -> PointerStyle? {
        switch kind(isDrawingZone: isDrawingZone, isPanning: isPanning) {
        case .openHand: .grabIdle
        case .closedHand: .grabActive
        case .rectangle: .rectSelection
        }
    }
}

/// Shows or hides the words on the controls that carry an icon too.
///
/// A narrow column takes the icons alone. The words stay in the accessibility
/// label of each control, so a screen reader reads the same name either way.
struct ControlWords: ViewModifier {
    let showsWords: Bool

    @ViewBuilder
    func body(content: Content) -> some View {
        if showsWords {
            content.labelStyle(.titleAndIcon)
        } else {
            content.labelStyle(.iconOnly)
        }
    }
}
