import CoreGraphics
import SwiftUI
import ThreatModelKit

/// What a secondary click offers on each thing the canvas draws.
///
/// The menu is a value, not a view: `ContextMenuItems` builds the rows and
/// `ElementMenuView` draws them. A test reads the rows in order and runs one,
/// so every item is proved to call the same session verb the panel control or
/// the Edit menu item calls, and the two paths cannot drift.
@MainActor
struct ElementMenu {
    let session: ThreatModelSession
    let canvas: CanvasState

    /// One row of a menu.
    enum Row: Identifiable {
        case item(id: String, title: String, shortcut: Shortcut? = nil, isEnabled: Bool = true, run: () -> Void)
        case submenu(id: String, title: String, rows: [Row])
        case separator(id: String)

        var id: String {
            switch self {
            case .item(let id, _, _, _, _): id
            case .submenu(let id, _, _): id
            case .separator(let id): id
            }
        }

        /// What a test reads: the identifier of every row, in order.
        var title: String {
            switch self {
            case .item(_, let title, _, _, _): title
            case .submenu(_, let title, _): title
            case .separator: ""
            }
        }
    }

    /// The keystroke the Edit menu already states for this verb.
    struct Shortcut: Equatable {
        let key: KeyEquivalent
        let modifiers: EventModifiers

        static let cut = Shortcut(key: "x", modifiers: .command)
        static let copy = Shortcut(key: "c", modifiers: .command)
        static let duplicate = Shortcut(key: "d", modifiers: .command)
        static let delete = Shortcut(key: .delete, modifiers: [])
        static let paste = Shortcut(key: "v", modifiers: .command)
        static let selectAll = Shortcut(key: "a", modifiers: .command)
    }

    static let privileges = [
        ("user", "User"),
        ("admin", "Administrator"),
        ("root", "Root"),
        ("system", "System"),
        ("kernel", "Kernel")
    ]

    private static let zoneKinds = [("private", "Private"), ("public", "Public")]

    private static let flowKinds = [
        ("network", "Network"),
        ("ipc", "Local IPC"),
        ("file", "File"),
        ("syscall", "System Call"),
        ("human", "Human")
    ]

    // MARK: what a secondary click selects

    /// A secondary click on a thing that is not selected selects it alone. A
    /// secondary click on a selected thing keeps the whole selection, so Cut,
    /// Copy, Duplicate and Delete still act on all of it.
    func selectBeforeMenu(componentId: String) {
        guard canvas.isSelected(componentId: componentId) == false else { return }
        canvas.select(componentId: componentId, addingToSelection: false)
    }

    func selectBeforeMenu(zoneId: String) {
        guard canvas.isSelected(zoneId: zoneId) == false else { return }
        canvas.select(zoneId: zoneId, addingToSelection: false)
    }

    func selectBeforeMenu(connectionId: String) {
        guard canvas.isSelected(connectionId: connectionId) == false else { return }
        canvas.select(connectionId: connectionId, addingToSelection: false)
    }

    // MARK: the four menus

    func component(_ componentId: String) -> [Row] {
        let component = session.canvas.components.first { $0.id == componentId }
        var rows: [Row] = [
            .item(id: "context-component-rename", title: "Rename\u{2026}") {
                canvas.select(componentId: componentId, addingToSelection: false)
                canvas.startEditingName(.component(componentId))
            },
            .item(id: "context-component-show-threats", title: "Show Threats") {
                show(.threats, elementId: "component:\(componentId)")
            },
            .item(id: "context-component-show-controls", title: "Show Controls") {
                show(.controls, elementId: "component:\(componentId)")
            },
            .item(id: "context-component-focus", title: "Focus") {
                canvas.focus(componentId: componentId)
            },
            .separator(id: "context-component-separator-1"),
            .item(
                id: "context-component-raise-threats",
                title: component?.threatsDisabled == true ? "Raise Threats" : "Raise Threats \u{2713}"
            ) {
                guard let component else { return }
                write(component, threatsDisabled: component.threatsDisabled == false)
            },
            .submenu(
                id: "context-component-sensitivity",
                title: "Sensitivity",
                rows: session.classificationChoices.map { level in
                    .item(
                        id: "context-component-sensitivity-\(level.id)",
                        title: level.label
                    ) {
                        guard let component else { return }
                        write(component, sensitivityId: level.id)
                    }
                }
            ),
            .submenu(
                id: "context-component-runs-as",
                title: "Runs As",
                rows: Self.privileges.map { id, label in
                    .item(id: "context-component-runs-as-\(id)", title: label) {
                        guard let component else { return }
                        write(component, runsAsId: id)
                    }
                }
            ),
            .submenu(
                id: "context-component-connect-to",
                title: "Connect To",
                rows: session.canvas.components
                    .filter { $0.id != componentId }
                    .map { other in
                        .item(id: "context-component-connect-to-\(other.id)", title: other.name) {
                            session.connect(
                                sourceComponentId: componentId,
                                targetComponentId: other.id
                            )
                        }
                    }
            ),
        ]
        // Merge joins the whole selection, so it is offered only when two or
        // more components are selected, and never over a user: a user is
        // not a component.
        let selected = canvas.selectedComponentIds
        let holdsAUser = session.canvas.components.contains { selected.contains($0.id) && $0.isUser }
        if selected.count >= 2, holdsAUser == false {
            rows.append(
                .item(id: "context-component-merge", title: "Merge\u{2026}") {
                    canvas.startMerging(componentIds: Array(selected))
                }
            )
        }
        rows += [
            .separator(id: "context-component-separator-2"),
            .item(id: "context-component-cut", title: "Cut", shortcut: .cut) { cutSelection() },
            .item(id: "context-component-copy", title: "Copy", shortcut: .copy) { copySelection() },
            .item(id: "context-component-duplicate", title: "Duplicate", shortcut: .duplicate) {
                duplicateSelection()
            },
            .separator(id: "context-component-separator-3"),
            .item(id: "context-component-delete", title: "Delete", shortcut: .delete) {
                deleteSelection()
            }
        ]
        return rows
    }

    func zone(_ zoneId: String) -> [Row] {
        let zone = session.canvas.zones.first { $0.id == zoneId }
        let inside = componentsInside(zoneId)
        return [
            .item(id: "context-zone-rename", title: "Rename\u{2026}") {
                canvas.select(zoneId: zoneId, addingToSelection: false)
                canvas.startEditingName(.zone(zoneId))
            },
            .item(id: "context-zone-show-threats", title: "Show Threats") {
                show(.threats, elementId: "zone:\(zoneId)")
            },
            .item(id: "context-zone-show-controls", title: "Show Controls") {
                show(.controls, elementId: "zone:\(zoneId)")
            },
            .separator(id: "context-zone-separator-1"),
            .submenu(
                id: "context-zone-kind",
                title: "Kind",
                rows: Self.zoneKinds.map { id, label in
                    .item(id: "context-zone-kind-\(id)", title: label) {
                        guard let zone else { return }
                        write(zone, networkZoneId: id)
                    }
                }
            ),
            .item(
                id: "context-zone-select-contents",
                title: "Select Contents",
                isEnabled: inside.isEmpty == false
            ) {
                canvas.select(componentIds: inside)
            },
            .separator(id: "context-zone-separator-2"),
            .item(id: "context-zone-cut", title: "Cut", shortcut: .cut) { cutSelection() },
            .item(id: "context-zone-copy", title: "Copy", shortcut: .copy) { copySelection() },
            .item(id: "context-zone-duplicate", title: "Duplicate", shortcut: .duplicate) {
                duplicateSelection()
            },
            .separator(id: "context-zone-separator-3"),
            .item(id: "context-zone-delete", title: "Delete", shortcut: .delete) { deleteSelection() }
        ]
    }

    func connection(_ connectionId: String) -> [Row] {
        let connection = session.canvas.connections.first { $0.id == connectionId }
        return [
            .item(id: "context-connection-label", title: "Label\u{2026}") {
                canvas.select(connectionId: connectionId, addingToSelection: false)
                canvas.startEditingName(.connection(connectionId))
            },
            .item(id: "context-connection-show-threats", title: "Show Threats") {
                show(.threats, elementId: "connection:\(connectionId)")
            },
            .separator(id: "context-connection-separator-1"),
            .submenu(
                id: "context-connection-kind",
                title: "Kind",
                rows: Self.flowKinds.map { id, label in
                    .item(id: "context-connection-kind-\(id)", title: label) {
                        session.setConnectionProperties(
                            connectionId: connectionId,
                            kind: id,
                            description: connection?.description
                        )
                    }
                }
            ),
            .separator(id: "context-connection-separator-2"),
            .item(id: "context-connection-delete", title: "Delete", shortcut: .delete) {
                deleteSelection()
            }
        ]
    }

    /// The menu on open canvas. The point is where the click landed, so Draw
    /// Zone starts there.
    func background(at point: CGPoint) -> [Row] {
        [
            .item(id: "context-canvas-paste", title: "Paste", shortcut: .paste) {
                let pasted = session.paste()
                canvas.selectAll(componentIds: pasted.componentIds, zoneIds: pasted.zoneIds)
            },
            .item(id: "context-canvas-select-all", title: "Select All", shortcut: .selectAll) {
                // Only what the canvas draws: with a tag filter on, the
                // elements it hides are not there to select.
                let drawn = canvas.tagFilter.narrow(session.canvas)
                canvas.selectAll(
                    componentIds: drawn.components.map(\.id),
                    zoneIds: drawn.zones.map(\.id)
                )
            },
            .separator(id: "context-canvas-separator-1"),
            .item(id: "context-canvas-draw-zone", title: "Draw Zone") {
                canvas.startDrawingZone()
                canvas.zoneDraft = (start: point, end: point)
            }
        ]
    }

    // MARK: what the items call

    /// The threats of one element, on the stage that answers them.
    private func show(_ stage: WorkStage, elementId: String) {
        session.focus(onElementId: elementId)
        canvas.showStage?(stage)
    }

    private func cutSelection() {
        session.cutSelection(
            componentIds: Array(canvas.selectedComponentIds),
            zoneIds: Array(canvas.selectedZoneIds)
        )
        canvas.clearSelection()
    }

    private func copySelection() {
        session.copySelection(
            componentIds: Array(canvas.selectedComponentIds),
            zoneIds: Array(canvas.selectedZoneIds)
        )
    }

    private func duplicateSelection() {
        let made = session.duplicate(
            componentIds: Array(canvas.selectedComponentIds),
            zoneIds: Array(canvas.selectedZoneIds)
        )
        canvas.selectAll(componentIds: made.componentIds, zoneIds: made.zoneIds)
    }

    private func deleteSelection() {
        CanvasGestures(session: session, canvas: canvas).deleteSelection()
    }

    /// Every component the zone holds, by the same geometry the model uses.
    private func componentsInside(_ zoneId: String) -> [String] {
        session.canvas.components.filter { $0.zoneId == zoneId }.map(\.id)
    }

    private func write(
        _ component: ViewedComponent,
        sensitivityId: String? = nil,
        threatsDisabled: Bool? = nil,
        runsAsId: String? = nil
    ) {
        session.setComponentProperties(
            componentId: component.id,
            name: component.customName,
            sensitivityId: sensitivityId ?? component.sensitivityId,
            threatsDisabled: threatsDisabled ?? component.threatsDisabled,
            runsAsId: runsAsId ?? component.runsAsId,
            shapeId: component.shapeOverrideId
        )
    }

    private func write(_ zone: ViewedZone, networkZoneId: String) {
        session.setZoneProperties(
            zoneId: zone.id,
            name: zone.customName,
            networkZoneId: networkZoneId,
            networkTypeId: zone.networkTypeId,
            riskReductionEnabled: zone.riskReductionEnabled,
            riskReductionPercent: zone.riskReductionPercent,
            boundaryId: zone.boundaryId
        )
    }
}

/// Draws the rows of one menu.
struct ElementMenuView: View {
    let rows: [ElementMenu.Row]

    var body: some View {
        ForEach(rows) { row in
            switch row {
            case .item(let id, let title, let shortcut, let isEnabled, let run):
                Button(title, action: run)
                    .keyboardShortcut(shortcut)
                    .disabled(isEnabled == false)
                    .accessibilityIdentifier(id)
            case .submenu(let id, let title, let rows):
                Menu(title) { ElementMenuView(rows: rows) }
                    .accessibilityIdentifier(id)
            case .separator:
                Divider()
            }
        }
    }
}

private extension View {
    /// The shortcut the Edit menu states for this verb, or none.
    @ViewBuilder
    func keyboardShortcut(_ shortcut: ElementMenu.Shortcut?) -> some View {
        if let shortcut {
            keyboardShortcut(shortcut.key, modifiers: shortcut.modifiers)
        } else {
            self
        }
    }
}
