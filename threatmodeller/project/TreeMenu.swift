import ThreatModelKit

/// What a secondary click offers on each thing the tree canvas draws.
///
/// The menu is a value, not a view: this builds the rows and `ElementMenuView`
/// draws them, the way `ElementMenu` does for the architecture canvas. A test
/// reads the rows in order and runs one, so every item is proved to call the
/// same editor verb the panel control calls.
@MainActor
struct TreeMenu {
    let editor: TreeEditor
    let canvas: TreeCanvasState
    let elements: [TreeElement]

    private var gestures: TreeCanvasGestures {
        TreeCanvasGestures(editor: editor, canvas: canvas, elements: elements)
    }

    /// A secondary click on a thing that is not selected selects it alone. A
    /// secondary click on a selected thing keeps the whole selection, so
    /// Delete still acts on all of it.
    func selectBeforeMenu(_ id: String) {
        guard canvas.isSelected(id) == false else { return }
        canvas.select(id, addingToSelection: false)
    }

    /// The menu on a node.
    func node(_ id: String) -> [ElementMenu.Row] {
        var rows: [ElementMenu.Row] = []
        if case .step = editor.graph.node(id)?.kind, editor.graph.goalId != id {
            rows.append(.item(id: "context-tree-set-goal", title: "Set as Goal") {
                editor.setGoal(id)
            })
        }
        if editor.graph.edges.contains(where: { $0.from == id }) {
            rows.append(.item(id: "context-tree-cut-join", title: "Cut the Outgoing Join") {
                editor.cutOutgoingJoin(of: id)
            })
        }
        if rows.isEmpty == false {
            rows.append(.separator(id: "context-tree-separator"))
        }
        rows.append(.item(id: "context-tree-delete", title: "Delete", shortcut: .delete) {
            gestures.deleteSelection()
        })
        return rows
    }

    /// The menu on a pending element: one item per threat the model raises
    /// on it, then Delete.
    func pending(_ id: String) -> [ElementMenu.Row] {
        var rows: [ElementMenu.Row] = []
        if let item = editor.pending.first(where: { $0.id == id }) {
            if item.element.threats.isEmpty {
                rows.append(.item(id: "context-pending-none", title: "Raises no threat", isEnabled: false) {})
            }
            for threat in item.element.threats {
                rows.append(.item(id: "context-pending-\(threat.threatKey)", title: threat.name) {
                    editor.pick(threat, for: id)
                })
            }
            rows.append(.separator(id: "context-pending-separator"))
        }
        rows.append(.item(id: "context-pending-delete", title: "Delete", shortcut: .delete) {
            gestures.deleteSelection()
        })
        return rows
    }

    /// The menu on open canvas.
    func background() -> [ElementMenu.Row] {
        [
            .item(id: "context-tree-select-all", title: "Select All", shortcut: .selectAll) {
                gestures.selectAll()
            },
            .item(id: "context-tree-zoom-to-fit", title: "Zoom to Fit") {
                gestures.zoomToFit()
            },
            .separator(id: "context-tree-background-separator"),
            .item(id: "context-tree-lay-out", title: "Lay Out Tree") {
                gestures.layOutTree()
            }
        ]
    }
}
