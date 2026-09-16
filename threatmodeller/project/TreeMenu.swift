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

    /// A secondary click on a join that is not selected selects it alone.
    func selectBeforeMenu(_ edge: TreeGraph.Edge) {
        guard canvas.isSelected(edge) == false else { return }
        canvas.select(edge, addingToSelection: false)
    }

    /// The menu on a node.
    func node(_ id: String) -> [ElementMenu.Row] {
        var rows: [ElementMenu.Row] = []
        if case .step = editor.graph.node(id)?.kind, editor.graph.goalId != id {
            rows.append(.item(id: "context-tree-set-goal", title: "Set as Goal") {
                editor.setGoal(id)
            })
        }
        if let offered = joinTo(id) { rows.append(offered) }
        rows.append(contentsOf: cutOutgoing(id))
        rows.append(contentsOf: threatsOfABox(id))
        if rows.isEmpty == false {
            rows.append(.separator(id: "context-tree-separator"))
        }
        rows.append(.item(id: "context-tree-delete", title: "Delete", shortcut: .delete) {
            gestures.deleteSelection()
        })
        return rows
    }

    /// The Join to\u{2026} submenu: every join the graph offers the node,
    /// named by the far end. A join this node feeds takes the far end's
    /// title; a join this node takes reads "From <title>". A node offered
    /// none gets no submenu.
    private func joinTo(_ id: String) -> ElementMenu.Row? {
        let offered = editor.graph.joinsOffered(for: id)
        guard offered.isEmpty == false else { return nil }
        return .submenu(
            id: "context-tree-join-to",
            title: "Join to\u{2026}",
            rows: offered.map { edge in
                let feeds = edge.from == id
                let other = feeds ? edge.to : edge.from
                let title = editor.graph.node(other)?.title ?? other
                return .item(
                    id: feeds ? "context-tree-join-to-\(other)" : "context-tree-join-from-\(other)",
                    title: feeds ? title : "From \(title)"
                ) {
                    gestures.join(from: edge.from, to: edge.to)
                }
            }
        )
    }

    /// A filled box is offered the threats the model raises on its element,
    /// the way a pending element is.
    private func threatsOfABox(_ id: String) -> [ElementMenu.Row] {
        guard case .placeholder(let element?) = editor.graph.node(id)?.kind else { return [] }
        if element.threats.isEmpty {
            return [.item(id: "context-box-none", title: "Raises no threat", isEnabled: false) {}]
        }
        return element.threats.map { threat in
            .item(id: "context-box-\(threat.threatKey)", title: threat.name) {
                editor.pick(threat, for: id)
            }
        }
    }

    /// Cut the Outgoing Join: one row for a node that feeds one node, and a
    /// submenu naming each far end for a node that feeds several.
    private func cutOutgoing(_ id: String) -> [ElementMenu.Row] {
        let outgoing = editor.graph.edges.filter { $0.from == id }
        guard outgoing.isEmpty == false else { return [] }
        guard outgoing.count > 1 else {
            return [.item(id: "context-tree-cut-join", title: "Cut the Outgoing Join") {
                editor.cutOutgoingJoin(of: id)
            }]
        }
        var rows: [ElementMenu.Row] = outgoing.map { edge in
            .item(
                id: "context-tree-cut-join-\(edge.to)",
                title: editor.graph.node(edge.to)?.title ?? edge.to
            ) {
                editor.cut(edge)
            }
        }
        rows.append(.separator(id: "context-tree-cut-join-separator"))
        rows.append(.item(id: "context-tree-cut-every-join", title: "Cut every Outgoing Join") {
            editor.cutOutgoingJoin(of: id)
        })
        return [.submenu(id: "context-tree-cut-join", title: "Cut the Outgoing Join", rows: rows)]
    }

    /// The menu on one join.
    func edge(_ edge: TreeGraph.Edge) -> [ElementMenu.Row] {
        [
            .item(id: "context-tree-edge-cut", title: "Cut this Join") {
                editor.cut(edge)
            },
            .separator(id: "context-tree-edge-separator"),
            .item(id: "context-tree-edge-delete", title: "Delete", shortcut: .delete) {
                gestures.deleteSelection()
            }
        ]
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

    /// The menu on open canvas. Two selected nodes are offered Join, from the
    /// first selected to the second.
    func background() -> [ElementMenu.Row] {
        var rows: [ElementMenu.Row] = []
        if canvas.selectedEdges.isEmpty, canvas.selectedInOrder.count == 2 {
            let pair = canvas.selectedInOrder
            rows.append(.item(id: "context-tree-join", title: "Join") {
                gestures.join(from: pair[0], to: pair[1])
            })
            rows.append(.separator(id: "context-tree-join-separator"))
        }
        rows.append(contentsOf: [
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
        ])
        return rows
    }
}
