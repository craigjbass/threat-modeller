import SwiftUI
import ThreatModelKit

/// The right sidebar of the Attack Trees stage: the selected node, or the
/// tree in front when nothing is selected.
///
/// The design in
/// `docs/superpowers/specs/2026-09-16-attack-tree-stage-design.md` states
/// what each state shows. `TreeSelection` states the words, so a test reads
/// them without a window.
struct TreeSelectionPanel: View {
    let editor: TreeEditor
    let canvas: TreeCanvasState
    /// What the assessment bound for the tree in front, or nil while it is
    /// unwritten.
    let bound: BoundAttackTree?

    private var selection: TreeSelection {
        TreeSelection.of(editor: editor, canvas: canvas, bound: bound)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                switch selection {
                case .noTree:
                    Text("Pick a tree, or add one.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                case .tree(let tree):
                    treePanel(tree)
                case .node(let node):
                    nodePanel(node)
                case .pending(let pending):
                    pendingPanel(pending)
                case .several(let count):
                    Text("\(count) nodes are selected.")
                        .font(.callout)
                    Button("Delete", role: .destructive) { gestures.deleteSelection() }
                        .accessibilityIdentifier("tree-selection-delete")
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .accessibilityIdentifier("tree-selection-panel")
    }

    private var gestures: TreeCanvasGestures {
        TreeCanvasGestures(editor: editor, canvas: canvas, elements: [])
    }

    // MARK: the tree in front

    @ViewBuilder
    private func treePanel(_ tree: TreeSelection.Tree) -> some View {
        Text("This tree")
            .font(.subheadline.weight(.semibold))

        LabeledContent("Name") {
            DeferredTextField(
                title: "Name",
                text: editor.name,
                width: 200,
                identifier: "attack-tree-name",
                commit: { editor.setName($0) }
            )
        }

        LabeledContent("Description") {
            DeferredTextField(
                title: "Description",
                text: editor.description,
                width: 200,
                identifier: "attack-tree-description",
                commit: { editor.setDescription($0) }
            )
        }

        LabeledContent("Raises risk by") {
            HStack(spacing: 4) {
                DeferredTextField(
                    title: "0",
                    text: "\(editor.raisesRiskBy)",
                    width: 60,
                    identifier: "attack-tree-raises-risk-by",
                    commit: { typed in
                        if let percent = Int(typed.trimmingCharacters(in: .whitespaces)) {
                            editor.setRaisesRiskBy(percent)
                        }
                    }
                )
                Text("per cent")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }

        Divider()

        Text(tree.standing)
            .font(.caption)
            .foregroundStyle(tree.isRefused ? Color.orange : .secondary)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityIdentifier("attack-tree-standing")

        Divider()

        Button("Delete Tree", role: .destructive) { editor.deleteTree() }
            .accessibilityIdentifier("delete-attack-tree")
    }

    // MARK: the selected node

    @ViewBuilder
    private func nodePanel(_ node: TreeSelection.Node) -> some View {
        Text(node.isGoal ? "The goal" : node.isJunction ? "A junction" : "A step")
            .font(.subheadline.weight(.semibold))

        LabeledContent("Threat", value: node.threat)
            .accessibilityIdentifier("tree-selected-threat")
        LabeledContent("Element", value: node.element)
            .accessibilityIdentifier("tree-selected-element")
        LabeledContent("Score") {
            HStack(spacing: 6) {
                Circle()
                    .fill(TreeStepState.colour(node.state))
                    .frame(width: 8, height: 8)
                Text(node.score)
            }
        }
        .accessibilityIdentifier("tree-selected-score")

        Divider()

        if node.canBecomeGoal {
            Button("Set as Goal") { editor.setGoal(node.id) }
                .accessibilityIdentifier("tree-selection-set-goal")
        }
        if node.feedsANode {
            Button("Cut the Outgoing Join") { editor.cutOutgoingJoin(of: node.id) }
                .accessibilityIdentifier("tree-selection-cut-join")
        }
        Button("Delete", role: .destructive) { gestures.deleteSelection() }
            .accessibilityIdentifier("tree-selection-delete")
    }

    // MARK: a dropped element waiting for a threat

    @ViewBuilder
    private func pendingPanel(_ pending: PendingElement) -> some View {
        Text("A dropped element")
            .font(.subheadline.weight(.semibold))

        LabeledContent("Element", value: pending.element.name)
            .accessibilityIdentifier("tree-selected-element")

        if pending.element.threats.isEmpty {
            Text("This element raises no threat, so it becomes no step.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            Text("Pick the threat this step reaches.")
                .font(.caption)
                .foregroundStyle(.secondary)
            ForEach(pending.element.threats, id: \.threatKey) { threat in
                Button(threat.name) { editor.pick(threat, for: pending.id) }
                    .accessibilityIdentifier("tree-selection-pick-\(threat.threatKey)")
            }
        }

        Divider()

        Button("Delete", role: .destructive) { gestures.deleteSelection() }
            .accessibilityIdentifier("tree-selection-delete")
    }
}

/// What the right sidebar shows, as words a test reads.
enum TreeSelection: Equatable {
    struct Tree: Equatable {
        /// The bound score, or the refusal.
        let standing: String
        let isRefused: Bool
    }

    struct Node: Equatable {
        let id: String
        let threat: String
        let element: String
        /// What the assessment says: open, closed, unbound, or not written.
        let score: String
        let state: StepState?
        let isGoal: Bool
        let isJunction: Bool
        let canBecomeGoal: Bool
        let feedsANode: Bool
    }

    case noTree
    case tree(Tree)
    case node(Node)
    case pending(PendingElement)
    case several(Int)

    @MainActor
    static func of(editor: TreeEditor, canvas: TreeCanvasState, bound: BoundAttackTree?) -> TreeSelection {
        guard editor.isEditing else { return .noTree }
        let selected = canvas.selectedIds
        guard selected.count <= 1 else { return .several(selected.count) }
        guard let id = selected.first else {
            return .tree(Tree(
                standing: editor.refusal.map { "Not written: \($0)." } ?? written(editor: editor, bound: bound),
                isRefused: editor.refusal != nil
            ))
        }
        if let pending = editor.pending.first(where: { $0.id == id }) {
            return .pending(pending)
        }
        guard let node = editor.graph.node(id) else { return .noTree }
        let isGoal = editor.graph.goalId == id
        let state = TreeStepState.state(of: node, in: bound)
        switch node.kind {
        case .step:
            return .node(Node(
                id: id,
                threat: node.title,
                element: node.subtitle,
                score: TreeStepState.says(state),
                state: state,
                isGoal: isGoal,
                isJunction: false,
                canBecomeGoal: isGoal == false,
                feedsANode: editor.graph.edges.contains { $0.from == id }
            ))
        case .allOf, .anyOf:
            let feeders = editor.graph.edges.filter { $0.to == id }.count
            return .node(Node(
                id: id,
                threat: node.kind == .allOf ? "Every step under it" : "Any step under it",
                element: feeders == 1 ? "1 node feeds it" : "\(feeders) nodes feed it",
                score: "A junction has no score of its own.",
                state: nil,
                isGoal: false,
                isJunction: true,
                canBecomeGoal: false,
                feedsANode: editor.graph.edges.contains { $0.from == id }
            ))
        }
    }

    /// What the assessment says about the written tree.
    @MainActor
    private static func written(editor: TreeEditor, bound: BoundAttackTree?) -> String {
        guard let scored = bound, scored.id == editor.id else {
            return "Written. The next assessment scores this tree."
        }
        if scored.isStale { return "Stale: a step names something this model no longer raises." }
        return scored.isOpen
            ? "Open: the goal's score moves \(scored.scoreBefore) \u{2192} \(scored.score)."
            : "Closed: every route is answered, and no score moves."
    }
}
