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
    /// The elements the `.arch` file states, for the search on a box and
    /// the warning on a join the flows do not support.
    var elements: [TreeElement] = []
    /// Every control description the model holds, in alphabetical order,
    /// for the menu that names one as sufficient to close the whole route.
    var controls: [String] = []
    /// The threats the assessment holds, so the selected node states the
    /// controls on its own threat.
    var threats: [AssessedThreat] = []
    /// Writes one control status. The threat card writes through the same use
    /// case, so one status has one writer and either stage gives the
    /// `.controls` file the same bytes.
    var onSetControlStatus: (_ key: String, _ statusId: String) -> Void = { _, _ in }

    private var selection: TreeSelection {
        TreeSelection.of(
            editor: editor,
            canvas: canvas,
            bound: bound,
            elements: elements,
            threats: threats
        )
    }

    /// The write the status picker makes.
    func setStatus(of control: AssessedControl, to statusId: String) {
        onSetControlStatus(control.key, statusId)
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
                case .box(let box):
                    boxPanel(box)
                case .join(let join):
                    joinPanel(join)
                case .several(let count):
                    Text("\(count) things are selected.")
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
                write: { editor.setName($0) }
            )
        }

        LabeledContent("Description") {
            DeferredTextField(
                title: "Description",
                text: editor.description,
                width: 200,
                identifier: "attack-tree-description",
                write: { editor.setDescription($0) }
            )
        }

        LabeledContent("Raises risk by") {
            HStack(spacing: 4) {
                DeferredTextField(
                    title: "0",
                    text: "\(editor.raisesRiskBy)",
                    width: 60,
                    identifier: "attack-tree-raises-risk-by",
                    write: { typed in
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

        sufficientSection(tree.sufficient)

        Divider()

        Button("Delete Tree", role: .destructive) { editor.deleteTree() }
            .accessibilityIdentifier("delete-attack-tree")
    }

    // MARK: the controls that are sufficient to close the whole route

    /// The controls the tree names as each sufficient to close the whole
    /// route, with what each is doing, a Remove beside each, and a menu of
    /// every control the model holds that the tree does not name yet.
    @ViewBuilder
    private func sufficientSection(_ sufficient: [TreeSelection.Sufficient]) -> some View {
        Text("Sufficient controls")
            .font(.subheadline.weight(.semibold))

        if sufficient.isEmpty {
            Text("No control is named as sufficient to close the whole route.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }

        ForEach(sufficient, id: \.description) { control in
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                VStack(alignment: .leading, spacing: 1) {
                    Text(control.description)
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(control.state)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 4)
                Button("Remove") { editor.removeSufficientControl(control.description) }
                    .font(.caption)
                    .accessibilityIdentifier("tree-sufficient-remove-\(control.description)")
            }
            .accessibilityIdentifier("tree-sufficient-\(control.description)")
        }

        let offered = controls.filter { description in
            sufficient.contains { $0.description == description } == false
        }
        if offered.isEmpty == false {
            Menu("Add a Sufficient Control") {
                ForEach(offered, id: \.self) { description in
                    Button(description) { editor.addSufficientControl(description) }
                }
            }
            .accessibilityIdentifier("tree-sufficient-add")
        }
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
        if let chain = node.chain {
            LabeledContent("Chain", value: chain)
                .accessibilityIdentifier("tree-selected-chain")
        }
        if let warning = node.warning {
            Label(warning, systemImage: "exclamationmark.triangle.fill")
                .font(.caption)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("tree-selected-warning")
        }

        // The goal carries no note: the grammar states no body for `goal`.
        if node.isJunction == false && node.isGoal == false {
            LabeledContent("Note") {
                DeferredTextField(
                    title: "Note",
                    text: node.note ?? "",
                    width: 200,
                    identifier: "tree-step-note",
                    write: { editor.setNote($0, for: node.id) }
                )
            }
        }

        if node.controls.isEmpty == false {
            Divider()
            controlsSection(node.controls)
        }

        if let sufficient = node.sufficient {
            Divider()
            sufficientSection(sufficient)
        }

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

    // MARK: the controls on the selected node's threat

    /// The controls the model offers on this step's threat, each with the
    /// four way status control the threat card draws. A step closes when one
    /// of these reads `implemented`, so this is where the route is answered
    /// without leaving the stage.
    @ViewBuilder
    private func controlsSection(_ controls: [AssessedControl]) -> some View {
        Text("Controls on this threat")
            .font(.subheadline.weight(.semibold))

        ForEach(controls, id: \.key) { control in
            VStack(alignment: .leading, spacing: 2) {
                Text(control.description)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                Picker("Status", selection: Binding(
                    get: { control.statusId },
                    set: { setStatus(of: control, to: $0) }
                )) {
                    ForEach(Self.statuses, id: \.0) { Text($0.1).tag($0.0) }
                }
                .labelsHidden()
                .frame(width: 160)
                .accessibilityIdentifier("tree-control-status-\(control.key)")
            }
            .accessibilityIdentifier("tree-control-\(control.key)")
        }
    }

    private static let statuses = [
        ("implemented", "Implemented"),
        ("not_implemented", "Not implemented"),
        ("not_applicable", "Not applicable"),
        ("accepted", "Accepted")
    ]

    // MARK: the selected join

    @ViewBuilder
    private func joinPanel(_ join: TreeSelection.Join) -> some View {
        Text("A join")
            .font(.subheadline.weight(.semibold))

        LabeledContent("From", value: join.from)
            .accessibilityIdentifier("tree-selected-join-from")
        LabeledContent("To", value: join.to)
            .accessibilityIdentifier("tree-selected-join-to")

        Divider()

        Button("Cut this Join") { editor.cut(join.edge) }
            .accessibilityIdentifier("tree-selection-cut-this-join")
        Button("Delete", role: .destructive) { gestures.deleteSelection() }
            .accessibilityIdentifier("tree-selection-delete")
    }

    // MARK: a box waiting for an element

    @ViewBuilder
    private func boxPanel(_ box: TreeSelection.Box) -> some View {
        Text(box.element == nil ? "A box" : "A filled box")
            .font(.subheadline.weight(.semibold))

        Text(TreeSelection.Box.notWritten)
            .font(.caption)
            .foregroundStyle(.orange)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityIdentifier("tree-box-not-written")

        if let element = box.element {
            LabeledContent("Element", value: element.name)
                .accessibilityIdentifier("tree-selected-element")

            if element.threats.isEmpty {
                Text("This element raises no threat, so it becomes no step.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Pick the threat this step reaches.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                ForEach(element.threats, id: \.threatKey) { threat in
                    Button(threat.name) { editor.pick(threat, for: box.id) }
                        .accessibilityIdentifier("tree-selection-pick-\(threat.threatKey)")
                }
            }

            Button("Pick another element") { editor.fill(box.id, with: nil) }
                .accessibilityIdentifier("tree-box-empty")
        } else {
            BoxSearch(box: box, elements: elements, editor: editor)
                // A new box starts a new search.
                .id(box.id)
        }

        Divider()

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

/// The search on a box: the elements the known end reaches, ranked by the
/// threats each raises, narrowed by what is typed.
private struct BoxSearch: View {
    let box: TreeSelection.Box
    let elements: [TreeElement]
    let editor: TreeEditor

    @State private var query = ""
    @State private var everyElement = false

    private var found: [TreeElement] {
        TreeConnectable.search(elements, from: box.anchor, query: query, everyElement: everyElement)
    }

    var body: some View {
        Text(scope)
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityIdentifier("tree-box-scope")

        TextField("Search elements", text: $query)
            .textFieldStyle(.roundedBorder)
            .accessibilityIdentifier("tree-box-search")

        if found.isEmpty {
            Text(query.isEmpty ? "No element to offer." : "No element matches \"\(query)\".")
                .font(.caption)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("tree-box-no-match")
            if everyElement == false, box.anchor != nil {
                Button("Show every element") { everyElement = true }
                    .accessibilityIdentifier("tree-box-every-element")
            }
        }

        ForEach(found) { element in
            Button {
                editor.fill(box.id, with: element)
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(element.name).font(.callout).lineLimit(1)
                        Text(element.kind).font(.caption2).foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 4)
                    Text("\(element.threats.count)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("tree-box-pick-\(element.payload)")
        }
    }

    private var scope: String {
        guard let knownEnd = box.knownEnd else {
            return "Every element. Join this box to a node to search what that node reaches."
        }
        return everyElement
            ? "Every element, with what an attacker at \(knownEnd) reaches first."
            : "The elements an attacker at \(knownEnd) reaches."
    }
}

/// What the right sidebar shows, as words a test reads.
enum TreeSelection: Equatable {
    struct Tree: Equatable {
        /// The bound score, or the refusal.
        let standing: String
        let isRefused: Bool
        /// The controls the file names as each sufficient to close the
        /// whole route, with what each is doing.
        var sufficient: [Sufficient] = []
    }

    /// One control named as sufficient to close the whole route, and what
    /// the assessment says about it.
    struct Sufficient: Equatable {
        let description: String
        let state: String

        /// What the panel says beside a sufficient control.
        static func says(_ state: SufficientControlState?) -> String {
            switch state {
            case .closes: "Closes the tree."
            case .open: "Open: not implemented."
            case .unevidenced: "Open: implemented with no evidence."
            case .unknown: "Unknown: no control has this description."
            case nil: "Not written yet."
            }
        }
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
        /// The step's place in its chain and its neighbours, as
        /// "Link 2 of 3, after Steal X, before Obtain Z.", or nil for a
        /// step outside every chain.
        var chain: String? = nil
        /// The join this step makes that no flow or zone supports, as
        /// "No flow or zone joins A to B.", or nil.
        var warning: String? = nil
        /// The tree's sufficient controls, on the goal; nil on every other
        /// node.
        var sufficient: [Sufficient]? = nil
        /// The controls the model offers on this node's threat, in the order
        /// the assessment gives them. Empty for a junction and for a step the
        /// assessment does not hold.
        var controls: [AssessedControl] = []
        /// The step's own note, or nil for a junction and for the goal: the
        /// grammar states no body for `goal`.
        var note: String? = nil
    }

    /// One selected box: the element it holds, if any, and the element at
    /// its known end, which the search reads.
    struct Box: Equatable {
        let id: String
        let element: TreeElement?
        /// The payload of the element at the known end, or nil while the
        /// box is joined to nothing.
        let anchor: String?
        /// The name of the element at the known end, or nil.
        let knownEnd: String?

        static let notWritten =
            "This box is not written. The tree is not saved until you pick an element, or delete the box."
    }

    /// One selected join, with the label of each end.
    struct Join: Equatable {
        let edge: TreeGraph.Edge
        let from: String
        let to: String
    }

    case noTree
    case tree(Tree)
    case node(Node)
    case pending(PendingElement)
    case box(Box)
    case join(Join)
    case several(Int)

    @MainActor
    static func of(
        editor: TreeEditor,
        canvas: TreeCanvasState,
        bound: BoundAttackTree?,
        elements: [TreeElement] = [],
        threats: [AssessedThreat] = []
    ) -> TreeSelection {
        guard editor.isEditing else { return .noTree }
        let selected = canvas.selectedIds
        guard canvas.selectionCount <= 1 else { return .several(canvas.selectionCount) }
        if let edge = canvas.selectedEdges.first {
            return .join(Join(
                edge: edge,
                from: editor.graph.node(edge.from)?.title ?? edge.from,
                to: editor.graph.node(edge.to)?.title ?? edge.to
            ))
        }
        guard let id = selected.first else {
            return .tree(Tree(
                standing: editor.refusal.map { "Not written: \($0)." } ?? written(editor: editor, bound: bound),
                isRefused: editor.refusal != nil,
                sufficient: sufficient(editor: editor, bound: bound)
            ))
        }
        if let pending = editor.pending.first(where: { $0.id == id }) {
            return .pending(pending)
        }
        guard let node = editor.graph.node(id) else { return .noTree }
        let isGoal = editor.graph.goalId == id
        let state = TreeStepState.state(of: node, in: bound)
        switch node.kind {
        case .step(_, let note):
            return .node(Node(
                id: id,
                threat: node.title,
                element: node.subtitle,
                score: TreeStepState.says(state),
                state: state,
                isGoal: isGoal,
                isJunction: false,
                canBecomeGoal: isGoal == false,
                feedsANode: editor.graph.edges.contains { $0.from == id },
                chain: isGoal ? nil : chain(of: id, in: editor.graph),
                warning: TreeConnectable.outsideJoin(from: id, in: editor.graph, elements: elements).map {
                    "No flow or zone joins \($0.from.name) to \($0.to.name)."
                },
                sufficient: isGoal ? sufficient(editor: editor, bound: bound) : nil,
                controls: controls(of: node, in: threats),
                note: isGoal ? nil : note
            ))
        case .placeholder(let element):
            let anchor = editor.graph.elementPayload(anchoring: id)
            return .box(Box(
                id: id,
                element: element,
                anchor: anchor,
                knownEnd: anchor.map { payload in
                    elements.first { $0.payload == payload }?.name ?? payload
                }
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

    /// The controls the model offers on one node's threat. A node the
    /// assessment no longer holds offers none.
    private static func controls(
        of node: TreeGraph.Node,
        in threats: [AssessedThreat]
    ) -> [AssessedControl] {
        guard case .step(let target, _) = node.kind else { return [] }
        let key = TreeDraft.key(of: target)
        return threats.first { $0.threatKey == key }?.controls ?? []
    }

    /// Where one step sits in its chain: its position, the link before it
    /// and the link after it. Nil for a step that is a chain of one.
    private static func chain(of id: String, in graph: TreeGraph) -> String? {
        let links = graph.chain(holding: id)
        guard links.count > 1, let at = links.firstIndex(of: id) else { return nil }
        var said = "Link \(at + 1) of \(links.count)"
        if at > 0 {
            said += ", after \(graph.node(links[at - 1])?.title ?? links[at - 1])"
        }
        if at < links.count - 1 {
            said += ", before \(graph.node(links[at + 1])?.title ?? links[at + 1])"
        }
        return said + "."
    }

    /// The controls the draft names as sufficient, each with what the
    /// assessment says about it, or "Not written yet." while the written
    /// tree does not name it.
    @MainActor
    private static func sufficient(editor: TreeEditor, bound: BoundAttackTree?) -> [Sufficient] {
        let scored = bound.flatMap { $0.id == editor.id ? $0 : nil }
        return editor.closedBy.map { description in
            Sufficient(
                description: description,
                state: Sufficient.says(
                    scored?.sufficientControls.first { $0.description == description }?.state
                )
            )
        }
    }

    /// What the assessment says about the written tree.
    @MainActor
    private static func written(editor: TreeEditor, bound: BoundAttackTree?) -> String {
        guard let scored = bound, scored.id == editor.id else {
            return "Written. The next assessment scores this tree."
        }
        if scored.isStale { return "Stale: a step names something this model no longer raises." }
        if let closedBy = scored.closedBy { return "Closed by \(closedBy): no score moves." }
        return scored.isOpen
            ? "Open: the goal's score moves \(scored.scoreBefore) \u{2192} \(scored.score)."
            : "Closed: every route is answered, and no score moves."
    }
}
