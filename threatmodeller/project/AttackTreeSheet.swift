import SwiftUI
import ThreatModelKit

/// Drawing an attack tree in the window.
///
/// The design in
/// `docs/superpowers/specs/2026-09-15-attack-tree-canvas-design.md` states the
/// shape: the trees on the left, a canvas in front, the elements beside it,
/// and every change that yields a valid tree written at once through a use
/// case, so a tree drawn here and one written by `threatmodeller format` are
/// the same file.
struct AttackTreeSheet: View {
    let project: ProjectSession
    /// The threats the model raises, so a goal and a step name one of them
    /// rather than a word a person typed.
    let threats: [AssessedThreat]
    /// The trees the model bound and scored, so the sheet states what each
    /// tree is worth while it is drawn.
    let bound: [BoundAttackTree]
    /// The elements the `.arch` file states, offered beside the canvas.
    let elements: [TreeElement]
    let dismiss: () -> Void

    /// The tree in front, or nil while none is chosen.
    @State private var chosen: String?
    /// What a person is drawing.
    @State private var graph = TreeGraph()
    @State private var pending: [PendingElement] = []
    @State private var meta = Meta()
    /// Why the graph is not a tree, or nil while it writes.
    @State private var refusal: String?
    /// The last tree written, so an unchanged graph writes nothing.
    @State private var lastWritten: SourceAttackTree?
    /// True once a tree is chosen or added, so the canvas has something to be.
    @State private var isEditing = false

    /// The attributes the tree states beside its shape.
    struct Meta: Equatable {
        var id: String
        var name: String
        var description: String
        var raisesRiskBy: Int

        init(id: String = "", name: String = "", description: String = "", raisesRiskBy: Int = 0) {
            self.id = id
            self.name = name
            self.description = description
            self.raisesRiskBy = raisesRiskBy
        }
    }

    private var trees: [SourceAttackTree] { project.attackTreeSources }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Attack trees")
                .font(.headline)

            Text(
                "A tree says how an attacker reaches one threat. Each step names a threat "
                    + "this model already raises."
            )
            .font(.caption)
            .foregroundStyle(.secondary)

            HStack(alignment: .top, spacing: 16) {
                list
                Divider()
                editor
            }
            .frame(minHeight: 380)

            if let message = project.errorMessage {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("attack-tree-error")
            }

            HStack {
                Button("Add Tree") { addTree() }
                    .disabled(threats.isEmpty)
                    .accessibilityIdentifier("add-attack-tree")

                Spacer()

                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("attack-trees-done")
            }
        }
        .padding(20)
        .frame(minWidth: 1000, minHeight: 600)
        .onAppear { chooseTheFirstTree() }
    }

    // MARK: the trees this system states

    private var list: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("This system's trees")
                .font(.subheadline.weight(.semibold))

            if trees.isEmpty {
                Text("This system states no tree.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("no-attack-trees")
            }

            List(trees, id: \.id, selection: $chosen) { tree in
                VStack(alignment: .leading, spacing: 2) {
                    Text(tree.displayName)
                        .font(.callout.weight(.semibold))
                    Text("Goal: \(tree.goal.threatId) on \(tree.goal.sourceId)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(said(of: tree))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .tag(tree.id)
                .accessibilityIdentifier("attack-tree-\(tree.id)")
            }
            .frame(width: 260)
            .onChange(of: chosen) { _, _ in openTheChosenTree() }
        }
    }

    /// What the assessment says about one tree, for the row under its name.
    private func said(of tree: SourceAttackTree) -> String {
        guard let scored = bound.first(where: { $0.id == tree.id }) else {
            return "This tree is not bound to the model."
        }
        if scored.isStale { return "Stale: a step names something this model no longer raises." }
        return scored.isOpen
            ? "Open: \(scored.scoreBefore) \u{2192} \(scored.score)"
            : "Closed: every route is answered."
    }

    // MARK: the tree in front

    @ViewBuilder
    private var editor: some View {
        if isEditing {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    TextField("Name", text: $meta.name)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityIdentifier("attack-tree-name")

                    Text("Raises risk by")
                        .font(.callout)
                    TextField("", value: $meta.raisesRiskBy, format: .number)
                        .frame(width: 60)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityIdentifier("attack-tree-raises-risk-by")
                    Text("per cent")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                TextField("Description", text: $meta.description)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("attack-tree-description")

                HStack(alignment: .top, spacing: 12) {
                    TreeCanvas(
                        graph: $graph,
                        pending: $pending,
                        elements: elements,
                        bound: bound.first { $0.id == meta.id }
                    )
                    elementList
                }

                Text(refusal.map { "Not written: \($0)." } ?? writtenLine)
                    .font(.caption)
                    .foregroundStyle(refusal == nil ? Color.secondary : .orange)
                    .accessibilityIdentifier("attack-tree-standing")

                Button("Delete Tree", role: .destructive) { delete() }
                    .accessibilityIdentifier("delete-attack-tree")
            }
            .onChange(of: graph) { _, _ in save() }
            .onChange(of: meta) { _, _ in save() }
        } else {
            Text("Pick a tree, or add one.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    /// What the assessment says about the written tree, under the canvas.
    private var writtenLine: String {
        guard let scored = bound.first(where: { $0.id == meta.id }) else {
            return "Written. The next assessment scores this tree."
        }
        if scored.isStale { return "Stale: a step names something this model no longer raises." }
        return scored.isOpen
            ? "Open: the goal's score moves \(scored.scoreBefore) \u{2192} \(scored.score)."
            : "Closed: every route is answered, and no score moves."
    }

    /// The elements the person drags from, with the two junctions above them.
    private var elementList: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("This system's elements")
                .font(.subheadline.weight(.semibold))
            Text("Drag one onto the canvas. A junction joins steps.")
                .font(.caption)
                .foregroundStyle(.secondary)

            List {
                Section {
                    Text("ALL OF").font(.caption.weight(.bold))
                        .draggable("junction:all")
                        .accessibilityIdentifier("tree-element-junction-all")
                    Text("ANY OF").font(.caption.weight(.bold))
                        .draggable("junction:any")
                        .accessibilityIdentifier("tree-element-junction-any")
                }
                Section {
                    ForEach(elements) { element in
                        HStack {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(element.name).font(.callout).lineLimit(1)
                                Text(element.kind).font(.caption2).foregroundStyle(.secondary)
                            }
                            Spacer(minLength: 4)
                            Text("\(element.threats.count)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .help("The threats this model raises here.")
                        }
                        .draggable(element.payload)
                        .accessibilityIdentifier("tree-element-\(element.payload)")
                    }
                }
            }
            .frame(width: 210)
        }
    }

    // MARK: what a person changes

    /// Writes the graph when it states a tree, or states the refusal. There
    /// is no Save button to forget: a valid change writes at once.
    private func save() {
        let result = graph.tree(
            id: meta.id,
            name: meta.name.isEmpty ? nil : meta.name,
            description: meta.description.isEmpty ? nil : meta.description,
            raisesRiskBy: meta.raisesRiskBy
        )
        switch result {
        case .success(let tree):
            refusal = nil
            guard tree != lastWritten else { return }
            lastWritten = tree
            project.saveAttackTree(tree)
            chosen = tree.id
        case .failure(let fault):
            refusal = fault.message
        }
    }

    private func chooseTheFirstTree() {
        guard chosen == nil else { return }
        chosen = trees.first?.id
        openTheChosenTree()
    }

    private func openTheChosenTree() {
        guard let chosen, let tree = trees.first(where: { $0.id == chosen }) else { return }
        meta = Meta(
            id: tree.id,
            name: tree.name ?? tree.id,
            description: tree.description ?? "",
            raisesRiskBy: tree.raisesRiskBy
        )
        graph = TreeGraph.graph(of: tree) { target in
            let key = TreeDraft.key(of: target)
            guard let threat = threats.first(where: { $0.threatKey == key }) else {
                return (target.threatId, "\(target.sourceKind) \(target.sourceId)")
            }
            return (threat.name, threat.source.displayName)
        }
        pending = []
        refusal = nil
        lastWritten = tree
        isEditing = true
    }

    private func addTree() {
        var number = trees.count + 1
        while trees.contains(where: { $0.id == "tree-\(number)" }) { number += 1 }
        meta = Meta(id: "tree-\(number)", name: "A new tree")
        graph = TreeGraph()
        pending = []
        refusal = TreeGraph.Refusal.noGoal.message
        lastWritten = nil
        chosen = nil
        isEditing = true
    }

    private func delete() {
        project.deleteAttackTree(meta.id)
        graph = TreeGraph()
        pending = []
        lastWritten = nil
        chosen = nil
        isEditing = false
    }
}

/// What a person is writing, before it becomes a tree in the file.
///
/// A threat is chosen by its key — `<threat id>@<source id>` — because that is
/// what the assessment hands out, and a step naming anything else binds to
/// nothing.
struct TreeDraft: Equatable {
    struct Step: Equatable {
        var key: String
        var note: String?
    }

    var id: String
    var name: String
    var description: String
    var raisesRiskBy: Int
    var goalKey: String
    var steps: [Step]

    init(
        id: String,
        name: String,
        description: String,
        raisesRiskBy: Int,
        goalKey: String,
        steps: [Step]
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.raisesRiskBy = raisesRiskBy
        self.goalKey = goalKey
        self.steps = steps
    }

    init(_ tree: SourceAttackTree) {
        id = tree.id
        name = tree.name ?? tree.id
        description = tree.description ?? ""
        raisesRiskBy = tree.raisesRiskBy
        goalKey = Self.key(of: tree.goal)
        steps = tree.steps.map { Step(key: Self.key(of: $0.target), note: $0.note) }
    }

    /// The tree this draft states, or nil when it states no step: a tree body
    /// holds exactly one root, and a root of nothing is not a tree.
    func source() -> SourceAttackTree? {
        guard let goal = Self.target(of: goalKey), steps.isEmpty == false else { return nil }
        let written = steps.compactMap { step -> SourceTreeNode? in
            guard let target = Self.target(of: step.key) else { return nil }
            return .step(SourceTreeStep(target: target, note: step.note))
        }
        guard written.isEmpty == false else { return nil }

        return SourceAttackTree(
            id: id,
            name: name.isEmpty ? nil : name,
            description: description.isEmpty ? nil : description,
            raisesRiskBy: raisesRiskBy,
            goal: goal,
            root: .all(written)
        )
    }

    /// The key the assessment hands out for one target.
    static func key(of target: SourceTreeTarget) -> String {
        "\(target.threatId)@\(target.sourceKind == "flow" ? "connection" : target.sourceKind):"
            + target.sourceId
    }

    /// The target one key names, or nil for a key this cannot read.
    static func target(of key: String) -> SourceTreeTarget? {
        let parts = key.split(separator: "@", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { return nil }
        let source = parts[1].split(separator: ":", maxSplits: 1).map(String.init)
        guard source.count == 2 else { return nil }
        return SourceTreeTarget(
            threatId: parts[0],
            sourceKind: source[0] == "connection" ? "flow" : source[0],
            sourceId: source[1]
        )
    }
}
