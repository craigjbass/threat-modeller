import SwiftUI
import ThreatModelKit

/// Writing an attack tree in the window.
///
/// The design in
/// `docs/superpowers/specs/2026-09-15-attack-tree-editor-design.md` states the
/// shape: the trees on the left, the tree in front on the right, and every
/// change written through a use case so a tree written here and one written
/// by `threatmodeller format` are the same file.
struct AttackTreeSheet: View {
    let project: ProjectSession
    /// The threats the model raises, so a goal and a step name one of them
    /// rather than a word a person typed.
    let threats: [AssessedThreat]
    /// The trees the model bound and scored, so the sheet states what each
    /// tree is worth while it is written.
    let bound: [BoundAttackTree]
    let dismiss: () -> Void

    /// The tree in front, or nil while none is chosen.
    @State private var chosen: String?
    /// What a person is writing, before it is written to the file.
    @State private var draft: TreeDraft?

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
        .frame(minWidth: 760, minHeight: 520)
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
        if let draft {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    TextField("Name", text: name(of: draft))
                        .textFieldStyle(.roundedBorder)
                        .accessibilityIdentifier("attack-tree-name")

                    TextField("Description", text: description(of: draft), axis: .vertical)
                        .lineLimit(2 ... 4)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityIdentifier("attack-tree-description")

                    HStack {
                        Text("Raises risk by")
                        TextField("", value: raisesRiskBy(of: draft), format: .number)
                            .frame(width: 60)
                            .textFieldStyle(.roundedBorder)
                            .accessibilityIdentifier("attack-tree-raises-risk-by")
                        Text("per cent")
                            .foregroundStyle(.secondary)
                    }
                    .font(.callout)

                    Picker("Goal", selection: goal(of: draft)) {
                        ForEach(threats, id: \.threatKey) { threat in
                            Text("\(threat.name) on \(threat.source.displayName)")
                                .tag(threat.threatKey)
                        }
                    }
                    .accessibilityIdentifier("attack-tree-goal")

                    Divider()

                    Text("Steps")
                        .font(.subheadline.weight(.semibold))
                    Text("Every step is open at once, so a route needs all of them.")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    ForEach(Array(draft.steps.enumerated()), id: \.offset) { index, step in
                        HStack {
                            Picker("", selection: stepKey(of: draft, at: index)) {
                                ForEach(threats, id: \.threatKey) { threat in
                                    Text("\(threat.name) on \(threat.source.displayName)")
                                        .tag(threat.threatKey)
                                }
                            }
                            .labelsHidden()

                            Button {
                                remove(stepAt: index)
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                            .accessibilityIdentifier("remove-step-\(index)")
                        }
                        .accessibilityIdentifier("attack-tree-step-\(index)")
                        Text(step.note ?? "")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }

                    Button("Add Step") { addStep() }
                        .disabled(threats.isEmpty)
                        .accessibilityIdentifier("add-attack-tree-step")

                    Divider()

                    HStack {
                        Button("Save Tree") { save() }
                            .disabled(draft.steps.isEmpty)
                            .accessibilityIdentifier("save-attack-tree")

                        Button("Delete Tree", role: .destructive) { delete() }
                            .accessibilityIdentifier("delete-attack-tree")
                    }
                }
                .padding(.trailing, 4)
            }
        } else {
            Text("Pick a tree, or add one.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    // MARK: what a person changes

    private func name(of draft: TreeDraft) -> Binding<String> {
        Binding(get: { draft.name }, set: { self.draft?.name = $0 })
    }

    private func description(of draft: TreeDraft) -> Binding<String> {
        Binding(get: { draft.description }, set: { self.draft?.description = $0 })
    }

    private func raisesRiskBy(of draft: TreeDraft) -> Binding<Int> {
        Binding(get: { draft.raisesRiskBy }, set: { self.draft?.raisesRiskBy = $0 })
    }

    private func goal(of draft: TreeDraft) -> Binding<String> {
        Binding(get: { draft.goalKey }, set: { self.draft?.goalKey = $0 })
    }

    private func stepKey(of draft: TreeDraft, at index: Int) -> Binding<String> {
        Binding(
            get: { index < draft.steps.count ? draft.steps[index].key : "" },
            set: { key in
                guard index < (self.draft?.steps.count ?? 0) else { return }
                self.draft?.steps[index].key = key
            }
        )
    }

    private func chooseTheFirstTree() {
        guard chosen == nil else { return }
        chosen = trees.first?.id
        openTheChosenTree()
    }

    private func openTheChosenTree() {
        guard let chosen, let tree = trees.first(where: { $0.id == chosen }) else {
            draft = nil
            return
        }
        draft = TreeDraft(tree)
    }

    private func addTree() {
        guard let first = threats.first else { return }
        let draft = TreeDraft(
            id: "tree-\(trees.count + 1)",
            name: "A new tree",
            description: "",
            raisesRiskBy: 0,
            goalKey: first.threatKey,
            steps: [TreeDraft.Step(key: first.threatKey, note: nil)]
        )
        self.draft = draft
        chosen = draft.id
    }

    private func addStep() {
        guard let first = threats.first else { return }
        draft?.steps.append(TreeDraft.Step(key: first.threatKey, note: nil))
    }

    private func remove(stepAt index: Int) {
        guard index < (draft?.steps.count ?? 0) else { return }
        draft?.steps.remove(at: index)
    }

    private func save() {
        guard let draft, let tree = draft.source() else { return }
        project.saveAttackTree(tree)
        chosen = tree.id
    }

    private func delete() {
        guard let draft else { return }
        project.deleteAttackTree(draft.id)
        self.draft = nil
        chosen = nil
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
