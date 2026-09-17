import SwiftUI
import ThreatModelKit

/// The left sidebar of the Attack Trees stage: the trees this system states,
/// and the elements a person drops on one.
///
/// The design in
/// `docs/superpowers/specs/2026-09-16-attack-tree-stage-design.md` states the
/// two lists. Picking a tree opens it on the canvas. A drag from the element
/// list lands on the canvas at the pointer.
struct TreeSidebar: View {
    let project: ProjectSession
    /// The model in front, for the names a node shows. A write reads the
    /// project again, so this changes after every change.
    let session: ThreatModelSession
    let editor: TreeEditor
    let canvas: TreeCanvasState
    /// The elements the `.arch` file states, with the threats raised on each.
    let elements: [TreeElement]
    /// The trees the model bound and scored.
    let bound: [BoundAttackTree]

    private var trees: [SourceAttackTree] { project.attackTreeSources }

    /// The tree in front, as the list's selection. Picking a row opens that
    /// tree; a new tree not yet written selects no row.
    private var chosen: Binding<String?> {
        Binding(
            get: { editor.isEditing ? editor.id : nil },
            set: { id in
                guard let id, id != editor.id, let tree = trees.first(where: { $0.id == id }) else { return }
                open(tree)
            }
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            treeList
            Divider()
            elementList
        }
        .onAppear { chooseTheFirstTree() }
        // Choosing another system closes the tree in front.
        .onChange(of: project.chosenSystem) { _, _ in
            editor.close()
            canvas.clearSelection()
            chooseTheFirstTree()
        }
        .accessibilityIdentifier("tree-sidebar")
    }

    // MARK: the trees this system states

    private var treeList: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("This system's trees")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Button("Add Tree") { addTree() }
                    .controlSize(.small)
                    .disabled(session.threats.isEmpty)
                    .accessibilityIdentifier("add-attack-tree")
            }
            .padding(.horizontal, 12)
            .padding(.top, 10)

            catalogueDriftNotice

            if trees.isEmpty {
                Text("This system states no tree.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 12)
                    .accessibilityIdentifier("no-attack-trees")
            }

            List(trees, id: \.id, selection: chosen) { tree in
                VStack(alignment: .leading, spacing: 2) {
                    Text(tree.displayName)
                        .font(.callout.weight(.semibold))
                    Text("Goal: \(tree.goal.threatId) on \(tree.goal.sourceId)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(TreeStanding.says(about: tree.id, in: bound))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .tag(tree.id)
                .accessibilityIdentifier("attack-tree-\(tree.id)")
            }
            .frame(minHeight: 120)
        }
    }

    /// What the `.attacktree` file states about the catalogue against what
    /// is in use, and the control that takes the tag in use. The same
    /// notice the architecture stage offers for the `.arch` file, for the
    /// tree file's own tag.
    @ViewBuilder
    private var catalogueDriftNotice: some View {
        if let drift = project.attackTreeCatalogueDrift {
            VStack(alignment: .leading, spacing: 4) {
                Text(drift.says)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Take \(drift.inUse)") { project.takeAttackTreeCatalogueInUse() }
                    .font(.caption)
                    .controlSize(.small)
                    .accessibilityIdentifier("take-attack-tree-catalogue-in-use")
            }
            .padding(.horizontal, 12)
            .padding(.top, 6)
            .accessibilityIdentifier("attack-tree-catalogue-drift-notice")
        }
    }

    // MARK: the elements a person drops

    /// The rows, ranked for the one selected node: what its element reaches
    /// first and marked, the rest dimmed and still draggable.
    private var rows: [RankedElement] {
        TreeConnectable.sidebarRows(editor: editor, canvas: canvas, elements: elements)
    }

    /// The name of the element the selected node is on, or nil.
    private var anchorName: String? {
        guard let anchor = TreeConnectable.anchor(editor: editor, canvas: canvas) else { return nil }
        return elements.first { $0.payload == anchor }?.name ?? anchor
    }

    private var elementList: some View {
        let rows = rows
        let isRanked = rows.contains { $0.isConnectable }
        return VStack(alignment: .leading, spacing: 6) {
            Text("This system's elements")
                .font(.subheadline.weight(.semibold))
                .padding(.horizontal, 12)
                .padding(.top, 10)
            Text(
                anchorName.map { "Marked: what an attacker at \($0) reaches." }
                    ?? "Drag one onto the canvas. A junction joins steps."
            )
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 12)
                .accessibilityIdentifier("tree-elements-caption")

            List {
                Section {
                    Text("ALL OF").font(.caption.weight(.bold))
                        .draggable("junction:all")
                        .accessibilityIdentifier("tree-element-junction-all")
                    Text("ANY OF").font(.caption.weight(.bold))
                        .draggable("junction:any")
                        .accessibilityIdentifier("tree-element-junction-any")
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Any element").font(.caption.weight(.bold))
                        Text("A box: join it, then search for the element.")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    .draggable(TreeElement.boxPayload)
                    .accessibilityIdentifier("tree-element-placeholder")
                }
                Section {
                    ForEach(rows) { row in
                        TreeElementRow(row: row, isRanked: isRanked)
                            .draggable(row.element.payload)
                            .accessibilityIdentifier("tree-element-\(row.element.payload)")
                    }
                }
            }
        }
    }

    // MARK: what a person does

    private func chooseTheFirstTree() {
        guard editor.isEditing == false, let first = trees.first else { return }
        open(first)
    }

    private func open(_ tree: SourceAttackTree) {
        editor.open(tree, threats: session.threats)
        canvas.clearSelection()
    }

    private func addTree() {
        editor.addTree(among: trees)
        canvas.clearSelection()
    }
}

/// One element row of the sidebar. While a node is selected, a row the
/// node's element reaches carries a check mark, and every other row is
/// dimmed and still draggable.
struct TreeElementRow: View {
    let row: RankedElement
    /// True while a node is selected, so the rows are marked or dimmed.
    let isRanked: Bool

    var body: some View {
        HStack {
            if isRanked {
                Image(systemName: row.isConnectable ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(row.isConnectable ? Color.accentColor : Color.secondary.opacity(0.4))
                    .help(row.isConnectable
                        ? "A flow or a zone joins this element to the selected node's element."
                        : "No flow or zone joins this element to the selected node's element.")
                    .accessibilityIdentifier(row.isConnectable ? "tree-element-connectable" : "tree-element-outside")
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(row.element.name).font(.callout).lineLimit(1)
                Text(row.element.kind).font(.caption2).foregroundStyle(.secondary)
            }
            Spacer(minLength: 4)
            Text("\(row.element.threats.count)")
                .font(.caption)
                .foregroundStyle(.secondary)
                .help("The threats this model raises here.")
        }
        .opacity(isRanked && row.isConnectable == false ? 0.5 : 1)
    }
}

/// What the assessment says about one tree, for the row under its name and
/// the line beside the canvas.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated enum TreeStanding {
    static func says(about treeId: String, in bound: [BoundAttackTree]) -> String {
        guard let scored = bound.first(where: { $0.id == treeId }) else {
            return "This tree is not bound to the model."
        }
        if scored.isStale { return "Stale: a step names something this model no longer raises." }
        return scored.isOpen
            ? "Open: \(scored.scoreBefore) \u{2192} \(scored.score)"
            : "Closed: every route is answered."
    }
}
