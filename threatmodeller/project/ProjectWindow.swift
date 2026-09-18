import SwiftUI
import ThreatModelKit

/// A project root, drawn.
///
/// The three columns are the ones a document window uses. What this window adds
/// is the systems picker, the save that writes text back, and the diagnostics.
struct ProjectWindow: View {
    let session: ProjectSession

    @State private var isShowingDiagnostics = false
    /// True while the question about downloading ATT&CK is on screen.
    @State private var isAskingAboutAttack = false
    @State private var isShowingLibraries = false
    /// True while the planned-work list is on screen.
    @State private var isShowingPlannedWork = false
    @State private var isShowingHistory = false
    /// True while the check summary is on screen.
    @State private var isShowingCheckSummary = false
    /// True while the Terraform import result is on screen.
    @State private var isShowingTerraformImport = false
    @State private var canvas = CanvasState()
    /// The tree in front on the Attack Trees stage, and its canvas. The
    /// window owns them, so the tree survives a change of stage.
    @State private var trees = TreeEditor()
    @State private var treeCanvas = TreeCanvasState()
    /// The stage of the work the window draws.
    @State private var stage: WorkStage = .architecture
    /// The name the user gives a system they start with nothing in it.
    @State private var newSystemName = ""

    var body: some View {
        // The chrome is a row above the columns, not an inset over them.
        // `safeAreaInset` does not inset a `NavigationSplitView` on macOS: the
        // columns keep the whole window, so a bar drawn that way covered the
        // top of the palette and of the threat sidebar, and no scroll brought
        // that top back into view.
        VStack(spacing: 0) {
            chrome

            Group {
                // The layout preview wins over the canvas: while the
                // search runs, the window draws the diagram re-routing, and
                // Lay Out on an open system draws it too.
                if let preview = session.layoutPreview {
                    layoutPreview(preview)
                // A drawn model wins over a stage. The stage is what the
                // window has instead of a diagram, never instead of one: a
                // stage left behind must not be able to hide the diagram.
                } else if let model = session.model {
                    ProjectColumns(
                        project: session,
                        session: model,
                        canvas: canvas,
                        stage: $stage,
                        trees: trees,
                        treeCanvas: treeCanvas
                    )
                        .focusedSceneValue(\.threatModelSession, model)
                        .focusedSceneValue(\.threatModelCanvas, canvas)
                        .focusedSceneValue(\.projectSession, session)
                        // The Edit menu's Undo and the View menu's zoom act
                        // on the tree while the tree is in front.
                        .focusedSceneValue(\.treeEditor, stage == .attackTrees ? trees : nil)
                        .focusedSceneValue(\.treeCanvas, stage == .attackTrees ? treeCanvas : nil)
                        // A context menu on the diagram takes a person to the
                        // threats of what they clicked.
                        .onAppear {
                            canvas.showStage = { stage = $0 }
                            // What lays a narrowed diagram out. The canvas
                            // calls it from the four narrowing verbs.
                            canvas.layouts = model
                            trees.project = session
                        }
                } else if let loading = session.loading {
                    loadingNotice(loading)
                } else if session.canInitialise {
                    emptyProject
                } else {
                    ContentUnavailableView(
                        session.root == nil ? "No project is open" : "Nothing is drawn",
                        systemImage: "folder",
                        description: Text(
                            session.errorMessage ?? "Open a project with File \u{25B8} Open Project."
                        )
                    )
                }
            }
        }
        .alert("Synchronise MITRE ATT&CK", isPresented: $isAskingAboutAttack) {
            Button("Download") {
                isAskingAboutAttack = false
                Task { await session.synchroniseAttack() }
            }
            Button("Cancel", role: .cancel) { isAskingAboutAttack = false }
        } message: {
            Text(session.attackSynchroniseQuestion)
        }
        .sheet(isPresented: $isShowingDiagnostics) {
            DiagnosticsSheet(
                fileName: session.diagnosticsFileName
                    ?? (session.policyRules.isEmpty ? "" : "policy.hcl"),
                diagnostics: session.diagnostics,
                dismiss: { isShowingDiagnostics = false },
                path: session.diagnosticsPath,
                policyRules: session.policyRules
            )
        }
        .sheet(isPresented: $isShowingCheckSummary) {
            CheckSummarySheet(
                systems: session.checkedSystems,
                dismiss: { isShowingCheckSummary = false }
            )
        }
        .sheet(isPresented: $isShowingTerraformImport) {
            if let result = session.terraformImportResult {
                TerraformImportSheet(
                    result: result,
                    dismiss: {
                        isShowingTerraformImport = false
                        session.dismissTerraformImportResult()
                    }
                )
            } else {
                NothingToShowSheet(
                    says: "The Terraform import result has gone.",
                    dismiss: { isShowingTerraformImport = false }
                )
            }
        }
        .sheet(isPresented: $isShowingHistory) {
            // The window's own history, so a sampling done here shows on the
            // Report stage and a sampling done there shows here.
            if let history = session.history {
                HistorySheet(
                    session: history,
                    dismiss: { isShowingHistory = false }
                )
            } else {
                NothingToShowSheet(
                    says: "This window has no history to read. Open a project first.",
                    dismiss: { isShowingHistory = false }
                )
            }
        }
        .sheet(item: systemSheet) { kind in
            if let model = session.model {
                SystemSheetView(
                    kind: kind,
                    session: model,
                    dismiss: { session.systemSheet = nil }
                )
            } else {
                NothingToShowSheet(
                    says: "No system is drawn, so there is no \(kind.title) to read.",
                    dismiss: { session.systemSheet = nil }
                )
            }
        }
        .sheet(isPresented: $isShowingPlannedWork) {
            if let model = session.model {
                PlannedWorkSheet(
                    project: session,
                    threats: model.threats,
                    dismiss: { isShowingPlannedWork = false }
                )
            } else {
                NothingToShowSheet(
                    says: "No system is drawn, so there is no planned work to read.",
                    dismiss: { isShowingPlannedWork = false }
                )
            }
        }
        .sheet(isPresented: $isShowingLibraries) {
            if let root = session.root {
                LibrariesSheet(
                    // A change reloads the project, so the palette shows a
                    // library that has just arrived.
                    session: LibrarySession(
                        useCases: session.useCases,
                        root: root,
                        onChange: { session.reload() },
                        fetcher: session.useCases.fetcher
                    ),
                    dismiss: { isShowingLibraries = false }
                )
            } else {
                NothingToShowSheet(
                    says: "No project is open, so there are no libraries to read.",
                    dismiss: { isShowingLibraries = false }
                )
            }
        }
        .onChange(of: session.diagnostics.count) {
            // Errors stop the picture, so they interrupt. Warnings sit in the
            // strip until the user asks for them.
            if session.hasErrors { isShowingDiagnostics = true }
        }
        .onChange(of: session.terraformImportResult) {
            if session.terraformImportResult != nil { isShowingTerraformImport = true }
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Picker("System", selection: chosen) {
                    ForEach(session.systems, id: \.self) { name in
                        systemRow(name).tag(name as String?)
                    }
                }
                .labelsHidden()
                .frame(minWidth: 160)
                .disabled(session.systems.isEmpty)
                .accessibilityIdentifier("system-picker")
            }

            // Declared before Libraries, so it sits to the left of it. A load
            // stage and a save message never show at once: a load is what is
            // happening now, and a message is what happened.
            ToolbarItem {
                if let stage = session.loading {
                    HStack(spacing: 8) {
                        Text(stage.says)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                        ProgressView()
                            .controlSize(.small)
                    }
                    // Clear of the system picker to its left.
                    .padding(.leading, 16)
                    .accessibilityIdentifier("loading-bar")
                } else if let message = session.toolbarMessage {
                    HStack(spacing: 8) {
                        Text(message)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .accessibilityIdentifier("last-action-message")

                        // A report a person cannot open is a path they have to
                        // read off the screen and find by hand.
                        if session.canOpenReport {
                            Button("Open") { session.openLastReport() }
                                .accessibilityIdentifier("open-report")
                            Button("Reveal in Finder") { session.revealLastReport() }
                                .accessibilityIdentifier("reveal-report")
                        }
                    }
                    .padding(.leading, 16)
                }
            }

            // The one control that states the answer `threatmodeller check`
            // gives: pass, or fail with a count. The sheet lists every
            // finding in the words the verb prints.
            ToolbarItem {
                Button {
                    isShowingCheckSummary = true
                } label: {
                    HStack(spacing: 4) {
                        Image(
                            systemName: session.passesCheck
                                ? "checkmark.seal.fill"
                                : "xmark.seal.fill"
                        )
                        .foregroundStyle(session.passesCheck ? Color.green : Color.red)
                        if session.checkFailureCount > 0 {
                            Text("\(session.checkFailureCount)")
                        }
                    }
                }
                .disabled(session.checkedSystems.isEmpty)
                .help("What threatmodeller check says about this project.")
                .accessibilityIdentifier("check-summary")
            }

            // The one control that reads the disk again outside the
            // files-changed notice, for a person who wants a reload for any
            // other reason: an editor outside auto sync, a git checkout, a
            // change to a file this application does not watch.
            ToolbarItem {
                Button("Reload", systemImage: "arrow.clockwise") {
                    session.reload(keepingSelectionIn: canvas)
                }
                .disabled(session.root == nil)
                .help("Read the project's files again.")
                .accessibilityIdentifier("reload-project")
            }

            ToolbarItem {
                // Reading the history compiles the model once per sampled
                // commit, so it is read when a person asks and never on open.
                Button("History", systemImage: "chart.line.uptrend.xyaxis") {
                    isShowingHistory = true
                }
                // The neighbours carry the same guard. Without it this
                // control opened a sheet with no history in it.
                .disabled(session.history == nil)
                .accessibilityIdentifier("show-history")
            }

            // What the system states about itself: one item per sheet, with
            // the count the model holds beside each. The menu bar draws the
            // same rows under System.
            ToolbarItem {
                Menu {
                    ElementMenuView(rows: Self.systemRows(project: session))
                } label: {
                    Label("System", systemImage: "list.bullet.rectangle")
                }
                .disabled(session.model == nil)
                .help("What this system states about itself, one sheet at a time.")
                .accessibilityIdentifier("system-menu")
            }

            ToolbarItem {
                Button("Planned Work", systemImage: "checklist") {
                    isShowingPlannedWork = true
                }
                .disabled(session.model == nil)
                .help("Who does each recommendation and each action, and by when.")
                .accessibilityIdentifier("planned-work")
            }

            ToolbarItem {
                Button("Libraries", systemImage: "books.vertical") {
                    isShowingLibraries = true
                }
                .disabled(session.root == nil)
                .accessibilityIdentifier("libraries")
            }

            // The one control in this window that reaches a network, and it
            // asks before it starts.
            ToolbarItem {
                Button("Synchronise ATT&CK", systemImage: "arrow.down.circle") {
                    isAskingAboutAttack = true
                }
                .disabled(session.root == nil)
                .accessibilityIdentifier("synchronise-attack")
            }

            settingItems
        }
    }

    /// The System menu rows this toolbar control draws. The menu bar draws
    /// the same value, so the two entry points cannot drift.
    static func systemRows(project: ProjectSession) -> [ElementMenu.Row] {
        SystemMenu(project: project).rows
    }

    /// Which System sheet is on screen. The session holds it, so a test runs
    /// a menu row and reads which sheet opened.
    private var systemSheet: Binding<SystemSheetKind?> {
        Binding(
            get: { session.systemSheet },
            set: { session.systemSheet = $0 }
        )
    }

    /// What a load is doing. Opening a large model takes long enough that a
    /// still window reads as a broken one, so the window says the stage it is
    /// in and, when it is opening the project, which step that is of the four.
    private func loadingNotice(_ stage: ProjectSession.LoadingStage) -> some View {
        VStack(spacing: 14) {
            ProgressView()
                .controlSize(.large)

            Text(stage.says)
                .font(.title3)

            Text(stepOf(stage))
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityIdentifier("loading")
    }

    /// The diagram the layout search is drawing, with the stage under it.
    ///
    /// The canvas fits the whole diagram when it takes over, so the picture
    /// does not move at the hand-over.
    private func layoutPreview(
        _ preview: (subject: LayoutSubject, layout: LayOutModelResponse)
    ) -> some View {
        VStack(spacing: 14) {
            FormingPicture(subject: preview.subject, layout: preview.layout)
                .frame(maxWidth: .infinity, maxHeight: .infinity)

            if let stage = session.loading {
                Text(stage.says)
                    .font(.title3)

                Text(stepOf(stage))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear { canvas.fitsOnNextAppearance = true }
    }

    /// A directory with nothing in it. Rather than an empty window, this
    /// application offers to write an example the user can read and change.
    private var emptyProject: some View {
        VStack(spacing: 14) {
            Image(systemName: "folder.badge.plus")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)

            Text("This project holds no systems")
                .font(.title3.bold())

            Text(
                "A project keeps its systems in a threatmodel directory: "
                    + "one .arch file for the architecture, and a .controls file beside it. "
                    + "Name a system to start with nothing in it, or start from an example."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .frame(maxWidth: 420)

            emptyStart

            Text("Or start from an example")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)

            VStack(spacing: 8) {
                ForEach(session.examples, id: \.id) { example in
                    Button {
                        session.startWriting(.example(id: example.id))
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(example.name)
                            Text(example.description)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.leading)
                        }
                        .frame(maxWidth: 420, alignment: .leading)
                        .contentShape(Rectangle())
                    }
                    .accessibilityIdentifier("initialise-\(example.id)")
                }
            }

            if let root = session.root {
                Text("It will be written to \(root)/threatmodel.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityIdentifier("empty-project")
        // The field starts on the folder's own name, which is usually what
        // the system is called.
        .onAppear { if newSystemName.isEmpty { newSystemName = session.suggestedSystemName } }
    }

    /// Name a system and start with nothing in it.
    private var emptyStart: some View {
        HStack(spacing: 8) {
            TextField("System name", text: $newSystemName)
                .textFieldStyle(.roundedBorder)
                .frame(width: 260)
                .onSubmit { createEmptySystem() }
                .accessibilityIdentifier("new-system-name")

            Button("Create", action: createEmptySystem)
                .buttonStyle(.borderedProminent)
                .disabled(newSystemName.trimmingCharacters(in: .whitespaces).isEmpty)
                .accessibilityIdentifier("initialise-empty")
        }
    }

    private func createEmptySystem() {
        session.startWriting(.empty(systemName: newSystemName))
    }

    private var autoSync: Binding<Bool> {
        Binding(
            get: { session.isAutoSyncOn },
            set: { session.isAutoSyncOn = $0 }
        )
    }

    private var pointerMode: Binding<PointerMode> {
        Binding(
            get: { session.pointerMode },
            set: { session.pointerMode = $0 }
        )
    }

    /// The two settings of the window: what Auto Sync writes, and which
    /// pointing device drives both canvases. Neither is a verb, so they sit
    /// here rather than on the floating panel.
    @ToolbarContentBuilder
    private var settingItems: some ToolbarContent {
        ToolbarItem { settingsRow }
    }

    /// The two settings drawn in one row, so the gap between them is one
    /// view's own spacing and not the toolbar's item spacing.
    ///
    /// The checkbox toggle draws no trailing inset of its own, so two
    /// separate `ToolbarItem`s left the gap to the toolbar's own spacing
    /// between items, which is not guaranteed for a control with no bezel.
    /// One `ToolbarItem` holding both controls in an `HStack` uses
    /// SwiftUI's own default spacing between two views instead, which is
    /// the same on every macOS version this application supports.
    var settingsRow: some View {
        HStack {
            autoSyncToggle
            pointerModePicker
        }
    }

    var autoSyncToggle: some View {
        Toggle("Auto Sync", isOn: autoSync)
            .toggleStyle(.checkbox)
            .help(
                "Save the .arch and .controls files when you change "
                    + "the model, and redraw the diagram when those "
                    + "files change on disk."
            )
            .accessibilityIdentifier("auto-sync")
    }

    /// Which pointing device drives both canvases.
    var pointerModePicker: some View {
        Picker("Pointer", selection: pointerMode) {
            ForEach(PointerMode.allCases) { mode in
                Text(mode.name).tag(mode)
            }
        }
        .pickerStyle(.menu)
        .help(
            "Trackpad: two finger scroll pans and pinch zooms. "
                + "Mouse: the wheel zooms, Shift-wheel pans sideways, "
                + "and a middle-button drag or a Space-drag pans."
        )
        .accessibilityIdentifier("pointer-mode")
    }

    private var chrome: some View {
        VStack(spacing: 0) {
            filesChangedNotice
            catalogueDriftNotice
            diagnosticsNotice
        }
    }

    private func stepOf(_ stage: ProjectSession.LoadingStage) -> String {
        // A synchronise is not a step of opening the project.
        let stages = ProjectSession.LoadingStage.openingStages
        guard let index = stages.firstIndex(of: stage) else {
            return "The window says here when it finishes or fails."
        }
        return "Step \(index + 1) of \(stages.count)"
    }

    /// A file changed on disk and this application did not redraw, because
    /// auto sync is off or something on screen is unsaved. The user picks.
    @ViewBuilder
    private var filesChangedNotice: some View {
        if session.hasFilesChangedOnDisk {
            HStack(spacing: 8) {
                Image(systemName: "arrow.triangle.2.circlepath")
                Text(filesChangedText)
                    .font(.callout)
                Spacer(minLength: 8)
                Button("Reload") { session.reload() }
                    .accessibilityIdentifier("reload-from-disk")
                Button(session.hasUnsavedChanges ? "Keep Mine" : "Dismiss") { session.keepMine() }
                    .accessibilityIdentifier("keep-mine")
            }
            .padding(8)
            .background(Color.blue.opacity(0.18))
            .accessibilityIdentifier("files-changed-notice")
        }
    }

    private var filesChangedText: String {
        session.hasUnsavedChanges
            ? "The files changed on disk. Your unsaved changes are still on screen."
            : "The files changed on disk. Auto Sync is off."
    }

    /// What the file states about the catalogue against what is in use, and
    /// the two things a person can do about it.
    @ViewBuilder
    private var catalogueDriftNotice: some View {
        if let drift = session.catalogueDrift {
            HStack(spacing: 8) {
                Image(systemName: "clock.arrow.circlepath")
                Text(drift.says)
                    .font(.callout)
                Spacer(minLength: 8)
                Button("Take \(drift.inUse)") { session.takeTheCatalogueInUse() }
                    .accessibilityIdentifier("take-catalogue-in-use")
                Button("Keep \(drift.stated)") { session.keepTheStatedCatalogue() }
                    .accessibilityIdentifier("keep-stated-catalogue")
            }
            .padding(8)
            .background(Color.yellow.opacity(0.25))
            .accessibilityIdentifier("catalogue-drift-notice")
        }
    }

    @ViewBuilder
    private var diagnosticsNotice: some View {
        // A breached policy rule raises the notice the way an error does: the
        // check fails the build for it, and the window must not say less.
        if session.diagnostics.isEmpty == false || session.errorMessage != nil
            || session.showsPolicyBreach {
            HStack(spacing: 8) {
                Image(
                    systemName: session.hasErrors || session.showsPolicyBreach
                        ? "xmark.octagon.fill"
                        : "exclamationmark.triangle.fill"
                )
                Text(noticeText)
                    .font(.callout)
                Spacer(minLength: 8)
                if session.diagnostics.isEmpty == false || session.policyRules.isEmpty == false {
                    Button("Show") { isShowingDiagnostics = true }
                        .accessibilityIdentifier("show-diagnostics")
                }
                Button("Dismiss") { session.dismissDiagnostics() }
            }
            .padding(8)
            .background(
                session.hasErrors || session.showsPolicyBreach
                    ? Color.red.opacity(0.2)
                    : Color.yellow.opacity(0.25)
            )
            .accessibilityIdentifier("project-notice")
        }
    }

    private var noticeText: String {
        if let errorMessage = session.errorMessage { return errorMessage }
        var parts: [String] = []
        let count = session.diagnostics.count
        if count > 0 {
            parts.append(count == 1
                ? "1 thing worth knowing about \(session.diagnosticsFileName ?? "this file")."
                : "\(count) things worth knowing about \(session.diagnosticsFileName ?? "this file")."
            )
        }
        if session.showsPolicyBreach {
            let breached = session.policyRules.count { $0.holds == false }
            parts.append(breached == 1
                ? "This system breaks 1 policy rule."
                : "This system breaks \(breached) policy rules."
            )
        }
        return parts.joined(separator: " ")
    }

    private var chosen: Binding<String?> {
        Binding(
            get: { session.chosenSystem },
            set: { name in
                guard let name else { return }
                session.pick(name)
                canvas.clearSelection()
            }
        )
    }

    /// One row of the systems picker: the name, and beside it the unanswered
    /// count and the worst level `threatmodeller list` prints for the same
    /// system. A system whose files do not parse shows a diagnostic mark
    /// instead, and the picker still opens the other systems.
    @ViewBuilder
    private func systemRow(_ name: String) -> some View {
        if let summary = session.systemSummaries[name] {
            if summary.isUnparsed {
                Label(name, systemImage: "exclamationmark.triangle.fill")
            } else {
                Text(systemCaption(name: name, summary: summary))
            }
        } else {
            Text(name)
        }
    }

    /// What one row of the systems picker states beside a parsed system's
    /// name.
    private func systemCaption(name: String, summary: SystemSummary) -> String {
        guard summary.worstLevel.isEmpty == false else {
            return "\(name) — \(summary.unanswered) unanswered"
        }
        return "\(name) — \(summary.unanswered) unanswered, \(summary.worstLevel)"
    }
}
