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
    /// True while the attack tree editor is on screen.
    @State private var isShowingAttackTrees = false
    @State private var isShowingHistory = false
    /// True while the check summary is on screen.
    @State private var isShowingCheckSummary = false
    @State private var canvas = CanvasState()
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
                // A drawn model wins over a stage. The stage is what the
                // window has instead of a diagram, never instead of one: a
                // stage left behind must not be able to hide the diagram.
                if let model = session.model {
                    ProjectColumns(
                        project: session,
                        session: model,
                        canvas: canvas,
                        stage: $stage
                    )
                        .focusedSceneValue(\.threatModelSession, model)
                        .focusedSceneValue(\.threatModelCanvas, canvas)
                        .focusedSceneValue(\.projectSession, session)
                        // A context menu on the diagram takes a person to the
                        // threats of what they clicked.
                        .onAppear { canvas.showStage = { stage = $0 } }
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
        .sheet(isPresented: $isShowingHistory) {
            if let root = session.root {
                HistorySheet(
                    session: HistorySession(useCases: session.useCases, root: root),
                    dismiss: { isShowingHistory = false }
                )
            }
        }
        .sheet(isPresented: $isShowingAttackTrees) {
            if let model = session.model {
                AttackTreeSheet(
                    project: session,
                    threats: model.threats,
                    bound: model.attackTrees,
                    elements: TreeElement.list(
                        threats: model.threats,
                        components: model.canvas.components,
                        connections: model.canvas.connections,
                        zones: model.canvas.zones
                    ),
                    dismiss: { isShowingAttackTrees = false }
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
            }
        }
        .onChange(of: session.diagnostics.count) {
            // Errors stop the picture, so they interrupt. Warnings sit in the
            // strip until the user asks for them.
            if session.hasErrors { isShowingDiagnostics = true }
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Picker("System", selection: chosen) {
                    ForEach(session.systems, id: \.self) { name in
                        Text(name).tag(name as String?)
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

            ToolbarItem {
                // Reading the history compiles the model once per sampled
                // commit, so it is read when a person asks and never on open.
                Button("History", systemImage: "chart.line.uptrend.xyaxis") {
                    isShowingHistory = true
                }
                .accessibilityIdentifier("show-history")
            }

            ToolbarItem {
                Button("Attack Trees", systemImage: "point.topleft.down.to.point.bottomright.curvepath") {
                    isShowingAttackTrees = true
                }
                .disabled(session.model == nil)
                .help("Write how an attacker reaches a threat.")
                .accessibilityIdentifier("attack-trees")
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

            // Auto Sync is a setting, not a verb, so it sits with the other
            // window-wide controls rather than on the floating panel with the
            // two verbs.
            ToolbarItem {
                Toggle("Auto Sync", isOn: autoSync)
                    .toggleStyle(.checkbox)
                    .help(
                        "Save the .arch and .controls files when you change "
                            + "the model, and redraw the diagram when those "
                            + "files change on disk."
                    )
                    .accessibilityIdentifier("auto-sync")
            }
        }
    }

    /// What a load is doing. Opening a large model takes long enough that a
    /// still window reads as a broken one, so the window says the stage it is
    /// in and, when it is opening the project, which step that is of the four.
    private func loadingNotice(_ stage: ProjectSession.LoadingStage) -> some View {
        VStack(spacing: 14) {
            // The shape of the diagram as the layout search last had it, so a
            // person watches it settle rather than watching nothing.
            if let forming = session.formingDiagram {
                FormingDiagram(layout: forming)
                    .frame(maxWidth: 520, maxHeight: 320)
            } else {
                ProgressView()
                    .controlSize(.large)
            }

            Text(stage.says)
                .font(.title3)

            Text(stepOf(stage))
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityIdentifier("loading")
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
}
