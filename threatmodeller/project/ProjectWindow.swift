import SwiftUI
import ThreatModelKit

/// A project root, drawn.
///
/// The three columns are the ones a document window uses. What this window adds
/// is the systems picker, the save that writes text back, and the diagnostics.
struct ProjectWindow: View {
    let session: ProjectSession

    @State private var isShowingDiagnostics = false
    @State private var isShowingLibraries = false
    @State private var canvas = CanvasState()

    var body: some View {
        Group {
            if let model = session.model {
                ProjectColumns(session: model, canvas: canvas)
                    .focusedSceneValue(\.threatModelSession, model)
                    .focusedSceneValue(\.threatModelCanvas, canvas)
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
        .safeAreaInset(edge: .top) { chrome }
        .sheet(isPresented: $isShowingDiagnostics) {
            DiagnosticsSheet(
                fileName: session.diagnosticsFileName ?? "",
                diagnostics: session.diagnostics,
                dismiss: { isShowingDiagnostics = false }
            )
        }
        .sheet(isPresented: $isShowingLibraries) {
            if let root = session.root {
                LibrariesSheet(
                    // A change reloads the project, so the palette shows a
                    // library that has just arrived.
                    session: LibrarySession(
                        useCases: session.useCases,
                        root: root,
                        onChange: { session.reloadFromDisk() }
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

            ToolbarItem {
                Button("Libraries", systemImage: "books.vertical") {
                    isShowingLibraries = true
                }
                .disabled(session.root == nil)
                .accessibilityIdentifier("libraries")
            }
        }
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
                    + "Start from an example and change it."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .frame(maxWidth: 420)

            VStack(spacing: 8) {
                ForEach(session.examples, id: \.id) { example in
                    Button {
                        session.initialise(sampleId: example.id)
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
            .padding(.top, 4)

            if let root = session.root {
                Text("It will be written to \(root)/threatmodel.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityIdentifier("empty-project")
    }

    private var chrome: some View {
        VStack(spacing: 0) {
            WorkflowBar(session: session)
            filesChangedNotice
            diagnosticsNotice
        }
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
                Button("Reload") { session.reloadFromDisk() }
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

    @ViewBuilder
    private var diagnosticsNotice: some View {
        if session.diagnostics.isEmpty == false || session.errorMessage != nil {
            HStack(spacing: 8) {
                Image(systemName: session.hasErrors ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                Text(noticeText)
                    .font(.callout)
                Spacer(minLength: 8)
                if session.diagnostics.isEmpty == false {
                    Button("Show") { isShowingDiagnostics = true }
                        .accessibilityIdentifier("show-diagnostics")
                }
                Button("Dismiss") { session.dismissDiagnostics() }
            }
            .padding(8)
            .background(session.hasErrors ? Color.red.opacity(0.2) : Color.yellow.opacity(0.25))
            .accessibilityIdentifier("project-notice")
        }
    }

    private var noticeText: String {
        if let errorMessage = session.errorMessage { return errorMessage }
        let count = session.diagnostics.count
        return count == 1
            ? "1 thing worth knowing about \(session.diagnosticsFileName ?? "this file")."
            : "\(count) things worth knowing about \(session.diagnosticsFileName ?? "this file")."
    }

    private var chosen: Binding<String?> {
        Binding(
            get: { session.chosenSystem },
            set: { name in
                guard let name else { return }
                session.choose(name)
                canvas.clearSelection()
            }
        )
    }
}

private struct ProjectColumns: View {
    let session: ThreatModelSession
    let canvas: CanvasState

    var body: some View {
        NavigationSplitView {
            PaletteView(session: session, canvas: canvas)
                .navigationSplitViewColumnWidth(min: 220, ideal: 260)
        } content: {
            CanvasView(session: session, canvas: canvas)
                .navigationTitle("Diagram")
                .navigationSplitViewColumnWidth(min: 400, ideal: 700)
        } detail: {
            ThreatSidebar(session: session)
                .navigationSplitViewColumnWidth(min: 300, ideal: 380)
        }
    }
}
