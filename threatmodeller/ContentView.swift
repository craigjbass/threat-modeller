import SwiftUI
import ThreatModelKit

struct ContentView: View {
    let document: ThreatModelDocument

    @State private var session: ThreatModelSession?

    var body: some View {
        Group {
            if let session {
                ModelView(session: session, drift: document.drift)
            } else if let startupError = document.store.startupError {
                ContentUnavailableView(
                    "The catalogue could not be loaded",
                    systemImage: "exclamationmark.triangle",
                    description: Text(startupError)
                )
            } else {
                ProgressView()
            }
        }
        .task {
            guard session == nil, let useCases = document.store.useCases else { return }
            session = ThreatModelSession(useCases: useCases)
        }
    }
}

private struct ModelView: View {
    let session: ThreatModelSession
    /// What had moved under this file since it was last saved, or nil for a
    /// new document.
    let drift: ThreatModelDrift?

    @State private var canvas = CanvasState()
    @State private var isDriftDismissed = false
    @State private var isSampleBrowserOpen = false

    /// Said once, above the diagram, and dismissible. A model that silently
    /// dropped what the catalogue no longer holds would be worse than one that
    /// says so.
    private var driftMessage: String? {
        guard isDriftDismissed == false, let drift, drift.hasDrift else { return nil }

        if drift.unknownTechnologyIds.isEmpty == false {
            return "This model uses "
                + "\(drift.unknownTechnologyIds.joined(separator: ", ")), "
                + "which the catalogue no longer holds. Those components raise no threats."
        }
        return "This model was last assessed against catalogue "
            + "\(drift.savedCatalogueTag ?? "an earlier version"). "
            + "This application holds \(drift.currentCatalogueTag)."
    }

    var body: some View {
        VStack(spacing: 0) {
            if let driftMessage {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                    Text(driftMessage).font(.callout)
                    Spacer(minLength: 8)
                    Button("Dismiss") { isDriftDismissed = true }
                }
                .padding(8)
                .background(Color.yellow.opacity(0.25))
                .accessibilityIdentifier("drift-banner")
            }

            columns
        }
        .focusedSceneValue(\.threatModelSession, session)
        .focusedSceneValue(\.threatModelCanvas, canvas)
        .focusedSceneValue(\.threatModelSampleBrowser, ShowSampleBrowser {
            isSampleBrowserOpen = true
        })
        .sheet(isPresented: $isSampleBrowserOpen) {
            SampleBrowser(session: session, canvas: canvas)
        }
    }

    private var columns: some View {
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

struct PaletteView: View {
    let session: ThreatModelSession
    /// Deleting a technology deletes the components using it, so the canvas
    /// must drop those rows from its selection.
    let canvas: CanvasState

    /// nil when no sheet is open, .some(nil) for a new technology, and
    /// .some(id) to change one.
    @State private var editing: EditedTechnology?

    var body: some View {
        List {
            ForEach(session.palette, id: \.id) { provider in
                Section(provider.displayName) {
                    ForEach(provider.categories, id: \.id) { category in
                        CategoryDisclosure(
                            providerId: provider.id,
                            category: category,
                            session: session,
                            canvas: canvas,
                            edit: { editing = EditedTechnology(value: $0) }
                        )
                    }
                }
            }
        }
        .navigationTitle("Technologies")
        .safeAreaInset(edge: .bottom) {
            Button {
                editing = EditedTechnology(value: nil)
            } label: {
                Label("New Technology\u{2026}", systemImage: "plus")
                    .frame(maxWidth: .infinity)
            }
            .padding(8)
            .accessibilityIdentifier("new-technology")
        }
        .sheet(item: $editing) { technologyId in
            CustomTechnologyEditor(session: session, technologyId: technologyId.value)
        }
    }
}

/// `sheet(item:)` needs something identifiable. A technology being changed is
/// named by its identifier; a new one has no identifier yet.
private struct EditedTechnology: Identifiable {
    let value: String?
    var id: String { value ?? "new" }
}

/// A category row plus its technologies.
///
/// This does not use `DisclosureGroup`. That control treats a click anywhere in
/// its label area as a toggle, so a button inside the label toggled the state a
/// second time and the group never opened. Here one button owns the toggle and
/// the rows below appear when it is open.
private struct CategoryDisclosure: View {
    let providerId: String
    let category: ListedCategory
    let session: ThreatModelSession
    let canvas: CanvasState
    let edit: (String) -> Void

    @State private var isExpanded = false

    var body: some View {
        Group {
            Button {
                isExpanded.toggle()
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .frame(width: 10)
                    Text(category.label)
                    Spacer(minLength: 0)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("category-\(providerId)-\(category.id)")

            if isExpanded {
                ForEach(category.technologies, id: \.id) { technology in
                    TechnologyRow(
                        technology: technology,
                        session: session,
                        canvas: canvas,
                        isDefinedByThisModel: providerId == CustomTechnology.provider.value,
                        edit: edit
                    )
                    .padding(.leading, 16)
                }
            }
        }
    }
}

/// A technology row. Drag it onto the canvas to place it where it is dropped,
/// or double-click it to place it near the top left of the canvas.
private struct TechnologyRow: View {
    let technology: ListedTechnology
    let session: ThreatModelSession
    let canvas: CanvasState
    /// Only a technology this model defines can be changed or deleted. The
    /// catalogue is a library, and this application does not edit it.
    let isDefinedByThisModel: Bool
    let edit: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(technology.name)
            Text(technology.description)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        .accessibilityIdentifier("technology-\(technology.id)")
        .draggable(technology.id) {
            Text(technology.name)
                .padding(6)
                .background(RoundedRectangle(cornerRadius: 6).fill(Color.accentColor.opacity(0.2)))
        }
        .onTapGesture(count: 2) {
            session.addAtDefaultPoint(technologyId: technology.id)
        }
        .contextMenu {
            if isDefinedByThisModel {
                Button("Edit\u{2026}") { edit(technology.id) }
                Button("Delete", role: .destructive) { delete() }
            }
        }
    }

    private func delete() {
        session.deleteCustomTechnology(technology.id)
        canvas.retainOnly(
            componentIds: Set(session.canvas.components.map(\.id)),
            connectionIds: Set(session.canvas.connections.map(\.id)),
            zoneIds: Set(session.canvas.zones.map(\.id))
        )
    }
}
