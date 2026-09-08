import SwiftUI
import ThreatModelKit

struct ContentView: View {
    @State private var session: ThreatModelSession?
    @State private var startupError: String?

    var body: some View {
        Group {
            if let session {
                ModelView(session: session)
            } else if let startupError {
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
            guard session == nil, startupError == nil else { return }
            do {
                session = ThreatModelSession(useCases: try Dependencies())
            } catch {
                startupError = String(describing: error)
            }
        }
    }
}

private struct ModelView: View {
    let session: ThreatModelSession
    @State private var canvas = CanvasState()

    var body: some View {
        NavigationSplitView {
            PaletteView(session: session)
                .navigationSplitViewColumnWidth(min: 220, ideal: 260)
        } content: {
            CanvasView(session: session, canvas: canvas)
                .navigationTitle("Diagram")
                .navigationSplitViewColumnWidth(min: 400, ideal: 700)
        } detail: {
            ThreatListView(session: session)
                .navigationSplitViewColumnWidth(min: 280, ideal: 360)
        }
    }
}

private struct PaletteView: View {
    let session: ThreatModelSession

    var body: some View {
        List {
            ForEach(session.palette, id: \.id) { provider in
                Section(provider.displayName) {
                    ForEach(provider.categories, id: \.id) { category in
                        CategoryDisclosure(providerId: provider.id, category: category, session: session)
                    }
                }
            }
        }
        .navigationTitle("Technologies")
    }
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
                    TechnologyRow(technology: technology, session: session)
                        .padding(.leading, 16)
                }
            }
        }
    }
}

/// A technology row that adds the technology when clicked anywhere on the
/// row, including the empty space to the right of the text.
private struct TechnologyRow: View {
    let technology: ListedTechnology
    let session: ThreatModelSession

    var body: some View {
        Button {
            session.add(technologyId: technology.id, x: 0, y: 0)
        } label: {
            VStack(alignment: .leading, spacing: 2) {
                Text(technology.name)
                Text(technology.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("technology-\(technology.id)")
    }
}

private extension AssessedThreat {
    /// Row key for the threat list. `AssessedThreat` carries no identity
    /// field of its own, so two equal threats would collide as one row.
    /// The pair of `threatId` and the source's id identifies a row.
    var rowIdentity: String { "\(threatId)#\(source.id)" }
}

private struct ThreatListView: View {
    let session: ThreatModelSession

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let errorMessage = session.errorMessage {
                Text(errorMessage)
                    .foregroundStyle(.red)
                    .padding()
            }

            if session.threats.isEmpty {
                ContentUnavailableView(
                    "No threats yet",
                    systemImage: "shield",
                    description: Text("Add a technology from the palette to see the threats it carries.")
                )
            } else {
                List(session.threats, id: \.rowIdentity) { threat in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(threat.name).font(.headline)
                            Spacer()
                            Text("\(threat.riskLevel.capitalized) · \(threat.riskScore)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Text(threat.source.displayName)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                        Text(threat.context ?? threat.description)
                            .font(.callout)
                        if threat.controls.isEmpty == false {
                            Text(threat.controls.map(\.description).joined(separator: " · "))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .navigationTitle("Threats")
    }
}
