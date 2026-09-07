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

    var body: some View {
        NavigationSplitView {
            PaletteView(session: session)
                .navigationSplitViewColumnWidth(min: 240, ideal: 280)
        } detail: {
            ThreatListView(session: session)
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
                        CategoryDisclosure(category: category, session: session)
                    }
                }
            }
        }
        .navigationTitle("Technologies")
    }
}

/// A category row that toggles open or closed no matter where the row is
/// clicked, not only on the small disclosure triangle.
private struct CategoryDisclosure: View {
    let category: ListedCategory
    let session: ThreatModelSession

    @State private var isExpanded = false

    var body: some View {
        DisclosureGroup(isExpanded: $isExpanded) {
            ForEach(category.technologies, id: \.id) { technology in
                TechnologyRow(technology: technology, session: session)
            }
        } label: {
            Button {
                isExpanded.toggle()
            } label: {
                Text(category.label)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
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
            session.add(technologyId: technology.id)
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
    }
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
                List(session.threats, id: \.self) { threat in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(threat.name).font(.headline)
                            Spacer()
                            Text("\(threat.riskLevel.capitalized) · \(threat.riskScore)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Text(threat.sourceName)
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
