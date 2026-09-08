import SwiftUI
import ThreatModelKit

/// Names a technology this model defines for itself.
///
/// The user says which of the catalogue's threats their service carries. They
/// cannot invent a threat, because a threat carries controls, MITRE techniques
/// and a severity that the rest of the application reads.
struct CustomTechnologyEditor: View {
    let session: ThreatModelSession
    /// The technology being changed, or nil to define a new one.
    let technologyId: String?

    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var categoryId = ""
    @State private var description = ""
    @State private var chosenThreatIds: Set<String> = []
    @State private var enforcesEncryption = false
    @State private var threatSearch = ""

    private var isEditing: Bool { technologyId != nil }

    private var visibleThreats: [ThreatChoice] {
        let query = threatSearch.trimmingCharacters(in: .whitespaces).lowercased()
        guard query.isEmpty == false else { return session.threatChoices }
        return session.threatChoices.filter { $0.name.lowercased().contains(query) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(isEditing ? "Edit Technology" : "New Technology")
                .font(.headline)

            Form {
                TextField("Name", text: $name)
                    .accessibilityIdentifier("technology-name")

                Picker("Category", selection: $categoryId) {
                    ForEach(session.categoryChoices, id: \.id) { category in
                        Text(category.label).tag(category.id)
                    }
                }
                .accessibilityIdentifier("technology-category")

                TextField("Description", text: $description, axis: .vertical)
                    .lineLimit(2 ... 4)
                    .accessibilityIdentifier("technology-description")

                Toggle("This technology encrypts what crosses it", isOn: $enforcesEncryption)
                    .accessibilityIdentifier("technology-enforces-encryption")
            }
            .formStyle(.grouped)

            threatChooser

            HStack {
                if let errorMessage = session.errorMessage {
                    Text(errorMessage)
                        .font(.callout)
                        .foregroundStyle(.red)
                }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(isEditing ? "Save" : "Add") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                    .accessibilityIdentifier("technology-save")
            }
        }
        .padding(16)
        .frame(width: 520, height: 560)
        .onAppear(perform: load)
    }

    private var threatChooser: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Threats it carries").font(.subheadline)
                Spacer()
                Text("\(chosenThreatIds.count) chosen")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            TextField("Search threats", text: $threatSearch)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("technology-threat-search")

            List {
                ForEach(visibleThreats, id: \.id) { threat in
                    Toggle(isOn: binding(for: threat.id)) {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(threat.name)
                            Text(
                                ([threat.severityLabel] + threat.strideLabels)
                                    .joined(separator: " \u{00B7} ")
                            )
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        }
                    }
                    .accessibilityIdentifier("threat-choice-\(threat.id)")
                }
            }
            .frame(minHeight: 160)
        }
    }

    private func binding(for threatId: String) -> Binding<Bool> {
        Binding(
            get: { chosenThreatIds.contains(threatId) },
            set: { isChosen in
                if isChosen {
                    chosenThreatIds.insert(threatId)
                } else {
                    chosenThreatIds.remove(threatId)
                }
            }
        )
    }

    private func load() {
        if categoryId.isEmpty { categoryId = session.categoryChoices.first?.id ?? "" }
        guard let technologyId, let technology = session.customTechnology(technologyId) else { return }
        name = technology.name
        categoryId = technology.categoryId
        description = technology.description
        chosenThreatIds = Set(technology.threatIds)
        enforcesEncryption = technology.enforcesEncryption
    }

    /// The sheet stays open when the model refuses a value, so the message
    /// appears next to the field the user must change.
    private func save() {
        let threatIds = session.threatChoices.map(\.id).filter(chosenThreatIds.contains)

        if let technologyId {
            let isSaved = session.editCustomTechnology(
                technologyId: technologyId,
                name: name,
                categoryId: categoryId,
                description: description,
                threatIds: threatIds,
                enforcesEncryption: enforcesEncryption
            )
            if isSaved { dismiss() }
            return
        }

        if session.createCustomTechnology(
            name: name,
            categoryId: categoryId,
            description: description,
            threatIds: threatIds,
            enforcesEncryption: enforcesEncryption
        ) != nil {
            dismiss()
        }
    }
}
