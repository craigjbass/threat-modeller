import SwiftUI
import ThreatModelKit

/// What the system takes on trust, and what one component lowers on another.
///
/// Both of these are facts about the architecture that the diagram cannot
/// draw: an assumption is a sentence, and a mitigates edge names threats. The
/// architecture stage keeps them in the column beside the diagram, so a
/// person writes them while the system is in front of them.
struct AssumptionsPanel: View {
    let session: ThreatModelSession

    @State private var label = ""
    @State private var text = ""
    @State private var owner = ""
    @State private var useCaseLabel = ""
    @State private var useCaseText = ""
    @State private var exclusionLabel = ""
    @State private var exclusionText = ""
    @State private var exclusionRationale = ""
    @State private var assetId = ""
    @State private var assetName = ""
    @State private var assetClassification = ""
    @State private var assetOwner = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("What this system takes on trust")
                    .font(.subheadline.weight(.semibold))

                if session.canvas.assumptions.isEmpty {
                    Text("Nothing is assumed. A report says so, and a reader knows what was not checked.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    ForEach(session.canvas.assumptions, id: \.label) { assumption in
                        assumptionRow(assumption)
                    }
                }

                Divider()
                writeOne

                Divider()
                assets

                Divider()
                useCases

                Divider()
                exclusions

                if session.canvas.mitigations.isEmpty == false {
                    Divider()
                    Text("What one component lowers on another")
                        .font(.subheadline.weight(.semibold))
                    ForEach(session.canvas.mitigations, id: \.sourceComponentId) { mitigation in
                        mitigationRow(mitigation)
                    }
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle("Assumptions")
        .accessibilityIdentifier("assumptions-panel")
    }

    /// The named things of value the system holds. A component states which
    /// of these it holds, and a flow states which it carries, so one
    /// classification is written once and read wherever the asset goes.
    private var assets: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("What this system holds")
                .font(.subheadline.weight(.semibold))

            if session.canvas.systemAssets.isEmpty {
                Text("No asset is named. A component then states its own classification.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(session.canvas.systemAssets, id: \.id) { asset in
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Text(asset.name)
                                .font(.callout.weight(.semibold))
                            Spacer(minLength: 4)
                            Button {
                                session.removeSystemAsset(id: asset.id)
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                            .accessibilityIdentifier("remove-asset-\(asset.id)")
                        }
                        Text(label(ofClassification: asset.classificationId))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        if let owner = asset.owner {
                            Text("Owner: \(owner)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(8)
                    .background(
                        RoundedRectangle(cornerRadius: 6)
                            .fill(Color(nsColor: .controlBackgroundColor))
                    )
                }
            }

            TextField("Identifier", text: $assetId)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("asset-id")
            TextField("Name", text: $assetName)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("asset-name")
            HStack(spacing: 6) {
                Picker("Classification", selection: $assetClassification) {
                    ForEach(session.classificationChoices, id: \.id) {
                        Text($0.label).tag($0.id)
                    }
                }
                .labelsHidden()
                .accessibilityIdentifier("asset-classification")

                TextField("Owner (optional)", text: $assetOwner)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("asset-owner")

                Button("Add") {
                    let owner = assetOwner.trimmingCharacters(in: .whitespaces)
                    session.setSystemAsset(
                        id: assetId.trimmingCharacters(in: .whitespaces),
                        name: assetName.trimmingCharacters(in: .whitespaces),
                        classificationId: assetClassification.isEmpty
                            ? (session.classificationChoices.first?.id ?? "internal")
                            : assetClassification,
                        owner: owner.isEmpty ? nil : owner
                    )
                    assetId = ""
                    assetName = ""
                    assetOwner = ""
                }
                .disabled(isWritable(assetId, assetName) == false)
                .accessibilityIdentifier("add-asset")
            }
        }
    }

    private func label(ofClassification id: String) -> String {
        session.classificationChoices.first { $0.id == id }?.label ?? id
    }

    /// What a person does with the system. A report reads these under Scope,
    /// so a reader can tell a flow modelled and found safe from a flow nobody
    /// modelled.
    private var useCases: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("What a person does with this system")
                .font(.subheadline.weight(.semibold))

            if session.canvas.useCases.isEmpty {
                Text("No use case is stated. A reader cannot tell what this model covers.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(session.canvas.useCases, id: \.label) { useCase in
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Text(useCase.label)
                                .font(.callout.weight(.semibold))
                            Spacer(minLength: 4)
                            Button {
                                session.removeSystemUseCase(label: useCase.label)
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                            .accessibilityIdentifier("remove-use-case-\(useCase.label)")
                        }
                        Text(useCase.text)
                            .font(.caption)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(8)
                    .background(
                        RoundedRectangle(cornerRadius: 6)
                            .fill(Color(nsColor: .controlBackgroundColor))
                    )
                }
            }

            TextField("Label", text: $useCaseLabel)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("use-case-label")
            HStack(spacing: 6) {
                TextField("What a person does", text: $useCaseText, axis: .vertical)
                    .lineLimit(2 ... 4)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("use-case-text")
                Button("Add") {
                    session.setSystemUseCase(
                        label: useCaseLabel.trimmingCharacters(in: .whitespaces),
                        text: useCaseText.trimmingCharacters(in: .whitespaces)
                    )
                    useCaseLabel = ""
                    useCaseText = ""
                }
                .disabled(isWritable(useCaseLabel, useCaseText) == false)
                .accessibilityIdentifier("add-use-case")
            }
        }
    }

    /// What this model does not cover, and why. A rationale is required: an
    /// exclusion with no reason is a gap.
    private var exclusions: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("What this model does not cover")
                .font(.subheadline.weight(.semibold))

            if session.canvas.exclusions.isEmpty {
                Text("Nothing is excluded. A report says so, and a reader knows the model claims to cover the whole system.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(session.canvas.exclusions, id: \.label) { exclusion in
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Text(exclusion.label)
                                .font(.callout.weight(.semibold))
                            Spacer(minLength: 4)
                            Button {
                                session.removeExclusion(label: exclusion.label)
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                            .accessibilityIdentifier("remove-exclusion-\(exclusion.label)")
                        }
                        Text(exclusion.text)
                            .font(.caption)
                            .fixedSize(horizontal: false, vertical: true)
                        Text("Rationale: \(exclusion.rationale)")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(8)
                    .background(
                        RoundedRectangle(cornerRadius: 6)
                            .fill(Color(nsColor: .controlBackgroundColor))
                    )
                }
            }

            TextField("Label", text: $exclusionLabel)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("exclusion-label")
            TextField("What the model does not cover", text: $exclusionText, axis: .vertical)
                .lineLimit(2 ... 4)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("exclusion-text")
            HStack(spacing: 6) {
                TextField("Why", text: $exclusionRationale, axis: .vertical)
                    .lineLimit(2 ... 4)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("exclusion-rationale")
                Button("Add") {
                    session.setExclusion(
                        label: exclusionLabel.trimmingCharacters(in: .whitespaces),
                        text: exclusionText.trimmingCharacters(in: .whitespaces),
                        rationale: exclusionRationale.trimmingCharacters(in: .whitespaces)
                    )
                    exclusionLabel = ""
                    exclusionText = ""
                    exclusionRationale = ""
                }
                .disabled(isWritableExclusion == false)
                .accessibilityIdentifier("add-exclusion")
            }
        }
    }

    private func isWritable(_ label: String, _ text: String) -> Bool {
        label.trimmingCharacters(in: .whitespaces).isEmpty == false
            && text.trimmingCharacters(in: .whitespaces).isEmpty == false
    }

    private var isWritableExclusion: Bool {
        isWritable(exclusionLabel, exclusionText)
            && exclusionRationale.trimmingCharacters(in: .whitespaces).isEmpty == false
    }

    private func assumptionRow(_ assumption: ViewedAssumption) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(assumption.label)
                    .font(.callout.weight(.semibold))
                Spacer(minLength: 4)
                Button {
                    session.removeAssumption(label: assumption.label)
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("remove-assumption-\(assumption.label)")
            }
            Text(assumption.text)
                .font(.caption)
                .fixedSize(horizontal: false, vertical: true)
            if let owner = assumption.owner {
                Text("Owner: \(owner)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .controlBackgroundColor)))
    }

    private func mitigationRow(_ mitigation: ViewedMitigation) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text("\(name(of: mitigation.sourceComponentId)) \u{2192} \(name(of: mitigation.targetComponentId))")
                    .font(.callout)
                Spacer(minLength: 4)
                Button {
                    session.removeMitigatesEdge(
                        from: mitigation.sourceComponentId,
                        to: mitigation.targetComponentId
                    )
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("remove-mitigates-\(mitigation.sourceComponentId)")
            }
            Text("\(mitigation.status.capitalized) \u{00B7} lowers \(mitigation.threatIds.count) by \(mitigation.reducesRiskBy)%")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .controlBackgroundColor)))
    }

    private func name(of componentId: String) -> String {
        session.canvas.components.first { $0.id == componentId }?.name ?? componentId
    }

    private var writeOne: some View {
        VStack(alignment: .leading, spacing: 6) {
            TextField("Label", text: $label)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("assumption-label")

            TextField("What is taken on trust", text: $text, axis: .vertical)
                .lineLimit(2 ... 4)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("assumption-text")

            HStack(spacing: 6) {
                TextField("Owner (optional)", text: $owner)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("assumption-owner")

                Button("Add", action: write)
                    .disabled(isWritable == false)
                    .accessibilityIdentifier("add-assumption")
            }
        }
    }

    private var isWritable: Bool {
        label.trimmingCharacters(in: .whitespaces).isEmpty == false
            && text.trimmingCharacters(in: .whitespaces).isEmpty == false
    }

    private func write() {
        let owner = owner.trimmingCharacters(in: .whitespaces)
        session.setAssumption(
            label: label.trimmingCharacters(in: .whitespaces),
            text: text.trimmingCharacters(in: .whitespaces),
            owner: owner.isEmpty ? nil : owner
        )
        label = ""
        text = ""
        self.owner = ""
    }
}
