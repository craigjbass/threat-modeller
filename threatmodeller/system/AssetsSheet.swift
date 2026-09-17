import SwiftUI
import ThreatModelKit

/// The named things of value the system holds.
///
/// A component states which of these it holds, and a flow states which it
/// carries, so one classification is written once and read wherever the asset
/// goes. The sheet writes `system_asset` blocks through the same use case the
/// architecture sidebar used before.
struct AssetsSheet: View {
    let session: ThreatModelSession
    let dismiss: () -> Void

    /// The fields of one `system_asset` block, as a person edits them.
    struct Draft: Equatable {
        var id = ""
        var name = ""
        var classification = ""
        var description = ""
        var owner = ""
    }

    @State private var draft: Draft
    /// The identifier of the asset a person opened with Edit, or nil while
    /// the form writes a new one.
    @State private var editing: String?

    init(
        session: ThreatModelSession,
        dismiss: @escaping () -> Void,
        draft: Draft = Draft()
    ) {
        self.session = session
        self.dismiss = dismiss
        _draft = State(initialValue: draft)
        _editing = State(initialValue: nil)
    }

    var body: some View {
        SystemSheet(
            kind: .assets,
            says: "What this system holds. A component states which of these it holds, "
                + "so one classification is written once.",
            fileName: session.architectureFileName,
            isWritable: isWritable,
            isEditing: editing != nil,
            dismiss: dismiss,
            write: write
        ) {
            if session.canvas.systemAssets.isEmpty {
                SystemSheetEmptyNote(
                    says: "No asset is named. A component then states its own classification."
                )
            } else {
                ForEach(session.canvas.systemAssets, id: \.id) { asset in
                    SystemSheetRow(
                        identifier: "asset-\(asset.id)",
                        edit: { read(asset) },
                        remove: { remove(asset) }
                    ) {
                        Text(asset.name)
                            .font(.callout.weight(.semibold))
                        Text(label(ofClassification: asset.classificationId))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        if asset.description.isEmpty == false {
                            Text(asset.description)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        if let owner = asset.owner {
                            Text("Owner: \(owner)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        } form: {
            TextField("Identifier", text: $draft.id)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("asset-id")
            TextField("Name", text: $draft.name)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("asset-name")
            Picker("Classification", selection: $draft.classification) {
                ForEach(session.classificationChoices, id: \.id) {
                    Text($0.label).tag($0.id)
                }
            }
            .labelsHidden()
            .accessibilityIdentifier("asset-classification")
            TextField("Description (optional)", text: $draft.description, axis: .vertical)
                .lineLimit(2 ... 4)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("asset-description")
            TextField("Owner (optional)", text: $draft.owner)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("asset-owner")
        }
    }

    private var isWritable: Bool {
        SystemSheetWriting.states(draft.id, draft.name)
    }

    /// Writes a new asset, or changes the asset whose identifier the form
    /// holds. Writing an identifier that is already there changes that asset.
    func write() {
        let owner = draft.owner.trimmingCharacters(in: .whitespaces)
        session.setSystemAsset(
            id: draft.id.trimmingCharacters(in: .whitespaces),
            name: draft.name.trimmingCharacters(in: .whitespaces),
            classificationId: draft.classification.isEmpty
                ? (session.classificationChoices.first?.id ?? "internal")
                : draft.classification,
            description: draft.description.trimmingCharacters(in: .whitespaces),
            owner: owner.isEmpty ? nil : owner
        )
        if session.errorMessage == nil { startANewOne() }
    }

    /// Reads one asset into the form, so a person changes it rather than
    /// typing it again.
    private func read(_ asset: ViewedSystemAsset) {
        editing = asset.id
        draft = Draft(
            id: asset.id,
            name: asset.name,
            classification: asset.classificationId,
            description: asset.description,
            owner: asset.owner ?? ""
        )
    }

    private func remove(_ asset: ViewedSystemAsset) {
        if editing == asset.id { startANewOne() }
        session.removeSystemAsset(id: asset.id)
    }

    private func startANewOne() {
        editing = nil
        draft = Draft()
    }

    private func label(ofClassification id: String) -> String {
        session.classificationChoices.first { $0.id == id }?.label ?? id
    }
}
