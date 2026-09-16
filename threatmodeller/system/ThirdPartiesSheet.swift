import SwiftUI
import ThreatModelKit

/// The parties outside this team the system depends on.
///
/// A component states which party provides it, so the vendor is written once
/// and read wherever the component goes.
struct ThirdPartiesSheet: View {
    let session: ThreatModelSession
    let dismiss: () -> Void

    /// The fields of one `third_party` block, as a person edits them.
    struct Draft: Equatable {
        var id = ""
        var name = ""
        var description = ""
        var kind = ThirdPartyKind.saas.rawValue
        var pays = false
        var uptime = UptimeDependency.none.rawValue
        var uptimeNotes = ""
        var owner = ""
        var link = ""
    }

    @State private var draft: Draft
    /// The identifier of the party a person opened with Edit, or nil while
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
            kind: .thirdParties,
            says: "Who outside this team this system depends on. A component states which party "
                + "provides it, so the vendor is written once.",
            fileName: session.architectureFileName,
            isWritable: SystemSheetWriting.states(draft.id, draft.name),
            isEditing: editing != nil,
            dismiss: dismiss,
            write: write
        ) {
            if session.canvas.thirdParties.isEmpty {
                SystemSheetEmptyNote(
                    says: "No third party is named. A reader cannot tell which part of this "
                        + "system another company runs."
                )
            } else {
                ForEach(session.canvas.thirdParties, id: \.id) { party in
                    SystemSheetRow(
                        identifier: "third-party-\(party.id)",
                        edit: { read(party) },
                        remove: { remove(party) }
                    ) {
                        Text(party.name)
                            .font(.callout.weight(.semibold))
                        Text(
                            "\(party.kindLabel) \u{00B7} "
                                + (party.payingCustomer ? "The team pays" : "The team does not pay")
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        if party.description.isEmpty == false {
                            Text(party.description)
                                .font(.caption)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Text("Uptime: \(party.uptimeLabel)")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                        if let owner = party.owner {
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
                .accessibilityIdentifier("third-party-id")
            TextField("Name", text: $draft.name)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("third-party-name")
            TextField("What it provides", text: $draft.description, axis: .vertical)
                .lineLimit(2 ... 4)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("third-party-description")

            HStack(spacing: 6) {
                Picker("Kind", selection: $draft.kind) {
                    ForEach(ThirdPartyKind.allCases, id: \.rawValue) {
                        Text($0.label).tag($0.rawValue)
                    }
                }
                .labelsHidden()
                .accessibilityIdentifier("third-party-kind")

                Picker("Uptime", selection: $draft.uptime) {
                    ForEach(UptimeDependency.allCases, id: \.rawValue) {
                        Text($0.label).tag($0.rawValue)
                    }
                }
                .labelsHidden()
                .accessibilityIdentifier("third-party-uptime")
            }

            Toggle("The team pays this party", isOn: $draft.pays)
                .font(.caption)
                .accessibilityIdentifier("third-party-paying-customer")

            TextField("What happens when it stops", text: $draft.uptimeNotes, axis: .vertical)
                .lineLimit(2 ... 4)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("third-party-uptime-notes")

            TextField("Owner (optional)", text: $draft.owner)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("third-party-owner")

            TextField("Link (optional)", text: $draft.link)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("third-party-link")
        }
    }

    /// Writes a new party, or changes the party whose identifier the form
    /// holds.
    func write() {
        let owner = draft.owner.trimmingCharacters(in: .whitespaces)
        let link = draft.link.trimmingCharacters(in: .whitespaces)
        session.setThirdParty(
            id: draft.id.trimmingCharacters(in: .whitespaces),
            name: draft.name.trimmingCharacters(in: .whitespaces),
            description: draft.description.trimmingCharacters(in: .whitespaces),
            kindId: draft.kind,
            payingCustomer: draft.pays,
            uptimeId: draft.uptime,
            uptimeNotes: draft.uptimeNotes.trimmingCharacters(in: .whitespaces),
            owner: owner.isEmpty ? nil : owner,
            link: link.isEmpty ? nil : link
        )
        if session.errorMessage == nil { startANewOne() }
    }

    private func read(_ party: ViewedThirdParty) {
        editing = party.id
        draft = Draft(
            id: party.id,
            name: party.name,
            description: party.description,
            kind: party.kindId,
            pays: party.payingCustomer,
            uptime: party.uptimeId,
            uptimeNotes: party.uptimeNotes,
            owner: party.owner ?? "",
            link: party.link ?? ""
        )
    }

    private func remove(_ party: ViewedThirdParty) {
        if editing == party.id { startANewOne() }
        session.removeThirdParty(id: party.id)
    }

    private func startANewOne() {
        editing = nil
        draft = Draft()
    }
}
