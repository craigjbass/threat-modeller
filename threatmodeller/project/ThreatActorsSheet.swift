import SwiftUI
import ThreatModelKit

/// The adversaries this system faces, and the ones it could face.
///
/// The list states what each actor is: its capability, its intent, the threats
/// it performs and the ATT&CK groups that work the same way. The tick writes
/// the system's `faces` list, and the form below writes a `threat_actor` block
/// into this system's architecture file. Both go through the use cases, so the
/// file the window writes is the file the executable reads.
struct ThreatActorsSheet: View {
    let session: ThreatModelSession
    let dismiss: () -> Void

    /// What a person types into the search field. An ATT&CK synchronise puts
    /// about 180 groups in this list, so the list needs a filter.
    @State private var search = ""
    /// The local block a person is writing.
    @State private var draft: Draft

    init(
        session: ThreatModelSession,
        dismiss: @escaping () -> Void,
        draft: Draft = Draft()
    ) {
        self.session = session
        self.dismiss = dismiss
        _draft = State(initialValue: draft)
    }

    /// The fields of one local `threat_actor` block, as a person edits them.
    struct Draft: Equatable {
        var id = ""
        var name = ""
        var description = ""
        var aliases = ""
        var capability = Likelihood.targeted.id
        var intent = ""
        var performs = ""
        /// The ATT&CK technique ids, as `MitreIdField` writes them: ids only,
        /// the same list the parser reads.
        var techniques: [String] = []
        var catalogueTier = ""
    }

    /// The tier a picker shows for "no tier at all".
    private static let noTier = ""

    private var actors: [ListedThreatActor] { session.threatActorsInUse }

    private var shown: [ListedThreatActor] {
        let wanted = search.trimmingCharacters(in: .whitespaces).lowercased()
        guard wanted.isEmpty == false else { return actors }
        return actors.filter {
            $0.name.lowercased().contains(wanted)
                || $0.id.lowercased().contains(wanted)
                || $0.intent.lowercased().contains(wanted)
        }
    }

    private var faced: [String] { actors.filter(\.isFaced).map(\.id) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Threat actors")
                .font(.headline)
            Text(
                "This assessment is written against the actors you tick. "
                    + "A threat no ticked actor performs keeps the catalogue's "
                    + "own likelihood, so leaving an actor out never lowers a score."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            TextField("Search", text: $search)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("threat-actor-search")

            list

            Divider()
            editor

            if let message = session.errorMessage {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("threat-actor-error")
            }

            Text(says)
                .font(.caption)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("threat-actors-faced")

            SystemSheetFooter(
                kind: .threatActors,
                fileName: session.architectureFileName,
                isWritable: isWritable,
                isEditing: false,
                dismiss: dismiss,
                write: write
            )
        }
        .padding(20)
        .frame(minWidth: 760, minHeight: 520)
        .accessibilityIdentifier("threat-actors-sheet")
    }

    /// What the sheet says about the actors this system faces.
    ///
    /// A system that faces nobody states that in words, because a row of
    /// unticked boxes reads the same as a list nobody has looked at yet.
    var says: String {
        if actors.isEmpty {
            return "This project holds no threat actor. "
                + "Synchronise ATT&CK, or write one below."
        }
        let faces = faced.count
        if faces == 0 {
            return "This system faces no threat actor. "
                + "Every threat keeps the catalogue's own likelihood."
        }
        return faces == 1
            ? "This system faces 1 of \(actors.count) actors."
            : "This system faces \(faces) of \(actors.count) actors."
    }

    // MARK: the actors

    private var list: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(shown, id: \.id) { actor in
                    row(actor)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(minHeight: 220)
    }

    private func row(_ actor: ListedThreatActor) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Toggle(isOn: faces(actor)) {
                    Text(actor.name)
                        .font(.callout.weight(.semibold))
                }
                .toggleStyle(.checkbox)
                .accessibilityIdentifier("faces-\(actor.id)")

                Text(actor.capabilityLabel)
                    .font(.caption)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 1)
                    .background(
                        RoundedRectangle(cornerRadius: 4)
                            .fill(Color.secondary.opacity(0.18))
                    )

                if actor.intent.isEmpty == false {
                    Text(actor.intent.capitalized)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer(minLength: 4)

                if actor.isLocal {
                    Button {
                        session.removeLocalThreatActor(id: actor.id)
                    } label: {
                        Image(systemName: "trash")
                    }
                    .buttonStyle(.borderless)
                    .help("Take this system's own threat actor block off.")
                    .accessibilityIdentifier("remove-threat-actor-\(actor.id)")

                    Button {
                        edit(actor)
                    } label: {
                        Image(systemName: "pencil")
                    }
                    .buttonStyle(.borderless)
                    .help("Read this block into the form below.")
                    .accessibilityIdentifier("edit-threat-actor-\(actor.id)")
                }
            }

            Text(performs(actor))
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if actor.aliases.isEmpty == false {
                Text("Aliases: \(actor.aliases.joined(separator: ", "))")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if actor.mitreGroups.isEmpty == false {
                Text("MITRE groups: \(groups(actor))")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(8)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
    }

    /// What this actor performs, by name. The whole list for a short one, and
    /// the first few plus a count for a long one.
    private func performs(_ actor: ListedThreatActor) -> String {
        guard actor.threatsPerformed > 0 else {
            return "Performs no threat this project's catalogue holds."
        }
        let shown = actor.threatNames.prefix(6).joined(separator: ", ")
        return actor.threatNames.count > 6
            ? "Performs \(shown) and \(actor.threatNames.count - 6) more."
            : "Performs \(shown)."
    }

    private func groups(_ actor: ListedThreatActor) -> String {
        let shown = actor.mitreGroups.prefix(6).joined(separator: ", ")
        return actor.mitreGroups.count > 6
            ? "\(shown) and \(actor.mitreGroups.count - 6) more"
            : shown
    }

    /// The tick on one row. Reading it says whether the `faces` list names the
    /// actor; writing it writes the whole list again.
    private func faces(_ actor: ListedThreatActor) -> Binding<Bool> {
        Binding(
            get: { actor.isFaced },
            set: { wanted in
                var held = faced
                if wanted {
                    guard held.contains(actor.id) == false else { return }
                    held.append(actor.id)
                } else {
                    held.removeAll { $0 == actor.id }
                }
                session.setFacedThreatActors(held)
            }
        )
    }

    // MARK: this system's own actor

    private var editor: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("An actor this system declares")
                .font(.subheadline.weight(.semibold))
            Text(
                "A block whose identifier matches a library actor or an ATT&CK "
                    + "group replaces that actor for this system, whole."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 6) {
                TextField("Identifier", text: $draft.id)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("threat-actor-id")
                TextField("Name", text: $draft.name)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("threat-actor-name")
            }

            HStack(spacing: 6) {
                Picker("Capability", selection: $draft.capability) {
                    ForEach(Likelihood.allTiers, id: \.id) {
                        Text($0.label).tag($0.id)
                    }
                }
                .labelsHidden()
                .accessibilityIdentifier("threat-actor-capability")

                TextField("Intent", text: $draft.intent)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("threat-actor-intent")

                Picker("Performs every threat at tier", selection: $draft.catalogueTier) {
                    Text("No catalogue tier").tag(Self.noTier)
                    ForEach(Likelihood.allTiers, id: \.id) {
                        Text("Every \($0.label.lowercased()) threat").tag($0.id)
                    }
                }
                .labelsHidden()
                .accessibilityIdentifier("threat-actor-catalogue-tier")
            }

            TextField("What this actor is", text: $draft.description, axis: .vertical)
                .lineLimit(2 ... 4)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("threat-actor-description")

            TextField("Aliases, separated by a comma", text: $draft.aliases)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("threat-actor-aliases")

            TextField("Threat ids, separated by a comma", text: $draft.performs)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("threat-actor-performs")

            techniqueField($draft.techniques)
        }
    }

    /// The control that writes this actor's ATT&CK technique ids.
    ///
    /// Issue #148: the ids are picked out of the synchronised matrix by id or
    /// by name, so nobody types one from memory.
    func techniqueField(_ ids: Binding<[String]>) -> MitreIdField {
        MitreIdField(
            title: "ATT&CK techniques this actor uses",
            identifier: "threat-actor-techniques",
            kind: .technique,
            ids: ids,
            search: { text, kind in session.searchAttackData(text, kind: kind) },
            synchronise: session.onSynchroniseAttack
        )
    }

    private var isWritable: Bool {
        draft.id.trimmingCharacters(in: .whitespaces).isEmpty == false
            && draft.name.trimmingCharacters(in: .whitespaces).isEmpty == false
    }

    /// Writes this system's own `threat_actor` block. Writing an identifier
    /// that is already there replaces that actor for this system.
    func write() {
        session.setLocalThreatActor(
            id: draft.id,
            name: draft.name,
            description: draft.description,
            aliases: SystemSheetWriting.split(draft.aliases),
            capability: draft.capability,
            intent: draft.intent,
            performs: SystemSheetWriting.split(draft.performs),
            techniques: draft.techniques,
            performsCatalogueTier: draft.catalogueTier.isEmpty ? nil : draft.catalogueTier
        )
        if session.errorMessage == nil { draft = Draft() }
    }

    /// Reads one block into the form, so a person changes it rather than
    /// typing it again.
    private func edit(_ actor: ListedThreatActor) {
        draft = Draft(
            id: actor.id,
            name: actor.name,
            description: actor.description,
            aliases: SystemSheetWriting.joined(actor.aliases),
            capability: actor.capabilityId,
            intent: actor.intent,
            performs: SystemSheetWriting.joined(actor.performsThreatIds),
            techniques: actor.techniques,
            catalogueTier: actor.performsCatalogueTierId ?? Self.noTier
        )
    }
}
