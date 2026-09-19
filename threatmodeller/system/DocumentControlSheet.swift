import SwiftUI
import ThreatModelKit

/// What the document states about itself: who owns it, what the system is, who
/// wrote it, which version it is, when it was written and when it was last read
/// again.
///
/// The report builds its document-control table from these attributes, and the
/// policy rule `system_requires_owner` reads the owner. Every named field
/// writes one change when the edit ends, so the sheet never holds a copy of the
/// model that can fall behind it. The write button writes one free `attribute`
/// block, which is the one part of this sheet that holds a list.
struct DocumentControlSheet: View {
    let session: ThreatModelSession
    let dismiss: () -> Void

    /// The fields of one free `attribute` block, as a person edits them.
    struct Draft: Equatable {
        var name = ""
        var value = ""
    }

    @State private var draft: Draft
    /// The name of the attribute a person opened with Edit, or nil while the
    /// form writes a new one.
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

    private var facts: ViewedSystemFacts { session.canvas.systemFacts }

    var body: some View {
        SystemSheet(
            kind: .documentControl,
            says: "What this document states about itself. Each named field writes when you "
                + "leave it. The button writes one more line the language does not name.",
            fileName: session.architectureFileName,
            isWritable: SystemSheetWriting.states(draft.name),
            isEditing: editing != nil,
            dismiss: dismiss,
            write: write
        ) {
            Text("Anything else this document states")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)

            if facts.attributes.isEmpty {
                SystemSheetEmptyNote(
                    says: "The document states nothing the language does not name."
                )
            } else {
                ForEach(facts.attributes, id: \.name) { attribute in
                    SystemSheetRow(
                        identifier: "system-attribute-\(attribute.name)",
                        edit: { read(attribute) },
                        remove: { remove(attribute) }
                    ) {
                        Text(attribute.name)
                            .font(.callout.weight(.semibold))
                        Text(attribute.value)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        } form: {
            namedFields

            Divider()

            Text("One more line the language does not name")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            TextField("Name", text: $draft.name)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("system-attribute-name")
            TextField("Value", text: $draft.value)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("system-attribute-value")
        }
    }

    /// The fields the language names. Each writes one change when the edit
    /// ends, the way the architecture sidebar wrote them.
    @ViewBuilder
    private var namedFields: some View {
        DeferredTextField(
            title: "Owner",
            text: facts.owner,
            identifier: "system-owner",
            write: { session.setSystemFacts(owner: $0) }
        )

        DeferredTextField(
            title: "What this system is",
            text: facts.description,
            identifier: "system-description",
            lines: 2 ... 4,
            write: { session.setSystemFacts(description: $0) }
        )

        DeferredTextField(
            title: "Authors, separated by commas",
            text: SystemSheetWriting.joined(facts.authors),
            identifier: "system-authors",
            write: { session.setSystemFacts(authors: SystemSheetWriting.split($0)) }
        )

        DeferredTextField(
            title: "Version",
            text: facts.version,
            identifier: "system-version",
            write: { session.setSystemFacts(version: $0) }
        )

        SystemDateField(
            title: "Created",
            date: facts.created,
            identifier: "system-created",
            commit: { session.setSystemFacts(created: $0) }
        )

        SystemDateField(
            title: "Reviewed",
            date: facts.reviewed,
            identifier: "system-reviewed",
            commit: { session.setSystemFacts(reviewed: $0) }
        )

        DeferredTextField(
            title: "Links, separated by commas",
            text: SystemSheetWriting.joined(facts.links),
            identifier: "system-links",
            write: { session.setSystemFacts(links: SystemSheetWriting.split($0)) }
        )

        DeferredTextField(
            title: "Repositories, separated by commas",
            text: SystemSheetWriting.joined(facts.repositories),
            identifier: "system-repositories",
            write: { session.setSystemFacts(repositories: SystemSheetWriting.split($0)) }
        )
    }

    func write() {
        session.setSystemAttribute(
            name: draft.name.trimmingCharacters(in: .whitespaces),
            value: draft.value.trimmingCharacters(in: .whitespaces)
        )
        if session.errorMessage == nil { startANewOne() }
    }

    private func read(_ attribute: ViewedSystemAttribute) {
        editing = attribute.name
        draft = Draft(name: attribute.name, value: attribute.value)
    }

    private func remove(_ attribute: ViewedSystemAttribute) {
        if editing == attribute.name { startANewOne() }
        session.removeSystemAttribute(name: attribute.name)
    }

    private func startANewOne() {
        editing = nil
        draft = Draft()
    }
}
