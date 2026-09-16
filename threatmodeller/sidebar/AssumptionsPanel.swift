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
    @State private var partyId = ""
    @State private var partyName = ""
    @State private var partyDescription = ""
    @State private var partyKind = ThirdPartyKind.saas.rawValue
    @State private var partyPays = false
    @State private var partyUptime = UptimeDependency.none.rawValue
    @State private var partyUptimeNotes = ""
    @State private var partyOwner = ""
    @State private var partyLink = ""
    @State private var attributeName = ""
    @State private var attributeValue = ""
    @State private var diagramLabel = ""
    @State private var diagramText = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                systemFacts
                riskTolerance

                Divider()
                systemDiagrams

                Divider()
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
                thirdParties

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

    /// The risk level a likelihood finding may answer up to. A system that
    /// states none reads as Low, the same default `threatmodeller check`
    /// uses, so the picker never shows a level the file does not back.
    private var riskTolerance: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Risk tolerance")
                .font(.subheadline.weight(.semibold))
            Text("The level a likelihood finding may bring a threat down to.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Picker("Risk tolerance", selection: riskToleranceBinding) {
                ForEach(RiskLevel.allCases, id: \.rawValue) { level in
                    Text(level.label).tag(level.rawValue)
                }
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .accessibilityIdentifier("risk-tolerance")
        }
    }

    private var riskToleranceBinding: Binding<String> {
        Binding(
            get: { session.canvas.riskTolerance },
            set: { session.setRiskTolerance($0) }
        )
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

    /// What the document states about itself: who owns it, what the system is,
    /// who wrote it, which version it is, when it was written and when it was
    /// last read again.
    ///
    /// The report builds its document-control table from these attributes, and
    /// the policy rule `system_requires_owner` reads the owner. Every field
    /// writes one change when the edit ends, so the panel needs no Save button
    /// and never holds a copy of the model that can fall behind it.
    private var systemFacts: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("What this document states about itself")
                .font(.subheadline.weight(.semibold))

            DeferredTextField(
                title: "Owner",
                text: session.canvas.systemFacts.owner,
                identifier: "system-owner",
                commit: { session.setSystemFacts(owner: $0) }
            )

            DeferredTextField(
                title: "What this system is",
                text: session.canvas.systemFacts.description,
                identifier: "system-description",
                lines: 2 ... 4,
                commit: { session.setSystemFacts(description: $0) }
            )

            DeferredTextField(
                title: "Authors, separated by commas",
                text: Self.joined(session.canvas.systemFacts.authors),
                identifier: "system-authors",
                commit: { session.setSystemFacts(authors: Self.split($0)) }
            )

            DeferredTextField(
                title: "Version",
                text: session.canvas.systemFacts.version,
                identifier: "system-version",
                commit: { session.setSystemFacts(version: $0) }
            )

            SystemDateField(
                title: "Created",
                date: session.canvas.systemFacts.created,
                identifier: "system-created",
                commit: { session.setSystemFacts(created: $0) }
            )

            SystemDateField(
                title: "Reviewed",
                date: session.canvas.systemFacts.reviewed,
                identifier: "system-reviewed",
                commit: { session.setSystemFacts(reviewed: $0) }
            )

            DeferredTextField(
                title: "Links, separated by commas",
                text: Self.joined(session.canvas.systemFacts.links),
                identifier: "system-links",
                commit: { session.setSystemFacts(links: Self.split($0)) }
            )

            DeferredTextField(
                title: "Repositories, separated by commas",
                text: Self.joined(session.canvas.systemFacts.repositories),
                identifier: "system-repositories",
                commit: { session.setSystemFacts(repositories: Self.split($0)) }
            )

            systemAttributes
        }
    }

    /// What the team states that the language does not name. One `attribute`
    /// block each.
    private var systemAttributes: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Anything else this document states")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)

            ForEach(session.canvas.systemFacts.attributes, id: \.name) { attribute in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text("\(attribute.name): \(attribute.value)")
                        .font(.caption)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 4)
                    Button {
                        attributeName = attribute.name
                        attributeValue = attribute.value
                    } label: {
                        Image(systemName: "pencil")
                    }
                    .buttonStyle(.borderless)
                    .accessibilityIdentifier("edit-system-attribute-\(attribute.name)")
                    Button {
                        session.removeSystemAttribute(name: attribute.name)
                    } label: {
                        Image(systemName: "trash")
                    }
                    .buttonStyle(.borderless)
                    .accessibilityIdentifier("remove-system-attribute-\(attribute.name)")
                }
            }

            HStack(spacing: 6) {
                TextField("Name", text: $attributeName)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("system-attribute-name")
                TextField("Value", text: $attributeValue)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("system-attribute-value")
                Button("Add", action: writeAttribute)
                    .disabled(attributeName.trimmingCharacters(in: .whitespaces).isEmpty)
                    .accessibilityIdentifier("add-system-attribute")
            }
        }
    }

    private func writeAttribute() {
        session.setSystemAttribute(
            name: attributeName.trimmingCharacters(in: .whitespaces),
            value: attributeValue.trimmingCharacters(in: .whitespaces)
        )
        attributeName = ""
        attributeValue = ""
    }

    /// The pictures a team keeps beside the diagram the canvas draws. A
    /// sequence diagram of a login, or a deployment diagram, says something
    /// the data-flow diagram cannot.
    private var systemDiagrams: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Pictures this system keeps beside its diagram")
                .font(.subheadline.weight(.semibold))

            if session.canvas.diagrams.isEmpty {
                Text("No diagram is written. A report shows only the diagram the canvas draws.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(session.canvas.diagrams, id: \.label) { diagram in
                    diagramRow(diagram)
                }
            }

            TextField("Label", text: $diagramLabel)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("diagram-label")
            TextField("Mermaid text", text: $diagramText, axis: .vertical)
                .lineLimit(4 ... 8)
                .textFieldStyle(.roundedBorder)
                .font(.system(.body, design: .monospaced))
                .accessibilityIdentifier("diagram-text")
            Button("Add", action: writeDiagram)
                .disabled(isWritable(diagramLabel, diagramText) == false)
                .accessibilityIdentifier("add-diagram")
        }
    }

    private func diagramRow(_ diagram: ViewedSystemDiagram) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(diagram.label)
                    .font(.callout.weight(.semibold))
                Spacer(minLength: 4)
                Button {
                    diagramLabel = diagram.label
                    diagramText = diagram.text
                } label: {
                    Image(systemName: "pencil")
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("edit-diagram-\(diagram.label)")
                Button {
                    session.removeSystemDiagram(label: diagram.label)
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("remove-diagram-\(diagram.label)")
            }
            Text(diagram.text)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .lineLimit(4)
        }
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .controlBackgroundColor)))
    }

    /// The form writes a new diagram, and writing a label that is already
    /// there changes that diagram. The pencil fills the form in, so a person
    /// edits what is written rather than typing it again.
    private func writeDiagram() {
        session.setSystemDiagram(
            label: diagramLabel.trimmingCharacters(in: .whitespaces),
            text: diagramText.trimmingCharacters(in: .whitespaces)
        )
        diagramLabel = ""
        diagramText = ""
    }

    /// One list, as one line a person edits.
    static func joined(_ items: [String]) -> String {
        items.joined(separator: ", ")
    }

    /// The items of one such line, without the whitespace around each and
    /// without the items that hold nothing.
    static func split(_ text: String) -> [String] {
        text.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0.isEmpty == false }
    }

    /// The parties outside this team the system depends on. A component
    /// states which party provides it, so the vendor is written once and read
    /// wherever the component goes.
    private var thirdParties: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Who outside this team this system depends on")
                .font(.subheadline.weight(.semibold))

            if session.canvas.thirdParties.isEmpty {
                Text("No third party is named. A reader cannot tell which part of this system another company runs.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(session.canvas.thirdParties, id: \.id) { party in
                    thirdPartyRow(party)
                }
            }

            writeThirdParty
        }
    }

    private func thirdPartyRow(_ party: ViewedThirdParty) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(party.name)
                    .font(.callout.weight(.semibold))
                Spacer(minLength: 4)
                Button {
                    edit(party)
                } label: {
                    Image(systemName: "pencil")
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("edit-third-party-\(party.id)")
                Button {
                    session.removeThirdParty(id: party.id)
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("remove-third-party-\(party.id)")
            }
            Text("\(party.kindLabel) \u{00B7} \(party.payingCustomer ? "The team pays" : "The team does not pay")")
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
            if party.uptimeNotes.isEmpty == false {
                Text(party.uptimeNotes)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let owner = party.owner {
                Text("Owner: \(owner)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            if let link = party.link {
                Text(link)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .controlBackgroundColor)))
    }

    /// The form writes a new party, and writing an id that is already there
    /// changes that party. The pencil fills the form in, so a person edits
    /// what is written rather than typing it again.
    private var writeThirdParty: some View {
        VStack(alignment: .leading, spacing: 6) {
            TextField("Identifier", text: $partyId)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("third-party-id")
            TextField("Name", text: $partyName)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("third-party-name")
            TextField("What it provides", text: $partyDescription, axis: .vertical)
                .lineLimit(2 ... 4)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("third-party-description")

            HStack(spacing: 6) {
                Picker("Kind", selection: $partyKind) {
                    ForEach(ThirdPartyKind.allCases, id: \.rawValue) {
                        Text($0.label).tag($0.rawValue)
                    }
                }
                .labelsHidden()
                .accessibilityIdentifier("third-party-kind")

                Picker("Uptime", selection: $partyUptime) {
                    ForEach(UptimeDependency.allCases, id: \.rawValue) {
                        Text($0.label).tag($0.rawValue)
                    }
                }
                .labelsHidden()
                .accessibilityIdentifier("third-party-uptime")
            }

            Toggle("The team pays this party", isOn: $partyPays)
                .font(.caption)
                .accessibilityIdentifier("third-party-paying-customer")

            TextField("What happens when it stops", text: $partyUptimeNotes, axis: .vertical)
                .lineLimit(2 ... 4)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("third-party-uptime-notes")

            HStack(spacing: 6) {
                TextField("Owner (optional)", text: $partyOwner)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("third-party-owner")

                TextField("Link (optional)", text: $partyLink)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("third-party-link")

                Button("Add", action: writeParty)
                    .disabled(isWritableThirdParty == false)
                    .accessibilityIdentifier("add-third-party")
            }
        }
    }

    private var isWritableThirdParty: Bool {
        isWritable(partyId, partyName)
    }

    private func edit(_ party: ViewedThirdParty) {
        partyId = party.id
        partyName = party.name
        partyDescription = party.description
        partyKind = party.kindId
        partyPays = party.payingCustomer
        partyUptime = party.uptimeId
        partyUptimeNotes = party.uptimeNotes
        partyOwner = party.owner ?? ""
        partyLink = party.link ?? ""
    }

    private func writeParty() {
        let owner = partyOwner.trimmingCharacters(in: .whitespaces)
        let link = partyLink.trimmingCharacters(in: .whitespaces)
        session.setThirdParty(
            id: partyId.trimmingCharacters(in: .whitespaces),
            name: partyName.trimmingCharacters(in: .whitespaces),
            description: partyDescription.trimmingCharacters(in: .whitespaces),
            kindId: partyKind,
            payingCustomer: partyPays,
            uptimeId: partyUptime,
            uptimeNotes: partyUptimeNotes.trimmingCharacters(in: .whitespaces),
            owner: owner.isEmpty ? nil : owner,
            link: link.isEmpty ? nil : link
        )
        partyId = ""
        partyName = ""
        partyDescription = ""
        partyKind = ThirdPartyKind.saas.rawValue
        partyPays = false
        partyUptime = UptimeDependency.none.rawValue
        partyUptimeNotes = ""
        partyOwner = ""
        partyLink = ""
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
