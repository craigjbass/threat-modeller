import SwiftUI
import ThreatModelKit

/// The editor in the right sidebar, shown while exactly one node is selected.
///
/// Every control writes through `SetComponentProperties` and the threat list
/// rescores, so the user sees what a sensitivity costs as they change it.
struct ComponentPanel: View {
    let session: ThreatModelSession
    /// Focus writes here, not through `session`, so a click that narrows the
    /// canvas to this component writes no file. Defaults to an unused state
    /// for the tests that read this panel and never open Focus.
    var canvas: CanvasState = CanvasState()
    let component: ViewedComponent

    /// The empty tag is Auto: the derivation decides.
    private static let shapes = [
        ("", "Auto"),
        ("actor", "Actor"),
        ("process", "Process"),
        ("store", "Store")
    ]

    /// What a component states about itself: deployed to Production, or
    /// planned and not deployed.
    private static let statuses = [
        ("live", "Live"),
        ("proposed", "Proposed")
    ]

    /// The draft asset the person is typing: its name and its
    /// classification. The Add button writes it and clears the name.
    @State private var assetName = ""
    @State private var assetClassification = ""

    private static let privileges = [
        ("user", "User"),
        ("admin", "Administrator"),
        ("root", "Root"),
        ("system", "System"),
        ("kernel", "Kernel")
    ]

    var body: some View {
        SelectionEditor(title: "This component", identifier: "component-panel") {
            controls
        }
    }

    @ViewBuilder
    private var controls: some View {
        SelectionField("Name") {
            DeferredTextField(
                title: "Name",
                text: component.customName ?? "",
                identifier: "component-name",
                commit: { write(name: $0) }
            )
        }

        // A component drawn with the wrong technology is changed here
        // rather than deleted and drawn again, which used to lose its
        // name, its place, its flows and every answer on it.
        SelectionField("Technology") {
            Picker("Technology", selection: technology) {
                ForEach(session.technologyChoices, id: \.provider) { group in
                    Section(group.provider) {
                        ForEach(group.technologies, id: \.id) { Text($0.label).tag($0.id) }
                    }
                }
            }
            .labelsHidden()
            .accessibilityIdentifier("component-technology")
        }

        SelectionField("Shape") {
            Picker("Shape", selection: shape) {
                ForEach(Self.shapes, id: \.0) { Text(label(forShape: $0.0, $0.1)).tag($0.0) }
            }
            .labelsHidden()
            .accessibilityIdentifier("component-shape")
        }

        // A model of a planned change draws both kinds on one canvas.
        // The canvas draws a proposed component with a broken outline.
        SelectionField("Status") {
            Picker("Status", selection: status) {
                ForEach(Self.statuses, id: \.0) { Text($0.1).tag($0.0) }
            }
            .labelsHidden()
            .accessibilityIdentifier("component-status")
        }

        SelectionField("Sensitivity") {
            Picker("Sensitivity", selection: sensitivity) {
                ForEach(session.classificationChoices, id: \.id) {
                    Text($0.label).tag($0.id)
                }
            }
            .labelsHidden()
            .accessibilityIdentifier("component-sensitivity")
        }

        SelectionField("Runs as") {
            Picker("Runs as", selection: runsAs) {
                ForEach(Self.privileges, id: \.0) { Text($0.1).tag($0.0) }
            }
            .labelsHidden()
            .accessibilityIdentifier("component-runs-as")
        }

        // The assets a system declares are a multiple choice: a component
        // holds none, one or many, and the menu states which.
        if session.canvas.systemAssets.isEmpty == false {
            SelectionField("Holds") {
                Menu {
                    ForEach(session.canvas.systemAssets, id: \.id) { asset in
                        Toggle(asset.name, isOn: holds(asset.id))
                    }
                } label: {
                    Text(heldLabel)
                }
                .accessibilityIdentifier("component-holds")
            }
        }

        // A component may hold things of value of its own, named here
        // rather than on the system. The component scores at the highest of
        // its own classification and every asset it states.
        SelectionField("Assets of its own") {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(component.assets, id: \.name) { asset in
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text(asset.name)
                            .font(.callout)
                        Text(label(ofClassification: asset.classificationId))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer(minLength: 4)
                        Button {
                            removeAsset(name: asset.name)
                        } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityIdentifier("remove-component-asset-\(asset.name)")
                    }
                }

                TextField("Name", text: $assetName)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("component-asset-name")

                Picker("Classification", selection: $assetClassification) {
                    ForEach(session.classificationChoices, id: \.id) {
                        Text($0.label).tag($0.id)
                    }
                }
                .labelsHidden()
                .accessibilityIdentifier("component-asset-data")

                Button("Add") {
                    addAsset(name: assetName, classificationId: assetClassification)
                    assetName = ""
                }
                .disabled(canAddAsset(named: assetName) == false)
                .accessibilityIdentifier("add-component-asset")
            }
        }

        // A component another company runs states which one. The picker
        // is only there when the system declares a third party, so a
        // model with none keeps the editor at the rows it had.
        if session.canvas.thirdParties.isEmpty == false {
            SelectionField("Provided by") {
                Picker("Provided by", selection: provider) {
                    ForEach(providerChoices, id: \.id) { Text($0.label).tag($0.id) }
                }
                .labelsHidden()
                .accessibilityIdentifier("component-provided-by")
            }
        }

        // The tags a component is filed under, as one line. The canvas
        // tag filter draws the view a tag names.
        SelectionField("Tags") {
            DeferredTextField(
                title: "Tags",
                text: tagsText,
                identifier: "component-tags",
                commit: { commitTags($0) }
            )
        }

        // The version the component runs and the CVEs that version
        // carries. A known exploited CVE raises every threat on the
        // component; the threat card names each one.
        SelectionField("Version") {
            DeferredTextField(
                title: "Version",
                text: component.version,
                identifier: "component-version",
                commit: { commitVersion($0) }
            )
        }

        SelectionField("CVEs") {
            DeferredTextField(
                title: "CVEs",
                text: cvesText,
                identifier: "component-cves",
                commit: { commitCves($0) }
            )
        }

        Divider()

        Toggle("Raise threats", isOn: threatsRaised)
            .toggleStyle(.switch)
            .accessibilityIdentifier("component-threats-raised")

        Button("Focus") { canvas.focus(componentId: component.id) }
            .accessibilityIdentifier("component-focus")
    }

    /// True while the name field holds a word. An asset needs a name, so the
    /// Add button waits for one.
    func canAddAsset(named name: String) -> Bool {
        name.trimmingCharacters(in: .whitespaces).isEmpty == false
    }

    /// Writes one asset the component states on itself. Writing a name that
    /// is already there changes the classification of that asset.
    func addAsset(name: String, classificationId: String) {
        session.setComponentAsset(
            componentId: component.id,
            name: name.trimmingCharacters(in: .whitespaces),
            classificationId: classificationId.isEmpty
                ? (session.classificationChoices.first?.id ?? "internal")
                : classificationId
        )
    }

    /// Takes one asset off the component.
    func removeAsset(name: String) {
        session.removeComponentAsset(componentId: component.id, name: name)
    }

    /// What a classification id is called in this project's scheme.
    private func label(ofClassification id: String) -> String {
        session.classificationChoices.first { $0.id == id }?.label ?? id
    }

    /// The line the tag field shows: every tag the component holds, separated
    /// by commas.
    var tagsText: String { TagFilter.text(from: component.tags) }

    /// Writes what a person typed in the tag field. An empty line takes every
    /// tag off the component.
    func commitTags(_ text: String) {
        write(tags: TagFilter.tags(from: text))
    }

    /// The line the CVEs field shows: every CVE id the component states,
    /// separated by commas.
    var cvesText: String { TagFilter.text(from: component.cves) }

    /// Writes what a person typed in the version field. An empty field takes
    /// the version off the component.
    func commitVersion(_ text: String) {
        write(version: text)
    }

    /// Writes what a person typed in the CVEs field. A word that is not a CVE
    /// id is refused whole, and the session says which word.
    func commitCves(_ text: String) {
        write(cves: TagFilter.tags(from: text))
    }

    /// What the menu reads when it is closed.
    private var heldLabel: String {
        guard component.holds.isEmpty == false else { return "Holds nothing" }
        let names = component.holds.compactMap { id in
            session.canvas.systemAssets.first { $0.id == id }?.name
        }
        return names.count == 1 ? "Holds \(names[0])" : "Holds \(names.count) assets"
    }

    /// What the picker offers: nobody, then every third party the system
    /// declares. The empty id is nobody.
    var providerChoices: [(id: String, label: String)] {
        [(id: "", label: "Provided by nobody")]
            + session.canvas.thirdParties.map { (id: $0.id, label: $0.name) }
    }

    private var provider: Binding<String> {
        Binding(
            get: { component.providedById ?? "" },
            set: { picked in
                session.setComponentProvider(
                    componentId: component.id,
                    thirdPartyId: picked.isEmpty ? nil : picked
                )
            }
        )
    }

    private func holds(_ assetId: String) -> Binding<Bool> {
        Binding(
            get: { component.holds.contains(assetId) },
            set: { wanted in
                var held = component.holds
                if wanted {
                    if held.contains(assetId) == false { held.append(assetId) }
                } else {
                    held.removeAll { $0 == assetId }
                }
                write(holds: held)
            }
        )
    }

    // MARK: writing through

    private func write(
        name newName: String? = nil,
        sensitivity newSensitivity: String? = nil,
        threatsDisabled newThreatsDisabled: Bool? = nil,
        runsAs newRunsAs: String? = nil,
        shape newShape: String? = nil,
        holds newHolds: [String]? = nil,
        tags newTags: [String]? = nil,
        status newStatus: String? = nil,
        version newVersion: String? = nil,
        cves newCves: [String]? = nil
    ) {
        let picked = newShape ?? component.shapeOverrideId ?? ""

        session.setComponentProperties(
            componentId: component.id,
            name: newName ?? component.customName,
            sensitivityId: newSensitivity ?? component.sensitivityId,
            threatsDisabled: newThreatsDisabled ?? component.threatsDisabled,
            runsAsId: newRunsAs ?? component.runsAsId,
            shapeId: picked.isEmpty ? nil : picked,
            holds: newHolds,
            tags: newTags,
            status: newStatus,
            version: newVersion,
            cves: newCves
        )
    }

    /// Auto states what the derivation currently gives, so a user who forces
    /// that same value sees no change and knows it.
    private func label(forShape id: String, _ name: String) -> String {
        guard id.isEmpty else { return name }
        let derived = DiagramShape(rawValue: component.shapeId)?.label ?? component.shapeId
        return "Auto \u{2014} \(derived)"
    }


    private var technology: Binding<String> {
        Binding(
            get: { component.technologyId },
            set: { session.changeTechnology(componentId: component.id, technologyId: $0) }
        )
    }

    private var sensitivity: Binding<String> {
        Binding(get: { component.sensitivityId }, set: { write(sensitivity: $0) })
    }

    /// What the Status picker reads and writes.
    var status: Binding<String> {
        Binding(get: { component.statusId }, set: { write(status: $0) })
    }

    /// What the Shape picker reads and writes. The empty word is Auto.
    var shape: Binding<String> {
        Binding(
            get: { component.shapeOverrideId ?? "" },
            set: { write(shape: $0) }
        )
    }

    private var runsAs: Binding<String> {
        Binding(get: { component.runsAsId }, set: { write(runsAs: $0) })
    }

    /// The switch reads the other way round from the model: a user turns
    /// threats on, not off.
    private var threatsRaised: Binding<Bool> {
        Binding(
            get: { component.threatsDisabled == false },
            set: { write(threatsDisabled: $0 == false) }
        )
    }
}
