import SwiftUI
import ThreatModelKit

/// The bar under the canvas, shown while exactly one node is selected.
///
/// Every control writes through `SetComponentProperties` and the threat list
/// rescores, so the user sees what a sensitivity costs as they change it.
struct ComponentPanel: View {
    let session: ThreatModelSession
    let component: ViewedComponent

    /// The empty tag is Auto: the derivation decides.
    private static let shapes = [
        ("", "Auto"),
        ("actor", "Actor"),
        ("process", "Process"),
        ("store", "Store")
    ]

    private static let privileges = [
        ("user", "User"),
        ("admin", "Administrator"),
        ("root", "Root"),
        ("system", "System"),
        ("kernel", "Kernel")
    ]

    var body: some View {
        // The controls scroll sideways. Their widths are fixed and they need
        // 982 points; the canvas column can be 400. Without the scroll the
        // row reflowed and the bar grew to 208 points, taking that height
        // from the diagram above it.
        ScrollView(.horizontal) {
            controls
        }
        .scrollIndicators(.never)
        .background(.bar)
    }

    private var controls: some View {
        HStack(alignment: .center, spacing: 16) {
            DeferredTextField(
                title: "Name",
                text: component.customName ?? "",
                width: 200,
                identifier: "component-name",
                commit: { write(name: $0) }
            )

            // A component drawn with the wrong technology is changed here
            // rather than deleted and drawn again, which used to lose its
            // name, its place, its flows and every answer on it.
            Picker("Technology", selection: technology) {
                ForEach(session.technologyChoices, id: \.provider) { group in
                    Section(group.provider) {
                        ForEach(group.technologies, id: \.id) { Text($0.label).tag($0.id) }
                    }
                }
            }
            .labelsHidden()
            .frame(width: 200)
            .accessibilityIdentifier("component-technology")

            Picker("Shape", selection: shape) {
                ForEach(Self.shapes, id: \.0) { Text(label(forShape: $0.0, $0.1)).tag($0.0) }
            }
            .labelsHidden()
            .frame(width: 170)
            .accessibilityIdentifier("component-shape")

            Picker("Sensitivity", selection: sensitivity) {
                ForEach(session.classificationChoices, id: \.id) {
                    Text($0.label).tag($0.id)
                }
            }
            .labelsHidden()
            .frame(width: 160)
            .accessibilityIdentifier("component-sensitivity")

            Picker("Runs as", selection: runsAs) {
                ForEach(Self.privileges, id: \.0) { Text($0.1).tag($0.0) }
            }
            .labelsHidden()
            .frame(width: 150)
            .accessibilityIdentifier("component-runs-as")

            // The assets a system declares are a multiple choice: a component
            // holds none, one or many, and the menu states which.
            if session.canvas.systemAssets.isEmpty == false {
                Menu {
                    ForEach(session.canvas.systemAssets, id: \.id) { asset in
                        Toggle(asset.name, isOn: holds(asset.id))
                    }
                } label: {
                    Text(heldLabel)
                }
                .frame(width: 200)
                .accessibilityIdentifier("component-holds")
            }

            // A component another company runs states which one. The picker
            // is only there when the system declares a third party, so a
            // model with none keeps the bar at the width it had.
            if session.canvas.thirdParties.isEmpty == false {
                Picker("Provided by", selection: provider) {
                    ForEach(providerChoices, id: \.id) { Text($0.label).tag($0.id) }
                }
                .labelsHidden()
                .frame(width: 200)
                .accessibilityIdentifier("component-provided-by")
            }

            Toggle("Raise threats", isOn: threatsRaised)
                .toggleStyle(.switch)
                .accessibilityIdentifier("component-threats-raised")

            Spacer(minLength: 0)
        }
        .padding(.horizontal, CanvasView.windowEdgeMargin)
        .padding(.vertical, 8)
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
        holds newHolds: [String]? = nil
    ) {
        let picked = newShape ?? component.shapeOverrideId ?? ""

        session.setComponentProperties(
            componentId: component.id,
            name: newName ?? component.customName,
            sensitivityId: newSensitivity ?? component.sensitivityId,
            threatsDisabled: newThreatsDisabled ?? component.threatsDisabled,
            runsAsId: newRunsAs ?? component.runsAsId,
            shapeId: picked.isEmpty ? nil : picked,
            holds: newHolds
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

    private var shape: Binding<String> {
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
