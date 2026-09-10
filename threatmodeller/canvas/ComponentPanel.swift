import SwiftUI
import ThreatModelKit

/// The bar under the canvas, shown while exactly one node is selected.
///
/// Every control writes through `SetComponentProperties` and the threat list
/// rescores, so the user sees what a sensitivity costs as they change it.
struct ComponentPanel: View {
    let session: ThreatModelSession
    let component: ViewedComponent

    private static let sensitivities = [
        ("public", "Public"),
        ("internal", "Internal"),
        ("confidential", "Confidential"),
        ("restricted", "Restricted")
    ]

    private static let privileges = [
        ("user", "User"),
        ("admin", "Administrator"),
        ("root", "Root"),
        ("system", "System"),
        ("kernel", "Kernel")
    ]

    var body: some View {
        HStack(alignment: .center, spacing: 16) {
            TextField("Name", text: name)
                .textFieldStyle(.roundedBorder)
                .frame(width: 200)
                .accessibilityIdentifier("component-name")

            Picker("Sensitivity", selection: sensitivity) {
                ForEach(Self.sensitivities, id: \.0) { Text($0.1).tag($0.0) }
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

            Toggle("Raise threats", isOn: threatsRaised)
                .toggleStyle(.switch)
                .accessibilityIdentifier("component-threats-raised")

            Spacer(minLength: 0)

            Text(component.technologyId)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
    }

    // MARK: writing through

    private func write(
        name newName: String? = nil,
        sensitivity newSensitivity: String? = nil,
        threatsDisabled newThreatsDisabled: Bool? = nil,
        runsAs newRunsAs: String? = nil
    ) {
        session.setComponentProperties(
            componentId: component.id,
            name: newName ?? component.customName,
            sensitivityId: newSensitivity ?? component.sensitivityId,
            threatsDisabled: newThreatsDisabled ?? component.threatsDisabled,
            runsAsId: newRunsAs ?? component.runsAsId
        )
    }

    private var name: Binding<String> {
        Binding(get: { component.customName ?? "" }, set: { write(name: $0) })
    }

    private var sensitivity: Binding<String> {
        Binding(get: { component.sensitivityId }, set: { write(sensitivity: $0) })
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
