import SwiftUI
import ThreatModelKit

/// The bar under the canvas, shown while exactly one user is selected.
///
/// Every control writes through `SetUserProperties`, so the `.arch` file
/// holds the `user` block on the next save. The user block design states the
/// block.
struct UserPanel: View {
    let session: ThreatModelSession
    let user: ViewedComponent

    private static let accessLevels = PrivilegeLevel.allCases.map { ($0.rawValue, $0.label) }

    /// The empty id is nobody: the user is not a threat actor.
    static let noActor = ""

    var body: some View {
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
                text: user.customName ?? "",
                width: 200,
                identifier: "user-name",
                commit: { write(name: $0) }
            )

            DeferredTextField(
                title: "Role",
                text: user.role,
                width: 200,
                identifier: "user-role",
                commit: { write(role: $0) }
            )

            Picker("Access", selection: access) {
                ForEach(Self.accessLevels, id: \.0) { Text($0.1).tag($0.0) }
            }
            .labelsHidden()
            .frame(width: 150)
            .accessibilityIdentifier("user-access")

            // The components the user reaches are a multiple choice: none,
            // one or many, and the menu states which.
            if reachable.isEmpty == false {
                Menu {
                    ForEach(reachable, id: \.id) { component in
                        Toggle(component.name, isOn: reaches(component.id))
                    }
                } label: {
                    Text(reachesLabel)
                }
                .frame(width: 200)
                .accessibilityIdentifier("user-reaches")
            }

            Picker("Threat actor", selection: threatActor) {
                ForEach(actorChoices, id: \.id) { Text($0.label).tag($0.id) }
            }
            .labelsHidden()
            .frame(width: 220)
            .accessibilityIdentifier("user-threat-actor")

            Spacer(minLength: 0)
        }
        .padding(.horizontal, CanvasView.windowEdgeMargin)
        .padding(.vertical, 8)
    }

    /// Every component that is not a user, in canvas order.
    var reachable: [ViewedComponent] {
        session.canvas.components.filter { $0.isUser == false }
    }

    /// What the menu reads when it is closed.
    var reachesLabel: String {
        guard user.reaches.isEmpty == false else { return "Reaches nothing" }
        let names = user.reaches.compactMap { id in reachable.first { $0.id == id }?.name }
        return names.count == 1 ? "Reaches \(names[0])" : "Reaches \(names.count) components"
    }

    /// What the picker offers: nobody, then every actor the project holds.
    var actorChoices: [(id: String, label: String)] {
        [(id: Self.noActor, label: "Not a threat actor")]
            + session.threatActorsInUse.map { (id: $0.id, label: $0.name) }
    }

    private func reaches(_ componentId: String) -> Binding<Bool> {
        Binding(
            get: { user.reaches.contains(componentId) },
            set: { wanted in
                var held = user.reaches
                if wanted {
                    if held.contains(componentId) == false { held.append(componentId) }
                } else {
                    held.removeAll { $0 == componentId }
                }
                write(reaches: held)
            }
        )
    }

    // MARK: writing through

    private func write(
        name newName: String? = nil,
        role newRole: String? = nil,
        access newAccess: String? = nil,
        reaches newReaches: [String]? = nil,
        threatActorId newActor: String?? = nil
    ) {
        session.setUserProperties(
            componentId: user.id,
            name: newName ?? user.customName,
            role: newRole ?? user.role,
            accessId: newAccess ?? user.runsAsId,
            reaches: newReaches ?? user.reaches,
            threatActorId: newActor ?? user.threatActorId
        )
    }

    /// What the Role field writes.
    func commitRole(_ text: String) { write(role: text) }

    /// What the Access picker reads and writes.
    var access: Binding<String> {
        Binding(get: { user.runsAsId }, set: { write(access: $0) })
    }

    /// What the Threat actor picker reads and writes. The empty id is nobody.
    var threatActor: Binding<String> {
        Binding(
            get: { user.threatActorId ?? Self.noActor },
            set: { write(threatActorId: .some($0.isEmpty ? nil : $0)) }
        )
    }
}
