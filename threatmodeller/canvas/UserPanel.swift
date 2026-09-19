import SwiftUI
import ThreatModelKit

/// The editor in the right sidebar, shown while exactly one user is selected.
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
        SelectionEditor(title: "This user", identifier: "user-panel") {
            controls
        }
    }

    @ViewBuilder
    private var controls: some View {
        SelectionField("Name") {
            DeferredTextField(
                title: "Name",
                text: user.customName ?? "",
                identifier: "user-name",
                write: { write(name: $0) }
            )
        }

        SelectionField("Role") {
            DeferredTextField(
                title: "Role",
                text: user.role,
                identifier: "user-role",
                write: { write(role: $0) }
            )
        }

        SelectionField("Access") {
            Picker("Access", selection: access) {
                ForEach(Self.accessLevels, id: \.0) { Text($0.1).tag($0.0) }
            }
            .labelsHidden()
            .accessibilityIdentifier("user-access")
        }

        // The clients the user holds and the components the user reaches
        // are each a set: none, one or many, picked as tokens. The field
        // shows even while the system holds no such component yet, so a
        // person who makes the user first still sees the control, empty.
        SelectionField("Uses") {
            usesField
        }
        SelectionField("Reaches") {
            reachesField
        }

        SelectionField("Threat actor") {
            Picker("Threat actor", selection: threatActor) {
                ForEach(actorChoices, id: \.id) { Text($0.label).tag($0.id) }
            }
            .labelsHidden()
            .accessibilityIdentifier("user-threat-actor")
        }
    }

    /// Every component that is not a user, in canvas order.
    var reachable: [ViewedComponent] {
        session.canvas.components.filter { $0.isUser == false }
    }

    /// The token field choices: every component this user could use or
    /// reach.
    var reachableChoices: [IdTokenField.Choice] {
        reachable.map { IdTokenField.choice(forComponent: $0) }
    }

    /// The field that writes `uses`.
    var usesField: IdTokenField {
        IdTokenField(
            identifier: "user-uses",
            ids: usesBinding,
            choices: reachableChoices,
            emptyMessage: IdTokenField.noComponentMessage
        )
    }

    /// The field that writes `reaches`.
    var reachesField: IdTokenField {
        IdTokenField(
            identifier: "user-reaches",
            ids: reachesBinding,
            choices: reachableChoices,
            emptyMessage: IdTokenField.noComponentMessage
        )
    }

    /// What the picker offers: nobody, then every actor the project holds.
    var actorChoices: [(id: String, label: String)] {
        [(id: Self.noActor, label: "Not a threat actor")]
            + session.threatActorsInUse.map { (id: $0.id, label: $0.name) }
    }

    private var usesBinding: Binding<[String]> {
        Binding(get: { user.uses }, set: { write(uses: $0) })
    }

    private var reachesBinding: Binding<[String]> {
        Binding(get: { user.reaches }, set: { write(reaches: $0) })
    }

    // MARK: writing through

    private func write(
        name newName: String? = nil,
        role newRole: String? = nil,
        access newAccess: String? = nil,
        uses newUses: [String]? = nil,
        reaches newReaches: [String]? = nil,
        threatActorId newActor: String?? = nil
    ) {
        session.setUserProperties(
            componentId: user.id,
            name: newName ?? user.customName,
            role: newRole ?? user.role,
            accessId: newAccess ?? user.runsAsId,
            uses: newUses ?? user.uses,
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
