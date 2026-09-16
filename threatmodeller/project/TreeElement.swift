import CoreGraphics
import ThreatModelKit

/// One element the `.arch` file states, offered beside the tree canvas with
/// the threats the model raises on it.
struct TreeElement: Identifiable, Equatable {
    /// `component`, `zone` or `flow` — the kinds the tree language states.
    let kind: String
    let sourceId: String
    let name: String
    let threats: [AssessedThreat]

    var id: String { payload }
    /// What a drag from the list carries.
    var payload: String { "\(kind):\(sourceId)" }

    /// Every element the model states, with the threats raised on it, in the
    /// order the canvas holds them: components, flows, zones.
    static func list(
        threats: [AssessedThreat],
        components: [ViewedComponent],
        connections: [ViewedConnection],
        zones: [ViewedZone]
    ) -> [TreeElement] {
        func raised(_ kind: String, _ id: String) -> [AssessedThreat] {
            threats.filter { threat in
                switch threat.source {
                case .component(let componentId, _, _):
                    kind == "component" && componentId == id
                case .connection(let connectionId, _, _):
                    kind == "flow" && connectionId == id
                case .zone(let zoneId, _):
                    kind == "zone" && zoneId == id
                }
            }
        }
        func componentName(_ id: String) -> String {
            components.first { $0.id == id }?.name ?? id
        }
        var rows = components.map {
            TreeElement(
                kind: "component", sourceId: $0.id, name: $0.name,
                threats: raised("component", $0.id)
            )
        }
        rows += connections.map {
            TreeElement(
                kind: "flow", sourceId: $0.id,
                name: "\(componentName($0.sourceComponentId)) \u{2192} "
                    + componentName($0.targetComponentId),
                threats: raised("flow", $0.id)
            )
        }
        rows += zones.map {
            TreeElement(kind: "zone", sourceId: $0.id, name: $0.name, threats: raised("zone", $0.id))
        }
        return rows
    }
}

/// An element dropped on the canvas that has not picked a threat yet. It is
/// not written, and it cannot be joined. The point is where it was dropped,
/// in model coordinates.
struct PendingElement: Identifiable, Equatable {
    let id: String
    let element: TreeElement
    let point: CGPoint
}
