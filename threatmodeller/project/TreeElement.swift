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
    /// The payloads of the elements an attacker at this element reaches,
    /// read from the flows and the zones. The design in
    /// `docs/superpowers/specs/2026-09-16-tree-connectable-elements-design.md`
    /// states the rule; this element is among them.
    var neighbours: Set<String> = []
    /// The names of the users that hold this element as a client, in model
    /// order. Empty for every element no user holds.
    var heldBy: [String] = []

    var id: String { payload }
    /// What a drag from the list carries.
    var payload: String { "\(kind):\(sourceId)" }

    /// What a drag of the **Any element** row carries: a box with no element.
    static let boxPayload = "placeholder"

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
        // A use link is no row: the tree language names components, flows
        // and zones, and the link from a user to a client is none of those.
        // It still joins the two for the adjacency below.
        rows += connections.filter { $0.isUse == false }.map {
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
        let reach = neighbours(components: components, connections: connections, zones: zones)
        let holders = Dictionary(
            connections.filter { $0.isUse && $0.isReach == false }
                .map { ($0.targetComponentId, [componentName($0.sourceComponentId)]) },
            uniquingKeysWith: +
        )
        return rows.map { row in
            var row = row
            row.neighbours = reach[row.payload] ?? [row.payload]
            if row.kind == "component" { row.heldBy = holders[row.sourceId] ?? [] }
            return row
        }
    }

    /// What an attacker at each element reaches, by payload. A component
    /// reaches the components it flows to or from, its zone, the components
    /// in that zone and its flows. A zone reaches the components in it and
    /// the flows that cross its boundary. A flow reaches its two ends and
    /// the zone each end sits in. Every element reaches itself.
    private static func neighbours(
        components: [ViewedComponent],
        connections: [ViewedConnection],
        zones: [ViewedZone]
    ) -> [String: Set<String>] {
        var reach: [String: Set<String>] = [:]
        func link(_ a: String, _ b: String) {
            reach[a, default: []].insert(b)
            reach[b, default: []].insert(a)
        }
        let zoneOf: [String: String] = Dictionary(
            uniqueKeysWithValues: components.compactMap { component in
                component.zoneId.map { (component.id, $0) }
            }
        )
        let zoneIds = Set(zones.map(\.id))

        for component in components {
            let payload = "component:\(component.id)"
            reach[payload, default: []].insert(payload)
            if let zone = zoneOf[component.id], zoneIds.contains(zone) {
                link(payload, "zone:\(zone)")
                for other in components where zoneOf[other.id] == zone {
                    link(payload, "component:\(other.id)")
                }
            }
        }
        for zone in zones {
            reach["zone:\(zone.id)", default: []].insert("zone:\(zone.id)")
        }
        for flow in connections {
            let source = "component:\(flow.sourceComponentId)"
            let target = "component:\(flow.targetComponentId)"
            // A use link joins the user and the client and is no element
            // of its own: a route runs as the user, through the client.
            if flow.isUse {
                link(source, target)
                continue
            }
            let payload = "flow:\(flow.id)"
            reach[payload, default: []].insert(payload)
            link(payload, source)
            link(payload, target)
            link(source, target)
            let sourceZone = zoneOf[flow.sourceComponentId]
            let targetZone = zoneOf[flow.targetComponentId]
            for zone in [sourceZone, targetZone].compactMap({ $0 }) where zoneIds.contains(zone) {
                // A flow reaches the zone each end sits in. The zone reaches
                // the flow only when the flow crosses its boundary.
                reach[payload, default: []].insert("zone:\(zone)")
                if sourceZone != targetZone {
                    reach["zone:\(zone)", default: []].insert(payload)
                }
            }
        }
        return reach
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
