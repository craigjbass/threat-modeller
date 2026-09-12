import Foundation
import ThreatModelKit

/// A picture of one threat: where it sits, and what reaches it.
///
/// The whole diagram says everything at once. A reader working through the
/// twenty threats that matter most should not have to find each one in it
/// twenty times.
public enum ThreatDiagrams {
    public struct Picture: Equatable, Sendable {
        public let threatId: String
        public let sourceId: String
        public let fileName: String
        public let svg: String

        public init(threatId: String, sourceId: String, fileName: String, svg: String) {
            self.threatId = threatId
            self.sourceId = sourceId
            self.fileName = fileName
            self.svg = svg
        }

        /// The key the report files a picture under.
        public var key: String { "\(threatId)@\(sourceId)" }
    }

    /// One picture for each threat, named after the system and its place in
    /// the list, so the same report always names the same file.
    public static func pictures(
        of model: DiagramBuilder.Model,
        for threats: [ReportThreat],
        stem: String
    ) -> [Picture] {
        threats.enumerated().compactMap { index, threat in
            guard let focused = focus(model, on: threat.sourceId) else { return nil }

            return Picture(
                threatId: threat.threatId,
                sourceId: threat.sourceId,
                fileName: "\(stem)-threat-\(index + 1).svg",
                svg: SvgWriter.svg(of: DiagramBuilder.drawing(of: focused))
            )
        }
    }

    /// The part of the model one threat is about.
    ///
    /// A threat on a component draws that component, every flow touching it
    /// and whatever sits at the other end. A threat on a flow draws the flow
    /// and its two ends. A threat on a zone draws the zone, what it holds, and
    /// every flow crossing its edge. Every zone holding a drawn component is
    /// drawn too, so a reader sees which side of a boundary each one is on.
    public static func focus(_ model: DiagramBuilder.Model, on sourceId: String) -> DiagramBuilder.Model? {
        let parts = sourceId.split(separator: ":", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { return nil }
        let kind = parts[0]
        let id = parts[1]

        var componentIds: Set<String> = []
        var connectionIds: Set<String> = []

        switch kind {
        case "component":
            guard model.components.contains(where: { $0.id == id }) else { return nil }
            componentIds.insert(id)
            for connection in model.connections
            where connection.sourceComponentId == id || connection.targetComponentId == id {
                connectionIds.insert(connection.id)
                componentIds.insert(connection.sourceComponentId)
                componentIds.insert(connection.targetComponentId)
            }

        case "connection":
            guard let connection = model.connections.first(where: { $0.id == id }) else { return nil }
            connectionIds.insert(connection.id)
            componentIds.insert(connection.sourceComponentId)
            componentIds.insert(connection.targetComponentId)

        case "zone":
            guard model.zones.contains(where: { $0.id == id }) else { return nil }
            // What the zone holds, and one hop out of it. Growing the set as
            // the flows are walked would follow the second hop as well, and a
            // picture of one zone would end up the whole diagram.
            let inside = Set(model.components.filter { $0.zoneId == id }.map(\.id))
            componentIds = inside
            for connection in model.connections {
                let ends = [connection.sourceComponentId, connection.targetComponentId]
                guard ends.contains(where: { inside.contains($0) }) else { continue }
                connectionIds.insert(connection.id)
                for end in ends { componentIds.insert(end) }
            }

        default:
            return nil
        }

        let components = model.components.filter { componentIds.contains($0.id) }
        let zoneIds = Set(components.compactMap(\.zoneId)).union(kind == "zone" ? [id] : [])

        return DiagramBuilder.Model(
            components: components,
            connections: model.connections.filter { connectionIds.contains($0.id) },
            zones: model.zones
                .filter { zoneIds.contains($0.id) }
                .map { shrunk($0, around: components) },
            risks: model.risks,
            guards: model.guards
        )
    }

    /// How much blank a shrunk zone keeps round what it holds.
    public static let zonePadding = 40.0

    /// The zone, cut to the components this picture still shows.
    ///
    /// A fragment that kept the whole zone would draw one node inside a box
    /// the size of the diagram it came from, which says nothing about either.
    /// A zone with nothing left in it keeps its own size, because there is
    /// nothing to cut it to.
    static func shrunk(_ zone: ViewedZone, around components: [ViewedComponent]) -> ViewedZone {
        let inside = components.filter { $0.zoneId == zone.id }
        guard inside.isEmpty == false else { return zone }

        let rects = inside.map {
            Component.drawnRect(
                at: Point(x: $0.x, y: $0.y),
                shape: DiagramBuilder.shape(of: $0)
            )
        }
        let lowestX = rects.map(\.minX).min()! - zonePadding
        let highestX = rects.map(\.maxX).max()! + zonePadding
        // The band at the top holds the name, and a component's centre must
        // sit below it for the zone to hold that component.
        let lowestY = rects.map(\.minY).min()! - zonePadding - ZoneContainment.headerHeight
        let highestY = rects.map(\.maxY).max()! + zonePadding

        return ViewedZone(
            id: zone.id,
            name: zone.name,
            customName: zone.customName,
            networkZoneId: zone.networkZoneId,
            networkTypeId: zone.networkTypeId,
            riskReductionEnabled: zone.riskReductionEnabled,
            riskReductionPercent: zone.riskReductionPercent,
            x: lowestX,
            y: lowestY,
            width: highestX - lowestX,
            height: highestY - lowestY,
            boundaryId: zone.boundaryId
        )
    }
}
