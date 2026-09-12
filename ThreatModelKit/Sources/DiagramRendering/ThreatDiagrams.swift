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

        return packed(
            DiagramBuilder.Model(
                components: components,
                connections: model.connections.filter { connectionIds.contains($0.id) },
                zones: model.zones
                    .filter { zoneIds.contains($0.id) }
                    .map { shrunk($0, around: components) },
                risks: model.risks,
                guards: model.guards
            )
        )
    }

    /// The widest blank a fragment keeps between one thing and the next.
    public static let widestBlank = 60.0

    /// The fragment with the empty parts taken out.
    ///
    /// Positions come from the whole layout, so two zones that sit far apart
    /// there sit far apart here, with nothing in between. Taking out the blank
    /// keeps what is left where it was in relation to everything else, and
    /// stops a picture of two nodes covering the space of thirty-five.
    public static func packed(_ model: DiagramBuilder.Model) -> DiagramBuilder.Model {
        let boxes = model.components.map {
            Component.drawnRect(at: Point(x: $0.x, y: $0.y), shape: DiagramBuilder.shape(of: $0))
        }
        let zones = model.zones.map {
            Rect(x: $0.x, y: $0.y, width: $0.width, height: $0.height)
        }
        let all = boxes + zones
        guard all.count > 1 else { return model }

        let acrossX = blanks(in: all.map { ($0.minX, $0.maxX) })
        let acrossY = blanks(in: all.map { ($0.minY, $0.maxY) })
        guard acrossX.isEmpty == false || acrossY.isEmpty == false else { return model }

        func moved(_ x: Double, _ y: Double) -> Point {
            Point(x: x - taken(from: acrossX, before: x), y: y - taken(from: acrossY, before: y))
        }

        return DiagramBuilder.Model(
            components: model.components.map { component in
                let place = moved(component.x, component.y)
                return ViewedComponent(
                    id: component.id,
                    technologyId: component.technologyId,
                    name: component.name,
                    customName: component.customName,
                    providerId: component.providerId,
                    categoryId: component.categoryId,
                    x: place.x,
                    y: place.y,
                    sensitivityId: component.sensitivityId,
                    threatsDisabled: component.threatsDisabled,
                    isUnknownTechnology: component.isUnknownTechnology,
                    zoneId: component.zoneId,
                    runsAsId: component.runsAsId,
                    shapeId: component.shapeId,
                    shapeOverrideId: component.shapeOverrideId
                )
            },
            connections: model.connections,
            zones: model.zones.map { zone in
                let place = moved(zone.x, zone.y)
                return ViewedZone(
                    id: zone.id,
                    name: zone.name,
                    customName: zone.customName,
                    networkZoneId: zone.networkZoneId,
                    networkTypeId: zone.networkTypeId,
                    riskReductionEnabled: zone.riskReductionEnabled,
                    riskReductionPercent: zone.riskReductionPercent,
                    x: place.x,
                    y: place.y,
                    width: zone.width,
                    height: zone.height,
                    boundaryId: zone.boundaryId
                )
            },
            risks: model.risks,
            guards: model.guards
        )
    }

    /// The stretches of one axis that nothing covers and that are wider than
    /// the widest blank a fragment keeps, as the range to close and how much
    /// of it to close.
    static func blanks(in spans: [(Double, Double)]) -> [(from: Double, remove: Double)] {
        let sorted = spans.sorted { $0.0 < $1.0 }
        var found: [(from: Double, remove: Double)] = []
        var reached = sorted[0].1

        for span in sorted.dropFirst() {
            let blank = span.0 - reached
            if blank > widestBlank { found.append((from: span.0, remove: blank - widestBlank)) }
            reached = max(reached, span.1)
        }

        return found
    }

    /// How much has been taken out of the axis before this point.
    static func taken(from blanks: [(from: Double, remove: Double)], before place: Double) -> Double {
        blanks.filter { place >= $0.from }.map(\.remove).reduce(0, +)
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
