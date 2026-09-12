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
            guard let focused = focus(
                model,
                on: threat.sourceId,
                titled: "\(threat.sourceName) — \(threat.name)"
            ) else { return nil }

            return Picture(
                threatId: threat.threatId,
                sourceId: threat.sourceId,
                fileName: "\(stem)-threat-\(index + 1).svg",
                svg: SvgWriter.svg(of: DiagramBuilder.drawing(of: focused))
            )
        }
    }

    /// A picture of one control: what it protects.
    public struct ControlPicture: Equatable, Sendable {
        public let protectorId: String
        public let fileName: String
        public let svg: String

        public init(protectorId: String, fileName: String, svg: String) {
            self.protectorId = protectorId
            self.fileName = fileName
            self.svg = svg
        }
    }

    /// One picture for each control, so a reader scrutinising a control sees
    /// every component that rests on it in one place.
    public static func controlPictures(
        of model: DiagramBuilder.Model,
        for dependencies: [ReportProtectionDependency],
        stem: String
    ) -> [ControlPicture] {
        dependencies.enumerated().compactMap { index, dependency in
            let covers = Dictionary(
                uniqueKeysWithValues: dependency.answeredByElementId.map {
                    ("component:\($0.key)", $0.value)
                }
            )
            guard let drawn = protecting(
                model,
                by: dependency.protectorId,
                covers: covers,
                titled: title(of: dependency)
            ) else { return nil }

            return ControlPicture(
                protectorId: dependency.protectorId,
                fileName: "\(stem)-control-\(index + 1).svg",
                svg: SvgWriter.svg(of: DiagramBuilder.drawing(of: drawn))
            )
        }
    }

    static func title(of dependency: ReportProtectionDependency) -> String {
        let count = dependency.answeredByElementId.count
        let threats = dependency.answeredByElementId.values.reduce(0, +)
        return "\(dependency.protectorName) \u{2014} answers \(threats) "
            + (threats == 1 ? "threat" : "threats")
            + " on \(count) " + (count == 1 ? "element" : "elements")
    }

    /// The part of the model one control is about: the control, every
    /// component it answers a threat on, the flows between any of them, and
    /// the zones that hold them.
    public static func protecting(
        _ model: DiagramBuilder.Model,
        by protectorId: String,
        covers: [String: Int],
        titled title: String? = nil
    ) -> DiagramBuilder.Model? {
        guard model.components.contains(where: { $0.id == protectorId }) else { return nil }

        var componentIds: Set<String> = [protectorId]
        for sourceId in covers.keys where sourceId.hasPrefix("component:") {
            componentIds.insert(String(sourceId.dropFirst("component:".count)))
        }

        let components = model.components.filter { componentIds.contains($0.id) }
        let connections = model.connections.filter {
            componentIds.contains($0.sourceComponentId)
                && componentIds.contains($0.targetComponentId)
        }
        let zoneIds = Set(components.compactMap(\.zoneId))

        return laidOut(
            DiagramBuilder.Model(
                components: components,
                connections: connections,
                zones: model.zones.filter { zoneIds.contains($0.id) },
                risks: model.risks,
                guards: model.guards,
                focus: "component:\(protectorId)",
                title: title,
                subtitle: "Heavy outline: the control. Dashed line: what it protects, "
                    + "with the count of threats it answers there. "
                    + "A badge on a node counts the threats still open on that node.",
                covers: covers
            )
        )
    }

    /// The part of the model one threat is about.
    ///
    /// A threat on a component draws that component, every flow touching it
    /// and whatever sits at the other end. A threat on a flow draws the flow
    /// and its two ends. A threat on a zone draws the zone, what it holds, and
    /// every flow crossing its edge. Every zone holding a drawn component is
    /// drawn too, so a reader sees which side of a boundary each one is on.
    public static func focus(
        _ model: DiagramBuilder.Model,
        on sourceId: String,
        titled title: String? = nil
    ) -> DiagramBuilder.Model? {
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

        return laidOut(
            DiagramBuilder.Model(
                components: components,
                connections: model.connections.filter { connectionIds.contains($0.id) },
                zones: model.zones.filter { zoneIds.contains($0.id) },
                risks: model.risks,
                guards: model.guards,
                focus: sourceId,
                title: title,
                subtitle: title == nil
                    ? nil
                    : "Heavy outline: the element this threat is raised on. "
                        + "A badge on a node counts the threats still open on that node." 
            )
        )
    }

    /// The fragment placed on its own.
    ///
    /// Taking the positions from the whole diagram left the pieces where a
    /// layout of thirty-five nodes needed them, which is nowhere near where a
    /// picture of three needs them. The same layout runs again over the
    /// fragment alone, so every technique and the whole fitness apply to the
    /// picture a reader actually sees.
    public static func laidOut(_ model: DiagramBuilder.Model) -> DiagramBuilder.Model {
        let placed = LayOutModel().execute(
            LayOutModelRequest(
                source: source(of: model),
                shapes: Dictionary(
                    uniqueKeysWithValues: model.components.map { ($0.id, $0.shapeId) }
                )
            )
        )

        let at = Dictionary(
            uniqueKeysWithValues: placed.components.map { ($0.id, Point(x: $0.x, y: $0.y)) }
        )
        let rects = Dictionary(uniqueKeysWithValues: placed.zones.map { ($0.id, $0) })

        return DiagramBuilder.Model(
            components: model.components.map { component in
                let place = at[component.id] ?? Point(x: component.x, y: component.y)
                return moved(component, to: place)
            },
            connections: model.connections,
            zones: model.zones.compactMap { zone in
                guard let rect = rects[zone.id] else { return nil }
                return sized(zone, to: rect)
            },
            risks: model.risks,
            guards: model.guards,
            focus: model.focus,
            title: model.title,
            subtitle: model.subtitle,
            covers: model.covers
        )
    }

    /// The fragment as the layout reads one: components in their zones, the
    /// flows between them, and what guards each one.
    ///
    /// The guard is named by its label rather than a component id, because the
    /// component doing the guarding is often not in the fragment. The layout
    /// only groups boundaries by it, so a label serves.
    static func source(of model: DiagramBuilder.Model) -> ArchitectureSource {
        func sourceComponent(_ component: ViewedComponent) -> SourceComponent {
            SourceComponent(
                id: component.id,
                technologyId: component.technologyId,
                name: component.name,
                data: component.sensitivityId,
                raisesThreats: component.threatsDisabled == false,
                runsAs: component.runsAsId,
                shape: component.shapeId
            )
        }

        let held = Set(model.zones.map(\.id))

        return ArchitectureSource(
            systemName: "fragment",
            zones: model.zones.map { zone in
                SourceZone(
                    id: zone.id,
                    kind: zone.networkZoneId,
                    network: zone.networkTypeId,
                    name: zone.customName,
                    reducesRisk: zone.riskReductionEnabled,
                    reducesRiskBy: zone.riskReductionPercent,
                    components: model.components
                        .filter { $0.zoneId == zone.id }
                        .map(sourceComponent),
                    boundary: zone.boundaryId
                )
            },
            components: model.components
                .filter { $0.zoneId.map { held.contains($0) == false } ?? true }
                .map(sourceComponent),
            flows: model.connections.map {
                SourceFlow(
                    sourceId: $0.sourceComponentId,
                    targetId: $0.targetComponentId,
                    kind: $0.kindId,
                    description: $0.description
                )
            },
            mitigates: model.components.flatMap { component in
                (model.guards["component:\(component.id)"] ?? []).map { held in
                    SourceMitigates(
                        sourceId: held.label,
                        targetId: component.id,
                        threatIds: [],
                        reducesRiskBy: 0,
                        status: held.isAssumed ? "assumed" : "adopted"
                    )
                }
            }
        )
    }

    static func moved(_ component: ViewedComponent, to place: Point) -> ViewedComponent {
        ViewedComponent(
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
    }

    static func sized(_ zone: ViewedZone, to rect: LaidOutZone) -> ViewedZone {
        ViewedZone(
            id: zone.id,
            name: zone.name,
            customName: zone.customName,
            networkZoneId: zone.networkZoneId,
            networkTypeId: zone.networkTypeId,
            riskReductionEnabled: zone.riskReductionEnabled,
            riskReductionPercent: zone.riskReductionPercent,
            x: rect.x,
            y: rect.y,
            width: rect.width,
            height: rect.height,
            boundaryId: zone.boundaryId
        )
    }
}
