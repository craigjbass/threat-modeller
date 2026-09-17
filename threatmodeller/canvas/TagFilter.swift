import CoreGraphics
import ThreatModelKit

/// What one tag filter draws on the canvas.
///
/// A model of sixty components draws every one of them at once. A tag files an
/// element under a word, so one model states a payments view, a
/// data-protection view and an operations view. The filter narrows what the
/// canvas draws and nothing else: it writes no file and changes no score.
///
/// The rule lives here rather than in the view, so a test states it and the
/// canvas, the report and anything else that narrows a diagram read the same
/// rule.
nonisolated struct TagFilter: Equatable {
    /// The tags a person picked. Empty draws the whole model.
    private(set) var pickedTags: Set<String> = []

    /// How many flows out the filter draws around the tagged elements. Zero
    /// draws the tagged elements alone. The stepper sets this, and the value
    /// holds while the picked tags change, so it does not reset for every
    /// tag a person picks.
    private(set) var neighbourDepth: Int = 0

    /// True while the filter hides anything.
    var isNarrowing: Bool { pickedTags.isEmpty == false }

    func isPicked(_ tag: String) -> Bool { pickedTags.contains(tag) }

    /// Picks a tag, or drops it when the person picked it already.
    mutating func pick(_ tag: String) {
        if pickedTags.contains(tag) {
            pickedTags.remove(tag)
        } else {
            pickedTags.insert(tag)
        }
    }

    /// Draws the whole model again.
    mutating func clear() {
        pickedTags = []
    }

    /// Sets how many flows out the filter draws. Never negative; the
    /// stepper's own lower bound keeps a person from setting one, but a
    /// caller that passes one anyway still gets zero.
    mutating func setNeighbourDepth(_ depth: Int) {
        neighbourDepth = max(0, depth)
    }

    /// Every tag the model states, in alphabetical order and with no repeats.
    /// This is what the toolbar lists.
    static func tags(in model: ViewThreatModelResponse) -> [String] {
        var found: Set<String> = []
        for component in model.components { found.formUnion(component.tags) }
        for zone in model.zones { found.formUnion(zone.tags) }
        for connection in model.connections { found.formUnion(connection.tags) }
        return found.sorted()
    }

    /// True when the element holds one of the picked tags. Everything passes
    /// while the person has picked no tag.
    func keeps(tags: [String]) -> Bool {
        guard isNarrowing else { return true }
        return tags.contains { pickedTags.contains($0) }
    }

    /// What the canvas draws: the components that hold a picked tag, the
    /// components that sit in a zone holding a picked tag, every component the
    /// walk reaches from those within `neighbourDepth` flows, the zones that
    /// rule keeps (below), and the flows whose two ends the canvas draws.
    ///
    /// A tag on a zone names a whole part of the system, so it draws the zone
    /// and the components inside it. Tagging the zone is the short way to name
    /// a view; a zone drawn empty names nothing.
    ///
    /// A flow needs both its ends, so a flow to a component this filter hides
    /// is hidden too, whatever the flow itself is filed under.
    func narrow(_ model: ViewThreatModelResponse) -> DrawnDiagram {
        let taggedZoneIds = Set(model.zones.filter { keeps(tags: $0.tags) }.map(\.id))
        let matched = model.components.filter { component in
            keeps(tags: component.tags)
                || component.zoneId.map(taggedZoneIds.contains) == true
        }
        let drawnIds = Self.walk(
            from: Set(matched.map(\.id)),
            depth: isNarrowing ? neighbourDepth : 0,
            in: model
        )
        let drawnComponents = model.components.filter { drawnIds.contains($0.id) }
        return DrawnDiagram(
            components: drawnComponents,
            zones: Self.zonesToDraw(model.zones, holding: drawnComponents, orKeeping: keeps),
            connections: model.connections.filter {
                drawnIds.contains($0.sourceComponentId)
                    && drawnIds.contains($0.targetComponentId)
            }
        )
    }

    /// What Focus draws: one component, every component the walk reaches
    /// from it within `depth` flows, either direction, the zones that rule
    /// keeps (below), and the flows between the drawn components.
    ///
    /// Focus is view state on `CanvasState`, not on this filter: a person
    /// focuses one component with no tag written on the model at all.
    static func focus(on componentId: String, depth: Int, in model: ViewThreatModelResponse) -> DrawnDiagram {
        let drawnIds = walk(from: [componentId], depth: depth, in: model)
        let drawnComponents = model.components.filter { drawnIds.contains($0.id) }
        return DrawnDiagram(
            components: drawnComponents,
            // Focus carries no tag of its own, so no zone qualifies by tag; a
            // zone draws here only while a drawn component sits in it.
            zones: Self.zonesToDraw(model.zones, holding: drawnComponents, orKeeping: { _ in false }),
            connections: model.connections.filter {
                drawnIds.contains($0.sourceComponentId)
                    && drawnIds.contains($0.targetComponentId)
            }
        )
    }

    /// A zone is context for what sits inside it, so it draws whenever it
    /// holds a drawn component, or `keeps` says a picked tag is on the zone
    /// itself. A zone with no drawn component and no tag of its own is
    /// context for nothing the picture shows.
    ///
    /// The walk (#128) never reads zone membership: sharing a zone with a
    /// drawn component does not make an element a neighbour of it.
    private static func zonesToDraw(
        _ zones: [ViewedZone],
        holding drawnComponents: [ViewedComponent],
        orKeeping keeps: (_ tags: [String]) -> Bool
    ) -> [ViewedZone] {
        let occupiedZoneIds = Set(drawnComponents.compactMap(\.zoneId))
        return zones.filter { occupiedZoneIds.contains($0.id) || keeps($0.tags) }
    }

    /// Every component id in `seedIds`, and every component id the walk
    /// reaches from them within `depth` flows, either direction.
    ///
    /// Focus (#129) calls this with one seed id, so the tag filter and Focus
    /// walk the model by the same rule.
    static func walk(
        from seedIds: Set<String>,
        depth: Int,
        in model: ViewThreatModelResponse
    ) -> Set<String> {
        guard depth > 0, seedIds.isEmpty == false else { return seedIds }
        var reachedIds = seedIds
        var frontier = seedIds
        for _ in 0..<depth {
            var next: Set<String> = []
            for connection in model.connections {
                if frontier.contains(connection.sourceComponentId),
                    reachedIds.contains(connection.targetComponentId) == false {
                    next.insert(connection.targetComponentId)
                }
                if frontier.contains(connection.targetComponentId),
                    reachedIds.contains(connection.sourceComponentId) == false {
                    next.insert(connection.sourceComponentId)
                }
            }
            guard next.isEmpty == false else { break }
            reachedIds.formUnion(next)
            frontier = next
        }
        return reachedIds
    }

    /// The tags one line of text states: trimmed, in the order typed, with no
    /// empty words and no repeats. The component panel reads a line and writes
    /// a list.
    static func tags(from text: String) -> [String] {
        var found: [String] = []
        for word in text.split(separator: ",") {
            let tag = word.trimmingWhitespace()
            guard tag.isEmpty == false, found.contains(tag) == false else { continue }
            found.append(tag)
        }
        return found
    }

    /// The line the component panel shows for a list of tags.
    static func text(from tags: [String]) -> String {
        tags.joined(separator: ", ")
    }
}

/// The part of a model the canvas draws.
nonisolated struct DrawnDiagram: Equatable {
    let components: [ViewedComponent]
    let zones: [ViewedZone]
    let connections: [ViewedConnection]

    /// The same drawn set at the coordinates a narrowed layout gave it.
    ///
    /// A narrowed diagram is a picture in its own right, so it is laid out on
    /// its own and the result is view state: the model keeps its own
    /// coordinates and the `.arch` file does not change. An element neither
    /// map names keeps the coordinates it has, so a canvas that narrows
    /// nothing draws the model.
    func placed(
        componentPositions: [String: CGPoint],
        zoneRects: [String: CGRect]
    ) -> DrawnDiagram {
        guard componentPositions.isEmpty == false || zoneRects.isEmpty == false else {
            return self
        }
        return DrawnDiagram(
            components: components.map { component in
                guard let point = componentPositions[component.id] else { return component }
                return component.moved(x: point.x, y: point.y)
            },
            zones: zones.map { zone in
                guard let rect = zoneRects[zone.id] else { return zone }
                return zone.moved(
                    x: rect.minX,
                    y: rect.minY,
                    width: rect.width,
                    height: rect.height
                )
            },
            connections: connections
        )
    }
}

private nonisolated extension Substring {
    func trimmingWhitespace() -> String {
        var characters = Array(self)
        while characters.first?.isWhitespace == true { characters.removeFirst() }
        while characters.last?.isWhitespace == true { characters.removeLast() }
        return String(characters)
    }
}
