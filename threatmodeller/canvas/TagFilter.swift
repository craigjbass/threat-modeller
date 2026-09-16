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

    /// What the canvas draws: the components and the zones that hold a picked
    /// tag, and the flows whose two ends the canvas draws.
    ///
    /// A flow needs both its ends, so a flow to a component this filter hides
    /// is hidden too, whatever the flow itself is filed under.
    func narrow(_ model: ViewThreatModelResponse) -> DrawnDiagram {
        let components = model.components.filter { keeps(tags: $0.tags) }
        let drawnIds = Set(components.map(\.id))
        return DrawnDiagram(
            components: components,
            zones: model.zones.filter { keeps(tags: $0.tags) },
            connections: model.connections.filter {
                drawnIds.contains($0.sourceComponentId)
                    && drawnIds.contains($0.targetComponentId)
            }
        )
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
}

private nonisolated extension Substring {
    func trimmingWhitespace() -> String {
        var characters = Array(self)
        while characters.first?.isWhitespace == true { characters.removeFirst() }
        while characters.last?.isWhitespace == true { characters.removeLast() }
        return String(characters)
    }
}
