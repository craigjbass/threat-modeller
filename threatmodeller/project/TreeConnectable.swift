import Foundation
import ThreatModelKit

/// One element in the rank the sidebar draws: the element, and whether the
/// selected node's element reaches it.
struct RankedElement: Identifiable, Equatable {
    let element: TreeElement
    let isConnectable: Bool

    var id: String { element.id }
}

/// What a tree node can connect to.
///
/// The design in
/// `docs/superpowers/specs/2026-09-16-tree-connectable-elements-design.md`
/// states the rules: the sidebar ranks the elements the selected node's
/// element reaches first, the search on a box lists them, and a join the
/// flows and zones do not support is written with a warning on the step.
/// Every rule reads `TreeElement.neighbours`.
enum TreeConnectable {
    /// Every element in one order for one anchor: the elements the anchor
    /// reaches first, ranked by the threats each raises, most first, ties in
    /// model order; then every other element in model order. With no
    /// anchor, the model order with none marked.
    static func rank(_ elements: [TreeElement], from anchor: String?) -> [RankedElement] {
        guard let anchor, let known = elements.first(where: { $0.payload == anchor }) else {
            return elements.map { RankedElement(element: $0, isConnectable: false) }
        }
        let reached = elements.filter { known.neighbours.contains($0.payload) }
        let rest = elements.filter { known.neighbours.contains($0.payload) == false }
        return byThreatsRaised(reached).map { RankedElement(element: $0, isConnectable: true) }
            + rest.map { RankedElement(element: $0, isConnectable: false) }
    }

    /// The search on a box: the elements the anchor reaches, or every
    /// element with no anchor or on request, that match the query, ranked
    /// by the threats each raises.
    static func search(
        _ elements: [TreeElement],
        from anchor: String?,
        query: String,
        everyElement: Bool
    ) -> [TreeElement] {
        let ranked = rank(elements, from: anchor)
        let offered = anchor == nil || everyElement
            ? byThreatsRaised(ranked.map(\.element))
            : ranked.filter(\.isConnectable).map(\.element)
        let wanted = query.trimmingCharacters(in: .whitespaces)
        guard wanted.isEmpty == false else { return offered }
        return offered.filter {
            $0.name.localizedCaseInsensitiveContains(wanted)
                || $0.sourceId.localizedCaseInsensitiveContains(wanted)
                || $0.kind.localizedCaseInsensitiveContains(wanted)
        }
    }

    /// The rows the sidebar draws: the rank for the one selected node, or
    /// the model order with nothing selected.
    @MainActor
    static func sidebarRows(editor: TreeEditor, canvas: TreeCanvasState, elements: [TreeElement]) -> [RankedElement] {
        rank(elements, from: anchor(editor: editor, canvas: canvas))
    }

    /// The element the one selected node is on, as a payload, or nil.
    @MainActor
    static func anchor(editor: TreeEditor, canvas: TreeCanvasState) -> String? {
        guard canvas.selectionCount == 1, let id = canvas.selectedInOrder.first else { return nil }
        if let pending = editor.pending.first(where: { $0.id == id }) { return pending.element.payload }
        return editor.graph.elementPayload(anchoring: id)
    }

    /// The two elements of a join the flows and zones do not support: the
    /// element of the node named, and the element of the node it feeds. Nil
    /// for a node that feeds nothing, for an end the model does not state,
    /// and for a join the anchor reaches.
    static func outsideJoin(
        from id: String,
        in graph: TreeGraph,
        elements: [TreeElement]
    ) -> (from: TreeElement, to: TreeElement)? {
        guard let fed = graph.edges.first(where: { $0.from == id })?.to,
              let fromPayload = graph.elementPayload(anchoring: id),
              let toPayload = graph.elementPayload(anchoring: fed),
              let from = elements.first(where: { $0.payload == fromPayload }),
              let to = elements.first(where: { $0.payload == toPayload }),
              to.neighbours.contains(from.payload) == false else { return nil }
        return (from, to)
    }

    /// Most threats first; ties keep the order given.
    private static func byThreatsRaised(_ elements: [TreeElement]) -> [TreeElement] {
        elements.enumerated()
            .sorted { a, b in
                if a.element.threats.count != b.element.threats.count {
                    return a.element.threats.count > b.element.threats.count
                }
                return a.offset < b.offset
            }
            .map(\.element)
    }
}

extension TreeGraph {
    /// The element one node is on, as a payload, or nil. A step is on its
    /// target. A box with an element is on that element. A junction, and a
    /// box with none, take the node they feed; a box that feeds nothing
    /// takes the node that feeds it.
    func elementPayload(anchoring id: String) -> String? {
        var seen: Set<String> = []
        var current = id
        while seen.insert(current).inserted, let node = node(current) {
            switch node.kind {
            case .step(let target, _):
                return "\(target.sourceKind):\(target.sourceId)"
            case .placeholder(let element?):
                return element.payload
            case .placeholder(nil):
                if let fed = edges.first(where: { $0.from == current })?.to {
                    current = fed
                } else if let feeder = edges.first(where: { $0.to == current })?.from {
                    current = feeder
                } else {
                    return nil
                }
            case .allOf, .anyOf:
                guard let fed = edges.first(where: { $0.from == current })?.to else { return nil }
                current = fed
            }
        }
        return nil
    }
}
