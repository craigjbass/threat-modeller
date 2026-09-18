import Foundation
import ThreatModelKit

/// Reads a mermaid flowchart and draws it.
///
/// A report holds diagram blocks a team wrote. The Markdown report writes each
/// one as a fenced block, and the window draws it, so a reader of the stage
/// sees the picture the report means rather than its source.
///
/// Only the flowchart is read. A mermaid diagram of another kind answers nil,
/// and the caller shows the text instead.
///
/// The design is
/// `docs/superpowers/specs/2026-09-17-report-stage-pictures-design.md`.
public enum MermaidDrawing {
    /// Which way the ranks run.
    public enum Direction: String, Equatable, Sendable {
        case down
        case up
        case right
        case left
    }

    /// The outline a node is drawn with.
    public enum NodeShape: Equatable, Sendable {
        case rectangle
        case rounded
        case stadium
        case circle
        case rhombus
        case hexagon
        case cylinder
    }

    public struct Node: Equatable, Sendable {
        public let id: String
        public let label: String
        public let shape: NodeShape

        public init(id: String, label: String, shape: NodeShape) {
            self.id = id
            self.label = label
            self.shape = shape
        }
    }

    public struct Edge: Equatable, Sendable {
        public let from: String
        public let to: String
        public let label: String?
        public let hasArrow: Bool
        public let isDashed: Bool

        public init(from: String, to: String, label: String?, hasArrow: Bool, isDashed: Bool) {
            self.from = from
            self.to = to
            self.label = label
            self.hasArrow = hasArrow
            self.isDashed = isDashed
        }
    }

    /// A `subgraph`, and what it holds.
    public struct Group: Equatable, Sendable {
        public let title: String
        public let nodeIds: [String]

        public init(title: String, nodeIds: [String]) {
            self.title = title
            self.nodeIds = nodeIds
        }
    }

    public struct Graph: Equatable, Sendable {
        public let direction: Direction
        public let nodes: [Node]
        public let edges: [Edge]
        public let groups: [Group]

        public init(direction: Direction, nodes: [Node], edges: [Edge], groups: [Group]) {
            self.direction = direction
            self.nodes = nodes
            self.edges = edges
            self.groups = groups
        }
    }

    // MARK: what the reader reads

    /// The graph the text states, or nil when this reader does not read it.
    public static func graph(of text: String) -> Graph? {
        let statements = self.statements(of: text)
        guard let header = statements.first,
              let direction = direction(ofHeader: header) else { return nil }

        var nodes: [Node] = []
        var byId: [String: Int] = [:]
        var edges: [Edge] = []
        var groups: [Group] = []
        var openGroups: [(title: String, nodeIds: [String])] = []

        func hold(_ node: Node) {
            if let at = byId[node.id] {
                if nodes[at].label == nodes[at].id, node.label != node.id {
                    nodes[at] = node
                }
            } else {
                byId[node.id] = nodes.count
                nodes.append(node)
            }
            guard openGroups.isEmpty == false else { return }
            if openGroups[openGroups.count - 1].nodeIds.contains(node.id) == false {
                openGroups[openGroups.count - 1].nodeIds.append(node.id)
            }
        }

        for statement in statements.dropFirst() {
            if statement.hasPrefix("subgraph") {
                openGroups.append((title: subgraphTitle(of: statement), nodeIds: []))
                continue
            }
            if statement == "end" {
                guard let closed = openGroups.popLast() else { continue }
                groups.append(Group(title: closed.title, nodeIds: closed.nodeIds))
                continue
            }
            guard saysSomethingAboutThePicture(statement) else { continue }

            let chain = link(in: statement)
            guard chain.nodes.isEmpty == false else { continue }
            for node in chain.nodes { hold(node) }
            for (index, link) in chain.links.enumerated() where index + 1 < chain.nodes.count {
                edges.append(
                    Edge(
                        from: chain.nodes[index].id,
                        to: chain.nodes[index + 1].id,
                        label: link.label,
                        hasArrow: link.hasArrow,
                        isDashed: link.isDashed
                    )
                )
            }
        }

        for open in openGroups.reversed() {
            groups.append(Group(title: open.title, nodeIds: open.nodeIds))
        }

        guard nodes.isEmpty == false else { return nil }
        return Graph(direction: direction, nodes: nodes, edges: edges, groups: groups)
    }

    /// The picture the text states, or nil when this reader does not read it.
    public static func drawing(of text: String) -> DiagramDrawing? {
        graph(of: text).map(drawing(of:))
    }

    // MARK: the text, in statements

    /// The statements of the block: one per line and per `;`, with comments
    /// and blank lines dropped.
    static func statements(of text: String) -> [String] {
        let lines: [String] = text
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map(String.init)
        var found: [String] = []
        for line in lines {
            for piece in splitOutsideBrackets(line, on: ";") {
                let statement = piece.trimmingCharacters(in: .whitespaces)
                guard statement.isEmpty == false, statement.hasPrefix("%%") == false else {
                    continue
                }
                found.append(statement)
            }
        }
        return found
    }

    /// The direction the header names, or nil when the header is not a
    /// flowchart.
    static func direction(ofHeader header: String) -> Direction? {
        let words = header.split(separator: " ").map(String.init)
        guard let first = words.first?.lowercased(),
              first == "graph" || first == "flowchart" else { return nil }

        switch words.count > 1 ? words[1].uppercased() : "TD" {
        case "LR": return .right
        case "RL": return .left
        case "BT": return .up
        default: return .down
        }
    }

    /// A statement that changes only how mermaid paints says nothing about
    /// the picture this reader draws.
    static func saysSomethingAboutThePicture(_ statement: String) -> Bool {
        let first = statement.split(separator: " ").first.map(String.init)?.lowercased() ?? ""
        return ["classdef", "class", "style", "linkstyle", "click", "direction"]
            .contains(first) == false
    }

    /// What a `subgraph` line calls itself.
    static func subgraphTitle(of statement: String) -> String {
        let rest = statement.dropFirst("subgraph".count).trimmingCharacters(in: .whitespaces)
        guard rest.isEmpty == false else { return "" }
        if let open = rest.firstIndex(where: { $0 == "[" || $0 == "(" }),
           let close = rest.lastIndex(where: { $0 == "]" || $0 == ")" }),
           open < close {
            return unquoted(String(rest[rest.index(after: open) ..< close]))
        }
        return unquoted(rest)
    }

    // MARK: one statement, as nodes and links

    struct Link {
        let label: String?
        let hasArrow: Bool
        let isDashed: Bool
    }

    /// The nodes of one statement and the links between them.
    static func link(in statement: String) -> (nodes: [Node], links: [Link]) {
        let text = Array(normalisedMiddleLabels(statement))
        var nodes: [Node] = []
        var links: [Link] = []
        var piece = ""
        var depth = 0
        var index = 0

        while index < text.count {
            let character = text[index]
            if "[({\"".contains(character) { depth += 1 }
            if "])}".contains(character) { depth = max(0, depth - 1) }
            if character == "\"", depth > 0, piece.hasSuffix("\"") { depth = max(0, depth - 1) }

            if depth == 0, let token = token(in: text, at: index) {
                if let node = node(of: piece) { nodes.append(node) }
                piece = ""
                links.append(token.link)
                index = token.next
                continue
            }
            piece.append(character)
            index += 1
        }

        if let node = node(of: piece) { nodes.append(node) }
        return (nodes, links)
    }

    /// A link token starting at `index`, or nil.
    static func token(in text: [Character], at index: Int) -> (link: Link, next: Int)? {
        guard "-=".contains(text[index]) else { return nil }

        var end = index
        while end < text.count, "-=.".contains(text[end]) { end += 1 }
        let run = String(text[index ..< end])
        guard run.count >= 2, run.contains(where: { $0 == "-" || $0 == "=" }) else { return nil }

        var hasArrow = false
        if end < text.count, "><xo".contains(text[end]) {
            hasArrow = true
            end += 1
        }

        var label: String?
        var after = end
        while after < text.count, text[after] == " " { after += 1 }
        if after < text.count, text[after] == "|" {
            var close = after + 1
            while close < text.count, text[close] != "|" { close += 1 }
            label = unquoted(String(text[(after + 1) ..< min(close, text.count)]))
            after = min(close + 1, text.count)
            end = after
        }

        return (Link(label: label, hasArrow: hasArrow, isDashed: run.contains(".")), end)
    }

    /// `a -- writes --> b` written the way `a -->|writes| b` is written, so
    /// one scanner reads both forms.
    static func normalisedMiddleLabels(_ statement: String) -> String {
        let pattern = "(-{2,}|={2,}|-\\.+)\\s+([^-=>|\\[\\]{}()]+?)\\s+(-{2,}|={2,}|\\.-*|-\\.-*)([>xo])?"
        guard let expression = try? NSRegularExpression(pattern: pattern) else { return statement }
        let whole = NSRange(statement.startIndex ..< statement.endIndex, in: statement)
        guard let match = expression.firstMatch(in: statement, range: whole),
              let opening = Range(match.range(at: 1), in: statement),
              let middle = Range(match.range(at: 2), in: statement),
              let closing = Range(match.range(at: 3), in: statement),
              let replaced = Range(match.range, in: statement) else { return statement }

        let dotted = statement[opening].contains(".") || statement[closing].contains(".")
        let thick = statement[opening].contains("=")
        let head = match.range(at: 4).location == NSNotFound ? "" : ">"
        let token = dotted ? "-.-" : (thick ? "==" : "--")
        let label = statement[middle].trimmingCharacters(in: .whitespaces)

        return statement.replacingCharacters(
            in: replaced,
            with: "\(token)\(head)|\(label)|"
        )
    }

    /// One node, or nil when the piece names none.
    static func node(of piece: String) -> Node? {
        let text = piece.trimmingCharacters(in: .whitespaces)
        guard text.isEmpty == false else { return nil }

        guard let open = text.firstIndex(where: { "[({>".contains($0) }) else {
            return Node(id: text, label: text, shape: .rectangle)
        }
        let id = String(text[text.startIndex ..< open]).trimmingCharacters(in: .whitespaces)
        guard id.isEmpty == false else { return nil }

        let body = String(text[open...])
        for (opening, closing, shape) in Self.brackets where
            body.hasPrefix(opening) && body.hasSuffix(closing) && body.count > opening.count + closing.count - 1 {
            let inner = String(body.dropFirst(opening.count).dropLast(closing.count))
            return Node(id: id, label: readable(inner), shape: shape)
        }
        return Node(id: id, label: id, shape: .rectangle)
    }

    /// The bracket pairs a node is written with, longest first so `[[` wins
    /// over `[`.
    static let brackets: [(String, String, NodeShape)] = [
        ("([", "])", .stadium),
        ("[[", "]]", .rectangle),
        ("[(", ")]", .cylinder),
        ("[/", "/]", .rectangle),
        ("[\\", "\\]", .rectangle),
        ("((", "))", .circle),
        ("{{", "}}", .hexagon),
        ("[", "]", .rectangle),
        ("(", ")", .rounded),
        ("{", "}", .rhombus),
        (">", "]", .rectangle)
    ]

    /// The label as a reader reads it: no quotes, and a line break as a
    /// space, because the picture writes one line.
    static func readable(_ text: String) -> String {
        unquoted(
            text
                .replacingOccurrences(of: "<br/>", with: " ")
                .replacingOccurrences(of: "<br>", with: " ")
                .replacingOccurrences(of: "<br />", with: " ")
        )
    }

    static func unquoted(_ text: String) -> String {
        var trimmed = text.trimmingCharacters(in: .whitespaces)
        if trimmed.count >= 2, trimmed.hasPrefix("\""), trimmed.hasSuffix("\"") {
            trimmed = String(trimmed.dropFirst().dropLast())
        }
        return trimmed.trimmingCharacters(in: .whitespaces)
    }

    /// Splits on a separator the brackets do not hold.
    static func splitOutsideBrackets(_ text: String, on separator: Character) -> [String] {
        var pieces: [String] = []
        var piece = ""
        var depth = 0
        for character in text {
            if "[({".contains(character) { depth += 1 }
            if "])}".contains(character) { depth = max(0, depth - 1) }
            if character == separator, depth == 0 {
                pieces.append(piece)
                piece = ""
                continue
            }
            piece.append(character)
        }
        pieces.append(piece)
        return pieces
    }
}

// MARK: - the picture

extension MermaidDrawing {
    /// The blank left around everything.
    static let margin = 24.0
    /// The height of a node box.
    static let nodeHeight = 44.0
    /// The gap between two nodes of one rank.
    static let alongGap = 28.0
    /// The gap between two ranks.
    static let rankGap = 70.0

    static func width(of label: String) -> Double {
        max(84, Double(label.count) * 7.6 + 28)
    }

    /// Where every node sits, by id.
    static func places(of graph: Graph) -> [String: Rect] {
        var rank: [String: Int] = [:]
        for node in graph.nodes { rank[node.id] = 0 }

        // Longest path, with the walk bounded by the node count so a cycle
        // stops rather than running round the loop.
        for _ in 0 ..< graph.nodes.count {
            var moved = false
            for edge in graph.edges {
                guard let from = rank[edge.from], let to = rank[edge.to] else { continue }
                if to < from + 1 {
                    rank[edge.to] = from + 1
                    moved = true
                }
            }
            if moved == false { break }
        }

        var byRank: [Int: [Node]] = [:]
        for node in graph.nodes { byRank[rank[node.id] ?? 0, default: []].append(node) }
        let ranks = byRank.keys.sorted()

        // The size of every rank, so each one is centred against the widest.
        var along: [Int: Double] = [:]
        for index in ranks {
            let nodes = byRank[index] ?? []
            let sizes = nodes.map { width(of: $0.label) }
            along[index] = sizes.reduce(0, +) + Double(max(0, nodes.count - 1)) * alongGap
        }
        let widestAlong = along.values.max() ?? 0

        var places: [String: Rect] = [:]
        var across = margin
        for index in ranks {
            let nodes = byRank[index] ?? []
            var offset = margin + (widestAlong - (along[index] ?? 0)) / 2
            for node in nodes {
                let size = width(of: node.label)
                places[node.id] = graph.direction.runsAcross
                    ? Rect(x: across, y: offset, width: size, height: nodeHeight)
                    : Rect(x: offset, y: across, width: size, height: nodeHeight)
                offset += size + alongGap
            }
            across += (graph.direction.runsAcross ? widestNode(nodes) : nodeHeight) + rankGap
        }
        return places
    }

    static func widestNode(_ nodes: [Node]) -> Double {
        nodes.map { width(of: $0.label) }.max() ?? 84
    }

    // swiftlint:disable:next function_body_length
    static func drawing(of graph: Graph) -> DiagramDrawing {
        var places = places(of: graph)

        // Everything drawn, so the picture is cut to what it holds.
        var maxX = 0.0
        var maxY = 0.0
        for rect in places.values {
            maxX = max(maxX, rect.maxX)
            maxY = max(maxY, rect.maxY)
        }

        if graph.direction == .up || graph.direction == .left {
            places = places.mapValues { rect in
                graph.direction == .up
                    ? Rect(x: rect.minX, y: maxY - rect.maxY + margin, width: rect.size.width, height: rect.size.height)
                    : Rect(x: maxX - rect.maxX + margin, y: rect.minY, width: rect.size.width, height: rect.size.height)
            }
        }

        var shapes: [DrawnShape] = []

        // The groups first, so a node draws over its own box.
        for group in graph.groups {
            let held = group.nodeIds.compactMap { places[$0] }
            guard held.isEmpty == false else { continue }
            let box = Rect(
                x: (held.map(\.minX).min() ?? 0) - 16,
                y: (held.map(\.minY).min() ?? 0) - 30,
                width: (held.map(\.maxX).max() ?? 0) - (held.map(\.minX).min() ?? 0) + 32,
                height: (held.map(\.maxY).max() ?? 0) - (held.map(\.minY).min() ?? 0) + 46
            )
            maxX = max(maxX, box.maxX)
            maxY = max(maxY, box.maxY)
            shapes.append(
                .rectangle(
                    box,
                    cornerRadius: 10,
                    DiagramStyle(stroke: .quiet, fill: DiagramColour.quiet.faded(to: 0.06), width: 1, dash: [6, 4])
                )
            )
            if group.title.isEmpty == false {
                shapes.append(
                    .text(
                        group.title,
                        at: Point(x: box.minX + 12, y: box.minY + 18),
                        anchor: .leading,
                        size: 12,
                        bold: true,
                        .quiet
                    )
                )
            }
        }

        // The edges next, so a line runs behind the boxes it joins.
        for edge in graph.edges {
            guard let from = places[edge.from], let to = places[edge.to] else { continue }
            let start = border(of: from, towards: centre(of: to))
            let finish = border(of: to, towards: centre(of: from))
            shapes.append(
                .path(
                    [.move(start), .line(finish)],
                    DiagramStyle(stroke: .quiet, width: 1.5, dash: edge.isDashed ? [5, 4] : [])
                )
            )
            if edge.hasArrow {
                shapes += arrow(at: finish, from: start)
            }
            if let label = edge.label, label.isEmpty == false {
                let middle = Point(x: (start.x + finish.x) / 2, y: (start.y + finish.y) / 2)
                let box = Rect(
                    x: middle.x - Double(label.count) * 3.3 - 5,
                    y: middle.y - 9,
                    width: Double(label.count) * 6.6 + 10,
                    height: 18
                )
                shapes.append(
                    .rectangle(box, cornerRadius: 4, DiagramStyle(fill: .paper, width: 0))
                )
                shapes.append(
                    .text(label, at: Point(x: middle.x, y: middle.y + 4), anchor: .centre, size: 11, bold: false, .quiet)
                )
            }
        }

        // The nodes last, so nothing is drawn over a label.
        for node in graph.nodes {
            guard let box = places[node.id] else { continue }
            shapes += outline(of: node.shape, in: box)
            shapes.append(
                .text(
                    node.label,
                    at: Point(x: box.minX + box.size.width / 2, y: box.minY + box.size.height / 2 + 4),
                    anchor: .centre,
                    size: 12,
                    bold: false,
                    .ink
                )
            )
        }

        return DiagramDrawing(
            origin: Point(x: 0, y: 0),
            size: Size(width: maxX + margin, height: maxY + margin),
            background: .paper,
            shapes: shapes
        )
    }

    static func centre(of rect: Rect) -> Point {
        Point(x: rect.minX + rect.size.width / 2, y: rect.minY + rect.size.height / 2)
    }

    /// Where a line from the middle of `rect` towards `target` leaves the box.
    static func border(of rect: Rect, towards target: Point) -> Point {
        let middle = centre(of: rect)
        let deltaX = target.x - middle.x
        let deltaY = target.y - middle.y
        guard deltaX != 0 || deltaY != 0 else { return middle }

        let halfWidth = rect.size.width / 2
        let halfHeight = rect.size.height / 2
        let scaleX = deltaX == 0 ? Double.greatestFiniteMagnitude : halfWidth / abs(deltaX)
        let scaleY = deltaY == 0 ? Double.greatestFiniteMagnitude : halfHeight / abs(deltaY)
        let scale = min(scaleX, scaleY)
        return Point(x: middle.x + deltaX * scale, y: middle.y + deltaY * scale)
    }

    /// The head of an arrow, as a filled triangle.
    static func arrow(at point: Point, from start: Point) -> [DrawnShape] {
        let deltaX = point.x - start.x
        let deltaY = point.y - start.y
        let length = (deltaX * deltaX + deltaY * deltaY).squareRoot()
        guard length > 0 else { return [] }

        let unitX = deltaX / length
        let unitY = deltaY / length
        let size = 9.0
        let back = Point(x: point.x - unitX * size, y: point.y - unitY * size)
        let left = Point(x: back.x - unitY * size / 2.4, y: back.y + unitX * size / 2.4)
        let right = Point(x: back.x + unitY * size / 2.4, y: back.y - unitX * size / 2.4)

        return [
            .path(
                [.move(point), .line(left), .line(right), .close],
                DiagramStyle(stroke: .quiet, fill: .quiet, width: 1)
            )
        ]
    }

    static func outline(of shape: NodeShape, in box: Rect) -> [DrawnShape] {
        let style = DiagramStyle(stroke: .ink, fill: .paper, width: 1.4)
        switch shape {
        case .rectangle:
            return [.rectangle(box, cornerRadius: 0, style)]
        case .rounded:
            return [.rectangle(box, cornerRadius: 10, style)]
        case .stadium, .cylinder:
            return [.rectangle(box, cornerRadius: box.size.height / 2, style)]
        case .circle:
            return [.ellipse(box, style)]
        case .rhombus:
            let middle = centre(of: box)
            return [
                .path(
                    [
                        .move(Point(x: middle.x, y: box.minY)),
                        .line(Point(x: box.maxX, y: middle.y)),
                        .line(Point(x: middle.x, y: box.maxY)),
                        .line(Point(x: box.minX, y: middle.y)),
                        .close
                    ],
                    style
                )
            ]
        case .hexagon:
            let notch = min(16, box.size.width / 4)
            return [
                .path(
                    [
                        .move(Point(x: box.minX + notch, y: box.minY)),
                        .line(Point(x: box.maxX - notch, y: box.minY)),
                        .line(Point(x: box.maxX, y: box.minY + box.size.height / 2)),
                        .line(Point(x: box.maxX - notch, y: box.maxY)),
                        .line(Point(x: box.minX + notch, y: box.maxY)),
                        .line(Point(x: box.minX, y: box.minY + box.size.height / 2)),
                        .close
                    ],
                    style
                )
            ]
        }
    }
}

extension MermaidDrawing.Direction {
    /// True when the ranks run across the page rather than down it.
    var runsAcross: Bool { self == .right || self == .left }
}
