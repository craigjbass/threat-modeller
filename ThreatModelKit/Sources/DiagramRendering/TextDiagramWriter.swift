import ThreatModelKit

/// Writes the diagram in a language a wiki, a pipeline or an editor reads.
///
/// SVG and PNG are pictures: a person cannot edit one in a pull request and a
/// diff of one says nothing. Mermaid, Graphviz DOT and D2 are text, so a wiki
/// renders the diagram, a pipeline draws it, and a reviewer reads what
/// changed.
///
/// Every writer walks the model in the order the model holds, so two runs on
/// one model give the same bytes. An adversary takes a shape of its own in
/// each language, so a reader tells it from a legitimate user.
public enum TextDiagramWriter {
    /// The languages this writes.
    public enum Language: String, CaseIterable, Sendable {
        case mermaid
        case dot
        case d2

        /// The extension a file of this language takes.
        public var fileExtension: String {
            switch self {
            case .mermaid: "mmd"
            case .dot: "dot"
            case .d2: "d2"
            }
        }
    }

    public static func text(
        of model: DiagramBuilder.Model,
        in language: Language
    ) -> String {
        switch language {
        case .mermaid: mermaid(of: model)
        case .dot: dot(of: model)
        case .d2: d2(of: model)
        }
    }

    // MARK: Mermaid

    /// A `flowchart` a GitHub wiki renders with no image file.
    ///
    /// A zone is a `subgraph`, a component's shape says what it is, and a flow
    /// states its kind on the arrow.
    public static func mermaid(of model: DiagramBuilder.Model) -> String {
        var lines = ["flowchart LR"]

        for zone in model.zones {
            let held = model.components.filter { $0.zoneId == zone.id }
            guard held.isEmpty == false else { continue }
            lines.append("  subgraph \(identifier(zone.id))[\(mermaidText(zone.name))]")
            for component in held {
                lines.append("    " + mermaidNode(component))
            }
            lines.append("  end")
        }

        for component in model.components where component.zoneId == nil {
            lines.append("  " + mermaidNode(component))
        }

        for connection in model.connections {
            lines.append(
                "  \(identifier(connection.sourceComponentId))"
                    + " -->|\(mermaidText(edgeLabel(connection)))|"
                    + " \(identifier(connection.targetComponentId))"
            )
        }

        return lines.joined(separator: "\n") + "\n"
    }

    /// A node, drawn in the shape Mermaid gives that kind of element.
    private static func mermaidNode(_ component: ViewedComponent) -> String {
        let name = mermaidText(component.name)
        if component.isAdversary { return "\(identifier(component.id)){{\(name)}}" }
        switch component.shapeId {
        case "actor": return "\(identifier(component.id))([\(name)])"
        case "store": return "\(identifier(component.id))[(\(name))]"
        default: return "\(identifier(component.id))[\(name)]"
        }
    }

    /// Mermaid reads `"` as the end of a label and `#` as an entity, and a
    /// label holding either breaks the diagram. Both travel as entities, and
    /// the label is always quoted.
    static func mermaidText(_ text: String) -> String {
        var built = ""
        for character in text {
            switch character {
            case "#": built += "#35;"
            case "\"": built += "#quot;"
            case "<": built += "#lt;"
            case ">": built += "#gt;"
            case "\n": built += " "
            default: built.append(character)
            }
        }
        return "\"\(built)\""
    }

    // MARK: Graphviz DOT

    public static func dot(of model: DiagramBuilder.Model) -> String {
        var lines = ["digraph {", "  rankdir=LR;", "  node [fontname=\"Helvetica\"];"]

        for zone in model.zones {
            let held = model.components.filter { $0.zoneId == zone.id }
            guard held.isEmpty == false else { continue }
            lines.append("  subgraph cluster_\(identifier(zone.id)) {")
            lines.append("    label=\(dotText(zone.name));")
            for component in held {
                lines.append("    " + dotNode(component))
            }
            lines.append("  }")
        }

        for component in model.components where component.zoneId == nil {
            lines.append("  " + dotNode(component))
        }

        for connection in model.connections {
            lines.append(
                "  \(identifier(connection.sourceComponentId))"
                    + " -> \(identifier(connection.targetComponentId))"
                    + " [label=\(dotText(edgeLabel(connection)))];"
            )
        }

        lines.append("}")
        return lines.joined(separator: "\n") + "\n"
    }

    private static func dotNode(_ component: ViewedComponent) -> String {
        "\(identifier(component.id)) [label=\(dotText(component.name)), shape=\(dotShape(component))];"
    }

    private static func dotShape(_ component: ViewedComponent) -> String {
        if component.isAdversary { return "octagon" }
        switch component.shapeId {
        case "actor": return "ellipse"
        case "store": return "cylinder"
        default: return "box"
        }
    }

    /// DOT reads a quoted string, in which `"` and `\` are escaped.
    static func dotText(_ text: String) -> String {
        var built = ""
        for character in text {
            switch character {
            case "\"": built += "\\\""
            case "\\": built += "\\\\"
            case "\n": built += " "
            default: built.append(character)
            }
        }
        return "\"\(built)\""
    }

    // MARK: D2

    public static func d2(of model: DiagramBuilder.Model) -> String {
        var lines: [String] = []

        for zone in model.zones {
            let held = model.components.filter { $0.zoneId == zone.id }
            guard held.isEmpty == false else { continue }
            lines.append("\(identifier(zone.id)): \(d2Text(zone.name)) {")
            for component in held {
                lines.append("  " + d2Node(component))
            }
            lines.append("}")
        }

        for component in model.components where component.zoneId == nil {
            lines.append(d2Node(component))
        }

        // A component inside a zone is addressed through the zone, the way D2
        // addresses anything nested.
        var zoneByComponent: [String: String] = [:]
        for component in model.components {
            if let zoneId = component.zoneId {
                zoneByComponent[component.id] = identifier(zoneId)
            }
        }
        func address(_ id: String) -> String {
            zoneByComponent[id].map { "\($0).\(identifier(id))" } ?? identifier(id)
        }

        for connection in model.connections {
            lines.append(
                "\(address(connection.sourceComponentId))"
                    + " -> \(address(connection.targetComponentId))"
                    + ": \(d2Text(edgeLabel(connection)))"
            )
        }

        return lines.joined(separator: "\n") + "\n"
    }

    private static func d2Node(_ component: ViewedComponent) -> String {
        "\(identifier(component.id)): \(d2Text(component.name)) { shape: \(d2Shape(component)) }"
    }

    private static func d2Shape(_ component: ViewedComponent) -> String {
        if component.isAdversary { return "hexagon" }
        switch component.shapeId {
        case "actor": return "person"
        case "store": return "cylinder"
        default: return "rectangle"
        }
    }

    /// D2 reads a quoted string, in which `"` and `\` are escaped.
    static func d2Text(_ text: String) -> String {
        var built = ""
        for character in text {
            switch character {
            case "\"": built += "\\\""
            case "\\": built += "\\\\"
            case "\n": built += " "
            default: built.append(character)
            }
        }
        return "\"\(built)\""
    }

    // MARK: shared

    /// An identifier every one of the three languages accepts: a letter or a
    /// digit stays, and anything else becomes an underscore. A name that
    /// starts with a digit takes a letter in front of it.
    static func identifier(_ id: String) -> String {
        var built = ""
        for character in id {
            if character.isLetter || character.isNumber {
                built.append(character)
            } else {
                built.append("_")
            }
        }
        if let first = built.first, first.isNumber { built = "n" + built }
        return built.isEmpty ? "unnamed" : built
    }

    /// The word a reader sees on an arrow: `reaches` on a reach, `uses` on a
    /// use link, else the flow kind.
    private static func edgeLabel(_ connection: ViewedConnection) -> String {
        if connection.isReach { return "reaches" }
        if connection.isUse { return "uses" }
        return FlowKind(rawValue: connection.kindId)?.label ?? connection.kindId
    }
}
