import ThreatModelKit

/// Writes a controls source in the canonical shape.
///
/// The order is fixed — components, then flows, then zones, then stale; inside
/// each, threats by id; inside each, controls by description — so a compile of
/// an unchanged model writes the file it read.
struct ControlsWriter {
    func write(_ source: ControlsSource) -> String {
        var lines: [String] = []
        lines.append("controls for \(quoted(source.systemName)) {")

        var body: [String] = []
        if let catalogueTag = source.catalogueTag {
            body.append("catalogue = \(quoted(catalogueTag))")
            body.append("")
        }

        for answer in Self.ordered(source.answers) {
            body += threatBlock(answer)
            body.append("")
        }

        while body.last == "" { body.removeLast() }
        lines += indent(body)
        lines.append("}")
        return lines.joined(separator: "\n") + "\n"
    }

    /// Live answers first, in the order component, flow, zone; stale answers
    /// last. Inside each group, by source and then by threat.
    static func ordered(_ answers: [SourceThreatAnswer]) -> [SourceThreatAnswer] {
        func rank(_ answer: SourceThreatAnswer) -> Int {
            switch answer.sourceKind {
            case "component": 0
            case "flow": 1
            case "zone": 2
            default: 3
            }
        }

        return answers.sorted { left, right in
            if left.isStale != right.isStale { return right.isStale }
            if rank(left) != rank(right) { return rank(left) < rank(right) }
            if left.sourceId != right.sourceId { return left.sourceId < right.sourceId }
            return left.threatId < right.threatId
        }
    }

    private func threatBlock(_ answer: SourceThreatAnswer) -> [String] {
        var lines: [String] = []
        let header = "threat \(quoted(answer.threatId))"
            + " on \(answer.sourceKind) \(quoted(answer.sourceId)) {"
        lines.append(answer.isStale ? "stale " + header : header)

        var body: [String] = []
        var attributes: [(String, String)] = []
        if let severityLabel = answer.severityLabel {
            attributes.append(("severity", quoted(severityLabel)))
        }
        if let score = answer.score {
            attributes.append(("score", String(score)))
        }
        body += aligned(attributes)

        if let finding = answer.likelihood {
            if body.isEmpty == false { body.append("") }
            body.append("likelihood \(quoted(finding.label)) {")
            var inner: [(String, String)] = []
            if Int(finding.likelihood.id) == nil {
                inner.append(("tier", quoted(finding.likelihood.id)))
            } else {
                inner.append(("prior", finding.likelihood.id))
            }
            inner.append(("rationale", quoted(finding.rationale)))
            if finding.sources.isEmpty == false {
                inner.append(("sources", "[" + finding.sources.map(quoted).joined(separator: ", ") + "]"))
            }
            body += indent(aligned(inner))
            body.append("}")
        }

        for control in answer.controls.sorted(by: { $0.description < $1.description }) {
            if body.isEmpty == false { body.append("") }
            body.append("control \(quoted(control.description)) {")
            var inner: [(String, String)] = [("status", quoted(control.status.rawValue))]
            if let note = control.note, note.isEmpty == false {
                inner.append(("note", quoted(note)))
            }
            body += indent(aligned(inner))
            body.append("}")
        }

        if let decision = answer.severityDecision {
            if body.isEmpty == false { body.append("") }
            body.append("severity_override \(quoted(decision.severityId)) {")
            var inner: [(String, String)] = [("rationale", quoted(decision.rationale))]
            if decision.sources.isEmpty == false {
                inner.append(("sources", "[" + decision.sources.map(quoted).joined(separator: ", ") + "]"))
            }
            body += indent(aligned(inner))
            body.append("}")
        }

        for compensating in answer.compensating {
            if body.isEmpty == false { body.append("") }
            body.append("compensating \(quoted(compensating.label)) {")
            body += indent(
                aligned([
                    ("reduces_risk_by", String(compensating.reducesRiskBy)),
                    ("rationale", quoted(compensating.rationale))
                ])
            )
            body.append("}")
        }

        for recommendation in answer.recommendations {
            if body.isEmpty == false { body.append("") }
            body.append("recommendation \(quoted(recommendation.text)) {")
            if let note = recommendation.note, note.isEmpty == false {
                body += indent(aligned([("note", quoted(note))]))
            }
            body.append("}")
        }

        lines += indent(body)
        lines.append("}")
        return lines
    }

    private func aligned(_ attributes: [(String, String)]) -> [String] {
        let width = attributes.map(\.0.count).max() ?? 0
        return attributes.map { name, value in
            name + String(repeating: " ", count: width - name.count) + " = " + value
        }
    }

    private func indent(_ lines: [String]) -> [String] {
        lines.map { $0.isEmpty ? "" : "  " + $0 }
    }

    private func quoted(_ text: String) -> String {
        var result = "\""
        for character in text {
            switch character {
            case "\"": result.append("\\\"")
            case "\\": result.append("\\\\")
            case "\n": result.append("\\n")
            case "\t": result.append("\\t")
            default: result.append(character)
            }
        }
        return result + "\""
    }
}
