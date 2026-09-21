import ThreatModelKit

/// Writes a controls source in the canonical shape.
struct ControlsWriter {
    func write(_ source: ControlsSource) -> String {
        var lines: [String] = []
        lines.append("controls for \(quoted(source.systemName)) {")

        var body: [String] = []
        if let catalogueTag = source.catalogueTag {
            body.append("catalogue = \(quoted(catalogueTag))")
        }
        if let riskTolerance = source.riskTolerance {
            body.append("tolerance = \(quoted(riskTolerance))")
        }
        if body.isEmpty == false {
            body.append("")
        }

        for answer in Self.ordered(source.answers) {
            body += threatBlock(answer)
            body.append("")
        }

        for tree in source.trees.sorted(by: Self.treeOrder) {
            body += treeBlock(tree)
            body.append("")
        }

        while body.last == "" { body.removeLast() }
        lines += indent(body)
        lines.append("}")
        return lines.joined(separator: "\n") + "\n"
    }

    static func treeOrder(_ left: SourceTreeAnswer, _ right: SourceTreeAnswer) -> Bool {
        if left.isStale != right.isStale { return right.isStale }
        return left.treeId < right.treeId
    }

    private func treeBlock(_ tree: SourceTreeAnswer) -> [String] {
        let header = "tree \(quoted(tree.treeId)) {"
        var lines: [String] = [tree.isStale ? "stale " + header : header]
        var body: [String] = []

        if tree.isStale == false {
            var attributes = [
                ("goal", quoted(tree.goalKey)),
                ("chain", String(tree.chain)),
                ("raises_risk_by", String(tree.raisesRiskBy)),
                ("score", String(tree.score)),
                ("score_before", String(tree.scoreBefore))
            ]
            if let closedBy = tree.closedBy { attributes.append(("closed_by", quoted(closedBy))) }
            body += aligned(attributes)
            body.append("")
        }

        for control in tree.sufficient {
            body.append("sufficient \(quoted(control.description)) {")
            body += indent(aligned([("state", quoted(control.state))]))
            body.append("}")
            body.append("")
        }

        for step in tree.steps {
            var attributes = [("state", quoted(step.state))]
            if let closedBy = step.closedBy { attributes.append(("by", quoted(closedBy))) }
            if let position = step.position { attributes.append(("position", String(position))) }
            body.append("step \(quoted(step.key)) {")
            body += indent(aligned(attributes))
            body.append("}")
            body.append("")
        }

        while body.last == "" { body.removeLast() }
        lines += indent(body)
        lines.append("}")
        return lines
    }

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
        if answer.impacts.isEmpty == false {
            attributes.append(
                ("impacts", "[" + answer.impacts.map(quoted).joined(separator: ", ") + "]")
            )
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
            if let edgeId = control.mitigatedBy, edgeId.isEmpty == false {
                inner.append(("mitigated_by", quoted(edgeId)))
            }
            inner += Self.proofAttributes(control.proof, quoted: quoted)
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
            var inner: [(String, String)] = [
                ("reduces_risk_by", String(compensating.reducesRiskBy)),
                ("rationale", quoted(compensating.rationale))
            ]
            if compensating.sources.isEmpty == false {
                inner.append(
                    ("sources", "[" + compensating.sources.map(quoted).joined(separator: ", ") + "]")
                )
            }
            inner += Self.proofAttributes(compensating.proof, quoted: quoted)
            body += indent(aligned(inner))
            body.append("}")
        }

        for recommendation in answer.recommendations {
            if body.isEmpty == false { body.append("") }
            body.append("recommendation \(quoted(recommendation.text)) {")
            var inner: [(String, String)] = []
            if let note = recommendation.note, note.isEmpty == false {
                inner.append(("note", quoted(note)))
            }
            if recommendation.sources.isEmpty == false {
                inner.append(
                    ("sources", "[" + recommendation.sources.map(quoted).joined(separator: ", ") + "]")
                )
            }
            if inner.isEmpty == false {
                body += indent(aligned(inner))
            }
            body.append("}")
        }

        lines += indent(body)
        lines.append("}")
        return lines
    }

    /// What proves a control is in place, when it states anything. A control
    /// that states none of the three writes none of them.
    static func proofAttributes(
        _ proof: ControlProof,
        quoted: (String) -> String
    ) -> [(String, String)] {
        var attributes: [(String, String)] = []
        if let evidence = proof.evidence {
            attributes.append(("evidence", quoted(evidence.rawValue)))
        }
        if proof.reference.isEmpty == false {
            attributes.append(("reference", quoted(proof.reference)))
        }
        if let verifiedOn = proof.verifiedOn {
            attributes.append(("verified_on", quoted(verifiedOn.description)))
        }
        return attributes
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
