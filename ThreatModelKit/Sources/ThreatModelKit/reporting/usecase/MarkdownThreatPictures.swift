/// The report's picture of each top residual threat.
///
/// The table above says which threats matter most. This says where each one
/// sits: the element it is raised on, what reaches it, and what stands in the
/// way. A reader who has to work that out from the whole diagram works it out
/// twenty times.
public enum MarkdownThreatPictures {
    /// The key a picture is filed under.
    public static func key(threatId: String, sourceId: String) -> String {
        "\(threatId)@\(sourceId)"
    }

    /// `diagrams` holds the diagram itself, as text a wiki renders. A threat
    /// that states one writes a fenced block rather than a link to an image
    /// file, so the report needs no file beside it.
    public static func lines(
        _ threats: [ReportThreat],
        pictures: [String: String],
        diagrams: [String: String] = [:]
    ) -> [String] {
        guard pictures.isEmpty == false || diagrams.isEmpty == false else { return [] }

        let drawn = threats.filter {
            let key = key(threatId: $0.threatId, sourceId: $0.sourceId)
            return pictures[key] != nil || diagrams[key] != nil
        }
        guard drawn.isEmpty == false else { return [] }

        var lines = ["## Top residual risk in detail", ""]

        for threat in drawn {
            let key = key(threatId: threat.threatId, sourceId: threat.sourceId)

            lines.append("### \(threat.name) \u{2014} \(threat.sourceName)")
            lines.append("")
            if let diagram = diagrams[key] {
                lines += Markdown.fenced(diagram, as: "mermaid")
            } else if let fileName = pictures[key] {
                lines.append("![\(threat.name) on \(threat.sourceName)](\(fileName))")
            } else {
                continue
            }
            lines.append("")
            lines.append(
                "Residual \(threat.riskScore) of \(threat.inherentScore) before controls. "
                    + "Level \(threat.riskLevel)."
            )

            let unanswered = threat.controls.filter { $0.isImplemented == false }
            if unanswered.isEmpty == false {
                lines.append("")
                lines.append("Not answered by:")
                for control in unanswered {
                    lines.append("- \(control.description)")
                }
            }

            if threat.mitigatedByComponentLabels.isEmpty == false {
                lines.append("")
                lines.append("Reduced by \(threat.mitigatedByComponentLabels.joined(separator: ", ")).")
            }

            lines.append("")
        }

        return lines
    }
}
