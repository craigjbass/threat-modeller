/// The report's Attack paths section.
///
/// WARNING: the walk is bounded. When it drops a path the section says so,
/// because a silent truncation reads as full coverage.
public enum MarkdownAttackPaths {
    public static func lines(_ paths: [ReportAttackPath], notListed: Int) -> [String] {
        guard paths.isEmpty == false || notListed > 0 else { return [] }

        var lines = ["## Attack paths", ""]
        for path in paths {
            lines.append("### \(path.startName) \u{2192} \(path.endName) (worst \(path.worstScore))")
            lines.append("")
            for (index, hop) in path.hops.enumerated() {
                var line = "\(index + 1). \(hop.componentName)"
                if let kind = hop.flowKindLabel { line += ", by \(kind)" }
                if let threat = hop.worstThreatName {
                    line += " \u{2014} \(threat) (\(hop.riskScore))"
                }
                if hop.reducedBy.isEmpty == false {
                    line += ", reduced by \(hop.reducedBy.joined(separator: ", "))"
                }
                lines.append(line)
            }
            lines.append("")
        }
        if notListed > 0 {
            lines.append("\(notListed) further paths are not listed.")
            lines.append("")
        }
        return lines
    }
}
