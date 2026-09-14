import Foundation
import ThreatModelKit

/// Draws the total score of each sampled commit as one line.
///
/// SVG, because the package writes it itself and every build draws it,
/// including the static Linux one. A commit whose files did not parse breaks
/// the line rather than dropping it to zero: a zero reads as "no risk", which
/// is the opposite of what a file that does not parse means.
public enum RiskOverTimeChart {
    public static let width = 720.0
    public static let height = 260.0
    private static let left = 48.0
    private static let right = 16.0
    private static let top = 16.0
    private static let bottom = 36.0

    /// `rows` is newest first, the way the history reads it. The chart draws
    /// oldest on the left, which is how a person reads time.
    public static func svg(of rows: [RiskHistoryRow]) -> String {
        let ordered = Array(rows.reversed())
        guard ordered.count >= 2 else { return "" }

        let highest = max(ordered.compactMap { $0.numbers?.totalScore }.max() ?? 0, 1)
        let plotWidth = width - left - right
        let plotHeight = height - top - bottom
        let step = ordered.count > 1 ? plotWidth / Double(ordered.count - 1) : plotWidth

        func point(_ index: Int, _ score: Int) -> (x: Double, y: Double) {
            (
                x: left + Double(index) * step,
                y: top + plotHeight - (Double(score) / Double(highest)) * plotHeight
            )
        }

        var lines: [String] = [
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"\(number(width))\" "
                + "height=\"\(number(height))\" viewBox=\"0 0 \(number(width)) \(number(height))\" "
                + "role=\"img\" aria-label=\"Total residual risk at each sampled commit\">",
            "<rect width=\"\(number(width))\" height=\"\(number(height))\" fill=\"#ffffff\"/>",
            "<line x1=\"\(number(left))\" y1=\"\(number(top))\" x2=\"\(number(left))\" "
                + "y2=\"\(number(top + plotHeight))\" stroke=\"#8a8a8a\" stroke-width=\"1\"/>",
            "<line x1=\"\(number(left))\" y1=\"\(number(top + plotHeight))\" "
                + "x2=\"\(number(left + plotWidth))\" y2=\"\(number(top + plotHeight))\" "
                + "stroke=\"#8a8a8a\" stroke-width=\"1\"/>",
            "<text x=\"4\" y=\"\(number(top + 10))\" font-family=\"-apple-system, sans-serif\" "
                + "font-size=\"11\" fill=\"#3c3c3c\">\(highest)</text>",
            "<text x=\"4\" y=\"\(number(top + plotHeight))\" "
                + "font-family=\"-apple-system, sans-serif\" font-size=\"11\" fill=\"#3c3c3c\">0</text>"
        ]

        // One path per run of commits that parsed, so a commit that did not
        // parse leaves a gap.
        var run: [String] = []
        for (index, row) in ordered.enumerated() {
            guard let numbers = row.numbers else {
                lines += path(of: run)
                run = []
                continue
            }
            let place = point(index, numbers.totalScore)
            run.append("\(number(place.x)),\(number(place.y))")
        }
        lines += path(of: run)

        for (index, row) in ordered.enumerated() {
            guard let numbers = row.numbers else { continue }
            let place = point(index, numbers.totalScore)
            lines.append(
                "<circle cx=\"\(number(place.x))\" cy=\"\(number(place.y))\" r=\"3\" "
                    + "fill=\"#1f6feb\"><title>\(escaped(row.commit.shortHash)): "
                    + "\(numbers.totalScore)</title></circle>"
            )
        }

        if let oldest = ordered.first, let newest = ordered.last {
            lines.append(
                "<text x=\"\(number(left))\" y=\"\(number(height - 12))\" "
                    + "font-family=\"-apple-system, sans-serif\" font-size=\"11\" "
                    + "fill=\"#3c3c3c\">\(escaped(oldest.commit.shortHash))</text>"
            )
            lines.append(
                "<text x=\"\(number(left + plotWidth - 50))\" y=\"\(number(height - 12))\" "
                    + "font-family=\"-apple-system, sans-serif\" font-size=\"11\" "
                    + "fill=\"#3c3c3c\">\(escaped(newest.commit.shortHash))</text>"
            )
        }

        lines.append("</svg>")
        return lines.joined(separator: "\n") + "\n"
    }

    private static func path(of run: [String]) -> [String] {
        guard run.count >= 2 else {
            return run.isEmpty ? [] : []
        }
        return [
            "<polyline points=\"\(run.joined(separator: " "))\" fill=\"none\" "
                + "stroke=\"#1f6feb\" stroke-width=\"2\"/>"
        ]
    }

    private static func number(_ value: Double) -> String {
        String(format: "%.1f", value)
    }

    private static func escaped(_ text: String) -> String {
        text
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }
}
