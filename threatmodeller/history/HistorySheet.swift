import SwiftUI
import ThreatModelKit

/// What the model scored at each sampled commit, and the line those scores
/// draw.
struct HistorySheet: View {
    let session: HistorySession
    let dismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Risk over time")
                .font(.title2)

            Text(
                "The score of this project at each commit that touched a threat model file, "
                    + "newest first. The history is your git history; nothing is stored."
            )
            .font(.caption)
            .foregroundStyle(.secondary)

            HStack(spacing: 8) {
                Button(session.isReading ? "Reading\u{2026}" : "Read") {
                    Task { await session.read() }
                }
                .disabled(session.isReading)
                .accessibilityIdentifier("read-history")

                Stepper(
                    "Sample \(session.commits) commits",
                    value: Binding(
                        get: { session.commits },
                        set: { session.commits = max(1, $0) }
                    ),
                    in: 1...500,
                    step: 10
                )
                .font(.caption)
                Spacer(minLength: 0)
            }

            if let message = session.message {
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("history-message")
            }

            if session.rows.isEmpty == false {
                graph
                rowList
            }

            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(minWidth: 640, minHeight: 480)
    }

    /// The same numbers the report draws, drawn here with the same rule: a
    /// commit that did not parse breaks the line rather than dropping it.
    private var graph: some View {
        GeometryReader { space in
            let rows = session.oldestFirst
            let highest = Double(session.highestTotal)
            let step = rows.count > 1 ? space.size.width / Double(rows.count - 1) : space.size.width

            ZStack {
                Path { line in
                    var started = false
                    for (index, row) in rows.enumerated() {
                        guard let numbers = row.numbers else {
                            started = false
                            continue
                        }
                        let point = CGPoint(
                            x: Double(index) * step,
                            y: space.size.height
                                - (Double(numbers.totalScore) / highest) * space.size.height
                        )
                        if started {
                            line.addLine(to: point)
                        } else {
                            line.move(to: point)
                            started = true
                        }
                    }
                }
                .stroke(Color.accentColor, lineWidth: 2)
            }
        }
        .frame(height: 160)
        .accessibilityIdentifier("history-graph")
    }

    private var rowList: some View {
        Table(session.rows, columns: {
            TableColumn("Date") { row in
                Text(MarkdownRiskOverTime.day(row.commit.date))
            }
            TableColumn("Commit") { row in Text(row.commit.shortHash) }
            TableColumn("Author") { row in Text(row.commit.author) }
            TableColumn("Total") { row in
                Text(row.numbers.map { "\($0.totalScore)" } ?? "did not parse")
            }
            TableColumn("Worst") { row in
                Text(row.numbers.map { "\($0.worstScore)" } ?? "\u{2014}")
            }
            TableColumn("Threats") { row in
                Text(row.numbers.map { "\($0.threatCount)" } ?? "\u{2014}")
            }
            TableColumn("Catalogue") { row in
                Text(row.numbers?.catalogueTag ?? "\u{2014}")
            }
        })
        .frame(minHeight: 160)
        .accessibilityIdentifier("history-rows")
    }
}

extension RiskHistoryRow: @retroactive Identifiable {
    public var id: String { commit.hash }
}
