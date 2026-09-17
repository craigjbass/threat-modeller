import Foundation
import Observation
import ThreatModelKit

/// Reads the project's git history, at a person's request.
///
/// Reading compiles the model once per sampled commit, so nothing reads it
/// when a window opens. The sheet asks, and this says what it found.
@MainActor
@Observable
final class HistorySession {
    private let useCases: UseCaseFactory
    private let root: String

    /// Everything the last read found, so the Report stage draws the same
    /// rows the sheet lists and compares against the same commit.
    private(set) var found = RiskHistory()
    var rows: [RiskHistoryRow] { found.rows }
    var truncated: Bool { found.truncated }
    private(set) var isReading = false
    private(set) var message: String?
    /// How many commits the next read samples.
    var commits = ReadRiskHistory.defaultCommits

    init(useCases: UseCaseFactory, root: String) {
        self.useCases = useCases
        self.root = root
    }

    func read() async {
        isReading = true
        defer { isReading = false }
        message = nil

        let read = await Task.detached { [useCases, root, commits] in
            useCases.readRiskHistory()
                .execute(ReadRiskHistoryRequest(root: root, commits: commits))
        }.value

        switch read {
        case .read(let history):
            found = history
            if history.rows.isEmpty {
                message = "No commit in this project touched a threat model file."
            }
        case .notARepository(let reason):
            found = RiskHistory()
            message = reason
        case .noSuchSystem:
            found = RiskHistory()
            message = "This project holds no such system."
        case .cannotRead(let reason):
            found = RiskHistory()
            message = "The history could not be read: \(reason)"
        }
    }

    /// The rows oldest first, which is how the graph reads time.
    var oldestFirst: [RiskHistoryRow] {
        rows.reversed()
    }

    var highestTotal: Int {
        max(rows.compactMap { $0.numbers?.totalScore }.max() ?? 0, 1)
    }
}
