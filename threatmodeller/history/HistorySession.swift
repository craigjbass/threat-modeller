import Foundation
import Observation
import ThreatModelKit

/// Reads the project's git history, for the History sheet to show.
@MainActor
@Observable
final class HistorySession {
    private let useCases: UseCaseFactory
    private let root: String

    private(set) var found = RiskHistory()
    var rows: [RiskHistoryRow] { found.rows }
    var truncated: Bool { found.truncated }
    private(set) var isReading = false
    private(set) var message: String?
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

    var oldestFirst: [RiskHistoryRow] {
        rows.reversed()
    }

    var highestTotal: Int {
        max(rows.compactMap { $0.numbers?.totalScore }.max() ?? 0, 1)
    }
}
