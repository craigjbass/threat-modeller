public protocol ApplyGovernanceUseCase {
    func execute(_ request: ApplyGovernanceRequest) -> ApplyGovernanceResponse
}

public struct ApplyGovernanceRequest: Equatable, Sendable {
    public let text: String

    public init(text: String) {
        self.text = text
    }
}

public enum ApplyGovernanceResponse: Equatable, Sendable {
    case applied(accepted: Int, work: Int)
    case refused(diagnostics: [Diagnostic])
}

/// Puts a governance file's decisions onto the model.
///
/// It moves no score. The report reads what it writes, and so does the threat
/// card: an accepted risk states who carries it, and planned work states who
/// does it.
public struct ApplyGovernance: ApplyGovernanceUseCase {
    private let models: ThreatModelGateway
    private let sources: GovernanceSourceGateway

    public init(models: ThreatModelGateway, sources: GovernanceSourceGateway) {
        self.models = models
        self.sources = sources
    }

    public func execute(_ request: ApplyGovernanceRequest) -> ApplyGovernanceResponse {
        let read = sources.read(request.text)
        guard let source = read.source, read.hasErrors == false else {
            return .refused(diagnostics: read.diagnostics)
        }

        var accepted: [ThreatKey: [RiskAcceptance]] = [:]
        var work: [ThreatKey: [PlannedWork]] = [:]

        // A stale stanza states a decision about something that is no longer
        // there, so nothing reads it.
        for threat in source.threats where threat.isStale == false {
            let live = threat.accepted.filter { $0.isStale == false }
            if live.isEmpty == false {
                accepted[threat.key] = live.map(Self.acceptance)
            }
            let planned = threat.work.filter { $0.isStale == false }
            if planned.isEmpty == false {
                work[threat.key] = planned.map(Self.work)
            }
        }

        var actions: [String: PlannedWork] = [:]
        for action in source.actions where action.isStale == false {
            actions[action.label] = Self.work(action)
        }

        return models.mutate { model in
            model.acceptedRisks = accepted
            model.plannedWork = work
            model.actionWork = actions
            return .applied(
                accepted: accepted.values.reduce(0) { $0 + $1.count },
                work: work.values.reduce(0) { $0 + $1.count } + actions.count
            )
        }
    }

    private static func acceptance(_ source: SourceAcceptedRisk) -> RiskAcceptance {
        RiskAcceptance(
            control: source.control,
            owner: source.owner,
            acceptedOn: source.acceptedOn.flatMap { try? GovernanceDate.read($0).get() },
            reviewBy: source.reviewBy.flatMap { try? GovernanceDate.read($0).get() },
            rationale: source.rationale,
            sources: source.sources
        )
    }

    private static func work(_ source: SourcePlannedWork) -> PlannedWork {
        PlannedWork(
            label: source.label,
            owner: source.owner,
            effort: source.effort.flatMap(PlannedWork.Effort.init(rawValue:)),
            dueBy: source.dueBy.flatMap { try? GovernanceDate.read($0).get() },
            status: PlannedWork.Status(rawValue: source.status) ?? .planned,
            acceptance: source.acceptance,
            note: source.note,
            sources: source.sources
        )
    }
}
