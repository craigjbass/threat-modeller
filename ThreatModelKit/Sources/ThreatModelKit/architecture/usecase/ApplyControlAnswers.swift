public protocol ApplyControlAnswersUseCase {
    func execute(_ request: ApplyControlAnswersRequest) -> ApplyControlAnswersResponse
}

public struct ApplyControlAnswersRequest: Equatable, Sendable {
    public let text: String
    public init(text: String) { self.text = text }
}

public enum ApplyControlAnswersResponse: Equatable, Sendable {
    case applied(answers: Int, warnings: [Diagnostic])
    case refused(diagnostics: [Diagnostic])
}

/// Puts what a controls file says onto the model on screen.
///
/// An answer naming a control the model does not offer is a warning, not an
/// error: a catalogue moved under a committed file, and that is what the
/// warning says.
public struct ApplyControlAnswers: ApplyControlAnswersUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let sources: ControlsSourceGateway

    public init(
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        sources: ControlsSourceGateway
    ) {
        self.models = models
        self.catalogue = catalogue
        self.sources = sources
    }

    public func execute(_ request: ApplyControlAnswersRequest) -> ApplyControlAnswersResponse {
        let read = sources.read(request.text)
        guard let source = read.source, read.hasErrors == false else {
            return .refused(diagnostics: read.diagnostics)
        }

        let model = models.current()
        let resolved = ThreatResolver(model: model, catalogue: catalogue).resolve()

        // Every control this model offers, by the threat it answers and its
        // description. That is what a file names.
        var keysByThreat: [String: [String: ControlKey]] = [:]
        for threat in resolved {
            let key = ThreatKey(threatId: threat.threat.id.value, sourceId: threat.source.id).value
            keysByThreat[key] = Dictionary(
                threat.controls.map { ($0.description, $0.key) },
                uniquingKeysWith: { first, _ in first }
            )
        }

        var statuses: [ControlKey: ControlStatus] = [:]
        var compensating: [ThreatKey: [CompensatingControl]] = [:]
        var recommendations: [ThreatKey: [Recommendation]] = [:]
        var likelihoods: [ThreatKey: LikelihoodFinding] = [:]
        var decisions: [ThreatKey: SeverityDecision] = [:]
        var warnings = read.warnings
        var applied = 0

        for answer in source.answers where answer.isStale == false {
            guard let offered = keysByThreat[answer.key.value] else {
                warnings.append(
                    Diagnostic(
                        severity: .warning,
                        line: 1,
                        column: 1,
                        message: "this model does not raise \"\(answer.threatId)\" on "
                            + "\(answer.sourceKind) \"\(answer.sourceId)\", so its answers are not applied"
                    )
                )
                continue
            }

            for control in answer.controls {
                guard let key = offered[control.description] else {
                    warnings.append(
                        Diagnostic(
                            severity: .warning,
                            line: 1,
                            column: 1,
                            message: "\"\(answer.threatId)\" no longer offers the control "
                                + "\"\(control.description)\", so its answer is not applied"
                        )
                    )
                    continue
                }
                statuses[key] = control.status
                if control.status.isAnswered { applied += 1 }
            }

            if answer.compensating.isEmpty == false {
                compensating[answer.key] = answer.compensating
                applied += answer.compensating.count
            }

            if answer.recommendations.isEmpty == false {
                recommendations[answer.key] = answer.recommendations.map {
                    Recommendation(text: $0.text, note: $0.note)
                }
            }

            if let finding = answer.likelihood {
                likelihoods[answer.key] = finding
            }

            if let decision = answer.severityDecision {
                if catalogue.taxonomy().severity(id: decision.severityId) == nil {
                    warnings.append(
                        Diagnostic(
                            severity: .warning,
                            line: 1,
                            column: 1,
                            message: "\"\(decision.severityId)\" is not a severity this catalogue holds, "
                                + "so the severity_override on \"\(answer.threatId)\" is not applied"
                        )
                    )
                } else {
                    decisions[answer.key] = decision
                }
            }
        }

        let readStatuses = statuses
        let readCompensating = compensating
        let readRecommendations = recommendations
        let readLikelihoods = likelihoods
        let readDecisions = decisions
        let count = applied
        let readWarnings = warnings

        return models.mutate { model in
            model.controlStatuses = readStatuses
            model.compensatingControls = readCompensating
            model.recommendations = readRecommendations
            model.likelihoodFindings = readLikelihoods
            model.severityDecisions = readDecisions
            return .applied(answers: count, warnings: readWarnings)
        }
    }
}
