public protocol ApplyControlAnswersUseCase {
    func execute(_ request: ApplyControlAnswersRequest) -> ApplyControlAnswersResponse
}

public struct ApplyControlAnswersRequest: Equatable, Sendable {
    public let text: String
    /// True when the file is one part of a split system, read after another
    /// part. The answers join the answers on screen instead of replacing them.
    public let addsToEarlierParts: Bool

    public init(text: String, addsToEarlierParts: Bool = false) {
        self.text = text
        self.addsToEarlierParts = addsToEarlierParts
    }
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
        var proofs: [ControlKey: ControlProof] = [:]
        var notes: [ControlKey: String] = [:]
        var mitigatedBy: [ControlKey: [ControlMitigation]] = [:]
        var compensating: [ThreatKey: [CompensatingControl]] = [:]
        var recommendations: [ThreatKey: [Recommendation]] = [:]
        var likelihoods: [ThreatKey: LikelihoodFinding] = [:]
        var decisions: [ThreatKey: SeverityDecision] = [:]
        var impacts: [ThreatKey: [ThreatImpact]] = [:]
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
                var status = control.status
                var mapped: [ControlMitigation] = []
                for mitigation in control.mitigations {
                    switch Self.read(
                        edgeId: mitigation.edgeId,
                        answering: answer,
                        in: model.mitigatesEdges
                    ) {
                    case .unknown:
                        warnings.append(
                            Diagnostic(
                                severity: .warning,
                                line: 1,
                                column: 1,
                                message: "the control \"\(control.description)\" names the "
                                    + "mitigates edge \"\(mitigation.edgeId)\", which this system "
                                    + "does not declare, so the mapping is not applied"
                            )
                        )
                    case .answersSomethingElse:
                        warnings.append(
                            Diagnostic(
                                severity: .warning,
                                line: 1,
                                column: 1,
                                message: "the mitigates edge \"\(mitigation.edgeId)\" does not "
                                    + "answer \"\(answer.threatId)\" on \(answer.sourceKind) "
                                    + "\"\(answer.sourceId)\", so the mapping is not applied"
                            )
                        )
                    case .proposed:
                        mapped.append(mitigation)
                        if status == .implemented {
                            status = .notImplemented
                            warnings.append(
                                Diagnostic(
                                    severity: .warning,
                                    line: 1,
                                    column: 1,
                                    message: "the mitigates edge \"\(mitigation.edgeId)\" is "
                                        + "proposed, so the control "
                                        + "\"\(control.description)\" is not implemented"
                                )
                            )
                        }
                    case .live:
                        mapped.append(mitigation)
                    }
                }
                if mapped.isEmpty == false { mitigatedBy[key] = mapped }
                statuses[key] = status
                if control.proof.isEmpty == false { proofs[key] = control.proof }
                if let controlNote = control.note, controlNote.isEmpty == false {
                    notes[key] = controlNote
                }
                if status.isAnswered { applied += 1 }
            }

            if answer.compensating.isEmpty == false {
                compensating[answer.key] = answer.compensating
                applied += answer.compensating.count
            }

            if answer.recommendations.isEmpty == false {
                recommendations[answer.key] = answer.recommendations.map {
                    Recommendation(text: $0.text, note: $0.note, sources: $0.sources)
                }
            }

            if answer.impacts.isEmpty == false {
                impacts[answer.key] = answer.impacts.compactMap(ThreatImpact.init(rawValue:))
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
        let readProofs = proofs
        let readNotes = notes
        let readMitigatedBy = mitigatedBy
        let readCompensating = compensating
        let readRecommendations = recommendations
        let readLikelihoods = likelihoods
        let readDecisions = decisions
        let readImpacts = impacts
        let count = applied
        let readWarnings = warnings

        let adds = request.addsToEarlierParts
        return models.mutate(label: ChangeLabel.applyAnswers) { model in
            func joined<Key, Value>(_ held: [Key: Value], _ read: [Key: Value]) -> [Key: Value] {
                adds ? held.merging(read) { _, part in part } : read
            }
            model.controlStatuses = joined(model.controlStatuses, readStatuses)
            model.controlProofs = joined(model.controlProofs, readProofs)
            model.controlNotes = joined(model.controlNotes, readNotes)
            model.controlMitigatedBy = joined(model.controlMitigatedBy, readMitigatedBy)
            model.compensatingControls = joined(model.compensatingControls, readCompensating)
            model.recommendations = joined(model.recommendations, readRecommendations)
            model.likelihoodFindings = joined(model.likelihoodFindings, readLikelihoods)
            model.severityDecisions = joined(model.severityDecisions, readDecisions)
            model.impactOverrides = joined(model.impactOverrides, readImpacts)
            return .applied(answers: count, warnings: readWarnings)
        }
    }

    /// What the model says about the edge a control names.
    private enum EdgeReading {
        /// No edge of this model carries that identifier.
        case unknown
        /// An edge carries the identifier and protects another element.
        case answersSomethingElse
        case live
        case proposed
    }

    /// An edge answers a control only when it protects the element the answer
    /// is written on. Which threats it answers is what the controls that name
    /// it say, so the edge states no threats of its own.
    private static func read(
        edgeId: String,
        answering answer: SourceThreatAnswer,
        in edges: [MitigatesEdge]
    ) -> EdgeReading {
        guard let edge = edges.first(where: { $0.id == edgeId }) else { return .unknown }
        guard answer.sourceKind == "component",
              edge.target.value == answer.sourceId else { return .answersSomethingElse }
        return edge.effectiveStatus == .proposed ? .proposed : .live
    }
}
