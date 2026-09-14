import Foundation

public protocol CompileGovernanceUseCase {
    func execute(_ request: CompileGovernanceRequest) -> CompileGovernanceResponse
}

public struct CompileGovernanceRequest: Equatable, Sendable {
    /// The answers the controls compile wrote.
    public let controlsText: String
    /// The governance as it is now, or nil the first time.
    public let governanceText: String?
    /// The actions the `.arch` file declares, in the order it declares them.
    public let actionLabels: [String]

    public init(controlsText: String, governanceText: String? = nil, actionLabels: [String] = []) {
        self.controlsText = controlsText
        self.governanceText = governanceText
        self.actionLabels = actionLabels
    }
}

public enum CompileGovernanceResponse: Equatable, Sendable {
    /// The file to write, or nil when the system governs nothing: no accepted
    /// control, no recommendation and no action. Nothing writes an empty file.
    case compiled(text: String?, governed: Int, stale: Int)
    case refused(diagnostics: [Diagnostic])
}

/// Writes the governance file from the compiled answers.
///
/// It never deletes a stanza. A stanza whose control is still accepted is kept
/// whole; a control that is accepted and ungoverned appears with every field
/// empty; a control that is no longer accepted is marked `stale` and waits for
/// a person to remove it.
public struct CompileGovernance: CompileGovernanceUseCase {
    private let controlsSources: ControlsSourceGateway
    private let governanceSources: GovernanceSourceGateway

    public init(
        controlsSources: ControlsSourceGateway,
        governanceSources: GovernanceSourceGateway
    ) {
        self.controlsSources = controlsSources
        self.governanceSources = governanceSources
    }

    public func execute(_ request: CompileGovernanceRequest) -> CompileGovernanceResponse {
        let read = controlsSources.read(request.controlsText)
        guard let answers = read.source, read.hasErrors == false else {
            return .refused(diagnostics: read.diagnostics)
        }

        var existing: GovernanceSource?
        if let governanceText = request.governanceText, governanceText.isEmpty == false {
            let read = governanceSources.read(governanceText)
            guard let source = read.source, read.hasErrors == false else {
                return .refused(diagnostics: read.diagnostics)
            }
            existing = source
        }

        var threats: [SourceGovernedThreat] = []
        var governed = 0
        var stale = 0
        var keysWritten: Set<String> = []

        for answer in answers.answers where answer.isStale == false {
            let previous = existing?.threat(for: answer.key)
            let accepted = answer.controls
                .filter { $0.status == .accepted }
                .map { control in
                    Self.kept(
                        previous?.accepted.first { $0.control == control.description },
                        control: control.description
                    )
                }
            let work = answer.recommendations.map { recommendation in
                Self.kept(
                    previous?.work.first { $0.label == recommendation.text },
                    label: recommendation.text
                )
            }

            // A control that is no longer accepted, and a recommendation that
            // is gone, each keep their stanza and are marked stale.
            let goneAccepted = (previous?.accepted ?? [])
                .filter { previous in accepted.contains { $0.control == previous.control } == false }
                .map { Self.staled($0) }
            let goneWork = (previous?.work ?? [])
                .filter { previous in work.contains { $0.label == previous.label } == false }
                .map { Self.staled($0) }

            guard accepted.isEmpty == false
                || work.isEmpty == false
                || goneAccepted.isEmpty == false
                || goneWork.isEmpty == false else { continue }

            keysWritten.insert(answer.key.value)
            governed += accepted.count + work.count
            stale += goneAccepted.count + goneWork.count
            threats.append(
                SourceGovernedThreat(
                    threatId: answer.threatId,
                    sourceKind: answer.sourceKind,
                    sourceId: answer.sourceId,
                    accepted: accepted + goneAccepted,
                    work: work + goneWork,
                    isStale: false
                )
            )
        }

        // A threat the architecture no longer raises keeps its whole block,
        // marked stale.
        for previous in existing?.threats ?? []
        where keysWritten.contains(previous.key.value) == false {
            threats.append(
                SourceGovernedThreat(
                    threatId: previous.threatId,
                    sourceKind: previous.sourceKind,
                    sourceId: previous.sourceId,
                    accepted: previous.accepted.map { Self.staled($0) },
                    work: previous.work.map { Self.staled($0) },
                    isStale: true
                )
            )
            stale += previous.accepted.count + previous.work.count
        }

        var actions = request.actionLabels.map { label in
            Self.kept(existing?.actions.first { $0.label == label }, label: label)
        }
        governed += actions.count
        let goneActions = (existing?.actions ?? [])
            .filter { previous in request.actionLabels.contains(previous.label) == false }
            .map { Self.staled($0) }
        actions += goneActions
        stale += goneActions.count

        guard threats.isEmpty == false || actions.isEmpty == false else {
            return .compiled(text: nil, governed: 0, stale: 0)
        }

        return .compiled(
            text: governanceSources.write(
                GovernanceSource(
                    systemName: answers.systemName,
                    threats: threats,
                    actions: actions
                )
            ),
            governed: governed,
            stale: stale
        )
    }

    /// The stanza a person already wrote, or an empty one for a control the
    /// file does not govern yet.
    private static func kept(_ previous: SourceAcceptedRisk?, control: String) -> SourceAcceptedRisk {
        guard let previous else { return SourceAcceptedRisk(control: control) }
        return SourceAcceptedRisk(
            control: previous.control,
            owner: previous.owner,
            acceptedOn: previous.acceptedOn,
            reviewBy: previous.reviewBy,
            rationale: previous.rationale,
            sources: previous.sources,
            isStale: false
        )
    }

    private static func kept(_ previous: SourcePlannedWork?, label: String) -> SourcePlannedWork {
        guard let previous else { return SourcePlannedWork(label: label) }
        return SourcePlannedWork(
            label: previous.label,
            owner: previous.owner,
            effort: previous.effort,
            dueBy: previous.dueBy,
            status: previous.status,
            acceptance: previous.acceptance,
            note: previous.note,
            sources: previous.sources,
            isStale: false
        )
    }

    private static func staled(_ risk: SourceAcceptedRisk) -> SourceAcceptedRisk {
        SourceAcceptedRisk(
            control: risk.control,
            owner: risk.owner,
            acceptedOn: risk.acceptedOn,
            reviewBy: risk.reviewBy,
            rationale: risk.rationale,
            sources: risk.sources,
            isStale: true
        )
    }

    private static func staled(_ work: SourcePlannedWork) -> SourcePlannedWork {
        SourcePlannedWork(
            label: work.label,
            owner: work.owner,
            effort: work.effort,
            dueBy: work.dueBy,
            status: work.status,
            acceptance: work.acceptance,
            note: work.note,
            sources: work.sources,
            isStale: true
        )
    }
}
