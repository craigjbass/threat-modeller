public protocol AssessLeverageUseCase {
    func execute(_ request: AssessLeverageRequest) -> AssessLeverageResponse
}

public struct AssessLeverageRequest: Equatable, Sendable {
    public init() {}
}

/// What one action would remove, and what the model scores without it.
public struct LeverageOfAction: Equatable, Sendable {
    public let action: Action
    /// Residual points this action removes across the whole model, measured
    /// alone against today's posture. Not additive: two actions answering
    /// one threat do not sum, so never add two `removes` values together.
    public let removes: Int
    /// The sum of every threat's residual score before any action.
    public let totalResidual: Int
    /// How many threats it moves at all.
    public let threatsMoved: Int
    /// The worst residual score anywhere in the model, before and after. An
    /// action that removes points without moving the headline reports one
    /// number twice.
    public let worstBefore: Int
    public let worstAfter: Int

    public init(
        action: Action,
        removes: Int,
        totalResidual: Int,
        threatsMoved: Int,
        worstBefore: Int,
        worstAfter: Int
    ) {
        self.action = action
        self.removes = removes
        self.totalResidual = totalResidual
        self.threatsMoved = threatsMoved
        self.worstBefore = worstBefore
        self.worstAfter = worstAfter
    }
}

public struct AssessLeverageResponse: Equatable, Sendable {
    /// Worst first, ties broken by label, so two runs of one model rank the
    /// same.
    public let leverage: [LeverageOfAction]
    public let totalResidual: Int
    public let worst: Int

    public init(leverage: [LeverageOfAction], totalResidual: Int, worst: Int) {
        self.leverage = leverage
        self.totalResidual = totalResidual
        self.worst = worst
    }
}

/// Measures what each action would remove.
///
/// It measures by resolving the model again with one action's edges adopted,
/// never by repeating a stage's arithmetic. A second copy of a stage is how a
/// report comes to publish a reduction the engine does not apply.
///
/// WARNING: leverage is not additive. Each action is measured alone against
/// today's posture, and two actions answering one threat give the stronger
/// reduction, never the sum. Whatever prints these numbers says so.
public struct AssessLeverage: AssessLeverageUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: AssessLeverageRequest) -> AssessLeverageResponse {
        let model = models.current()
        let baseline = scores(of: model)
        let actions = Actions.build(from: model.mitigatesEdges)

        guard actions.isEmpty == false else {
            return AssessLeverageResponse(
                leverage: [],
                totalResidual: baseline.total,
                worst: baseline.worst
            )
        }

        let measured = actions.map { action -> LeverageOfAction in
            var adopted = model
            adopted.mitigatesEdges = model.mitigatesEdges.map { edge in
                guard action.edgeIds.contains(edge.id) else { return edge }
                return MitigatesEdge(
                    source: edge.source,
                    target: edge.target,
                    threatIds: edge.threatIds,
                    reducesRiskBy: edge.reducesRiskBy,
                    status: .adopted,
                    action: edge.action
                )
            }
            let after = scores(of: adopted)

            return LeverageOfAction(
                action: action,
                // `max(0, ...)` never fires: `ComponentMitigations` always
                // takes the strongest answering edge, so adopting one more
                // edge can only lower a score, never raise it, and the
                // parser rejects a `reduces_risk_by` outside 0 to 100. The
                // floor stays as a guard against a future change to either
                // fact, not because this one can go negative today.
                removes: max(0, baseline.total - after.total),
                totalResidual: baseline.total,
                threatsMoved: baseline.byKey.filter { key, score in
                    (after.byKey[key] ?? score) < score
                }.count,
                worstBefore: baseline.worst,
                worstAfter: after.worst
            )
        }

        return AssessLeverageResponse(
            leverage: measured.sorted { left, right in
                if left.removes != right.removes { return left.removes > right.removes }
                return left.action.label < right.action.label
            },
            totalResidual: baseline.total,
            worst: baseline.worst
        )
    }

    /// Every threat's residual score, keyed by threat and source.
    private func scores(of model: ThreatModel) -> (total: Int, worst: Int, byKey: [String: Int]) {
        let resolved = ThreatResolver(model: model, catalogue: catalogue).resolve()
        var byKey: [String: Int] = [:]
        for threat in resolved {
            byKey["\(threat.threat.id.value)@\(threat.source.id)"] = threat.score.value
        }
        return (
            byKey.values.reduce(0, +),
            byKey.values.max() ?? 0,
            byKey
        )
    }
}
