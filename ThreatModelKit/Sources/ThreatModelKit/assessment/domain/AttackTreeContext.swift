/// What the sufficient control rule of `AttackTreeBinding` reads from the
/// model and the catalogue: every control description the catalogue and the
/// libraries hold, the proofs the `.controls` file states, and the risk
/// level at and above which the policy demands evidence.
///
/// The assessment and the compile both bind the trees, so both build one of
/// these from the same two rules.
public struct AttackTreeContext: Sendable {
    /// Every control description the catalogue states on any threat, and
    /// every technology mitigation the catalogue and the `.lib` files state.
    public let knownControls: Set<String>
    public let proofs: [ControlKey: ControlProof]
    public let evidenceDemandedAbove: RiskLevel?

    public init(model: ThreatModel, catalogue: TechnologyCatalogue) {
        var known: Set<String> = []
        for threat in catalogue.everyThreat() {
            for control in threat.controls { known.insert(control.description) }
        }
        for technology in TechnologyLookup(model: model, catalogue: catalogue).all() {
            for descriptions in technology.threatMitigations.values {
                known.formUnion(descriptions)
            }
        }
        knownControls = known
        proofs = model.controlProofs
        evidenceDemandedAbove = Self.moreDemandingOfArchAndPolicy(
            model.requiresEvidenceAbove,
            model.policy?.implementedRequiresEvidenceAbove
        )
    }

    private static func moreDemandingOfArchAndPolicy(_ left: RiskLevel?, _ right: RiskLevel?) -> RiskLevel? {
        switch (left, right) {
        case (nil, nil): nil
        case (let level?, nil), (nil, let level?): level
        case (let left?, let right?): left.rank <= right.rank ? left : right
        }
    }
}

public extension AttackTreeBinding {
    /// Binds with what the model and the catalogue hold.
    static func bind(
        trees: [SourceAttackTree],
        to resolved: [ResolvedThreat],
        context: AttackTreeContext
    ) -> [BoundAttackTree] {
        bind(
            trees: trees,
            to: resolved,
            known: context.knownControls,
            proofs: context.proofs,
            evidenceDemandedAbove: context.evidenceDemandedAbove
        )
    }
}
