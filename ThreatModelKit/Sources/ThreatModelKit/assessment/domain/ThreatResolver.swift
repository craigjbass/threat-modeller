/// One control offered against a resolved threat.
public struct ResolvedControl: Equatable, Sendable {
    public let description: String
    /// True when the control came from the technology rather than the threat.
    public let isTechnologySpecific: Bool
    public let key: ControlKey
    /// True when the model records this control as in place.
    public let isImplemented: Bool
    /// What the user said about it. A control nobody has answered is
    /// `not_implemented`.
    public let status: ControlStatus
    /// What the user wrote beside the answer, or nil.
    public let note: String?

    public init(
        description: String,
        isTechnologySpecific: Bool,
        key: ControlKey,
        isImplemented: Bool,
        status: ControlStatus? = nil,
        note: String? = nil
    ) {
        self.description = description
        self.isTechnologySpecific = isTechnologySpecific
        self.key = key
        self.isImplemented = isImplemented
        self.status = status ?? (isImplemented ? .implemented : .notImplemented)
        self.note = note
    }
}

/// What raised a threat, in domain terms.
public enum ResolvedSource: Hashable, Sendable {
    case component(id: ComponentId, name: String, providerId: ProviderId)
    case connection(id: ConnectionId, sourceName: String, targetName: String)
    case zone(id: ZoneId, name: String)

    public var displayName: String {
        switch self {
        case .component(_, let name, _):
            name
        case .connection(_, let sourceName, let targetName):
            "\(sourceName) \u{2192} \(targetName)"
        case .zone(_, let name):
            name
        }
    }

    /// Identifies the source across kinds. Two sources of different kinds never
    /// share one.
    public var id: String {
        switch self {
        case .component(let id, _, _):
            "component:\(id.value)"
        case .connection(let id, _, _):
            "connection:\(id.value)"
        case .zone(let id, _):
            "zone:\(id.value)"
        }
    }
}

/// One threat the model raises, scored.
public struct ResolvedThreat: Equatable, Sendable {
    public let threat: Threat
    /// The severity the score used. The threat's own, unless overridden.
    public let severity: ThreatSeverity
    public let source: ResolvedSource
    public let sensitivity: DataSensitivity
    public let score: RiskScore
    public let controls: [ResolvedControl]
    public let context: String?
    public let isTlsMitigated: Bool
    /// The key an override for this threat is recorded under. Spec section 5.3
    /// keys a component threat by its technology, so every component of that
    /// technology shares one override.
    public let overrideKey: SeverityOverrideKey
    /// The severity id the user overrode this threat to, or nil. When set,
    /// `severity` is that severity rather than the threat's own.
    public let overriddenSeverityId: String?
    /// The mitigations that answered this threat. Empty when none did.
    public let mitigatedBy: [PathwayMitigationDefinition]
    /// What compensates this threat, from the controls file.
    public let compensating: [CompensatingControl]
    /// The score before the compensating control was applied. Equal to
    /// `score.value` when none was.
    public let scoreBeforeCompensation: Int
    /// The score before any pathway mitigation. Equal to `score.value` when
    /// none applied.
    public let scoreBeforePathwayMitigation: Int
    /// The score before the controls answered anything. Equal to `score.value`
    /// when no control was implemented.
    public let scoreBeforeControls: Int
    /// The components whose `mitigates` edges lowered this threat.
    public let mitigatedByComponents: [ComponentMitigation]
    /// How often an attack of this kind happens, and what the stage used.
    public let likelihood: Likelihood
    /// The score the likelihood stage received. Equal to `score.value` when
    /// the likelihood is `commodity`.
    public let scoreBeforeLikelihood: Int

    public init(
        threat: Threat,
        severity: ThreatSeverity,
        source: ResolvedSource,
        sensitivity: DataSensitivity,
        score: RiskScore,
        controls: [ResolvedControl],
        context: String?,
        isTlsMitigated: Bool,
        overrideKey: SeverityOverrideKey,
        overriddenSeverityId: String?,
        mitigatedBy: [PathwayMitigationDefinition],
        scoreBeforePathwayMitigation: Int,
        scoreBeforeControls: Int? = nil,
        compensating: [CompensatingControl] = [],
        scoreBeforeCompensation: Int? = nil,
        mitigatedByComponents: [ComponentMitigation] = [],
        likelihood: Likelihood = .commodity,
        scoreBeforeLikelihood: Int? = nil
    ) {
        self.scoreBeforeControls = scoreBeforeControls ?? score.value
        self.compensating = compensating
        self.scoreBeforeCompensation = scoreBeforeCompensation ?? score.value
        self.threat = threat
        self.severity = severity
        self.source = source
        self.sensitivity = sensitivity
        self.score = score
        self.controls = controls
        self.context = context
        self.isTlsMitigated = isTlsMitigated
        self.overrideKey = overrideKey
        self.overriddenSeverityId = overriddenSeverityId
        self.mitigatedBy = mitigatedBy
        self.scoreBeforePathwayMitigation = scoreBeforePathwayMitigation
        self.mitigatedByComponents = mitigatedByComponents
        self.likelihood = likelihood
        self.scoreBeforeLikelihood = scoreBeforeLikelihood ?? score.value
    }
}

/// Resolves every threat a model raises, and scores each one.
///
/// Component threats come from the component's technology. Connection threats
/// come from the catalogue and belong to the link, not to either end. Zone
/// threats belong to each private zone. `AssessThreatModel` turns the result
/// into plain values for a delivery mechanism; `SummariseRisk` counts it. Both
/// read this one resolution, so a count can never disagree with a list.
public struct ThreatResolver {
    private let model: ThreatModel
    private let catalogue: TechnologyCatalogue
    private let lookup: TechnologyLookup

    public init(model: ThreatModel, catalogue: TechnologyCatalogue) {
        self.model = model
        self.catalogue = catalogue
        lookup = TechnologyLookup(model: model, catalogue: catalogue)
    }

    public func resolve() -> [ResolvedThreat] {
        var resolved: [ResolvedThreat] = []
        // Spec section 5.3: a duplicate threat and source pair is raised once.
        var raised: Set<String> = []

        func raise(_ threat: ResolvedThreat) {
            let pair = "\(threat.threat.id.value)@\(threat.source.id)"
            guard raised.contains(pair) == false else { return }
            raised.insert(pair)
            resolved.append(compensated(likelihooded(threat)))
        }

        // Derived, never stored. Spec section 5.2.
        var zonesByComponent: [ComponentId: Zone] = [:]
        var sensitivityById: [ComponentId: DataSensitivity] = [:]
        var technologyById: [ComponentId: TechnologyId] = [:]
        for component in model.components {
            zonesByComponent[component.id] = ZoneContainment.zone(
                holding: component.centre,
                in: model.zones
            )
            sensitivityById[component.id] = component.effectiveSensitivity
            technologyById[component.id] = component.technologyId
        }
        let graph = UpstreamGraph(connections: model.connections)

        // Names every component once, for the `mitigates` stage to report
        // which component answered a threat.
        var nameById: [ComponentId: String] = [:]
        for component in model.components {
            nameById[component.id] = component.customName
                ?? lookup.findById(component.technologyId)?.name
                ?? component.technologyId.value
        }

        for component in model.components {
            guard component.threatsDisabled == false else { continue }
            guard let technology = lookup.findById(component.technologyId) else { continue }

            let multiplier = ZoneMultiplier.value(for: zonesByComponent[component.id])

            for threat in lookup.threatsFor(technologyId: component.technologyId) {
                guard ThreatApplicability.appliesToComponent(
                    threat: threat,
                    runsAs: component.runsAs
                ) else { continue }
                let overrideKey = SeverityOverrideKey.forComponent(
                    technologyId: component.technologyId,
                    threatId: threat.id
                )
                let chosen = severity(for: threat, overrideKey: overrideKey)
                let sensitivity = escalated(
                    threat: threat,
                    on: component,
                    graph: graph,
                    sensitivityById: sensitivityById
                )
                let base = RiskScore(severity: chosen.severity, sensitivity: sensitivity)
                let zoned = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard zoned.value > 0 else { continue }
                let controls = componentControls(
                    for: threat,
                    on: technology,
                    componentId: component.id
                )
                let covered = ControlCoverage.apply(to: zoned.value, controls: controls)
                guard let mitigation = mitigated(
                    threat: threat,
                    score: covered,
                    upstreamOf: component.id,
                    graph: graph,
                    technologyById: technologyById
                ) else { continue }
                let byComponents = ComponentMitigations.apply(
                    score: mitigation.score,
                    threatId: threat.id,
                    target: component.id,
                    edges: model.mitigatesEdges,
                    nameOf: { nameById[$0] ?? $0.value }
                )
                let score = RiskScore(value: byComponents.score)

                raise(
                    ResolvedThreat(
                        threat: threat,
                        severity: chosen.severity,
                        source: .component(
                            id: component.id,
                            name: component.customName ?? technology.name,
                            providerId: technology.provider
                        ),
                        sensitivity: sensitivity,
                        score: score,
                        controls: controls,
                        context: technology.threatContext[threat.id],
                        isTlsMitigated: false,
                        overrideKey: overrideKey,
                        overriddenSeverityId: chosen.overriddenId,
                        mitigatedBy: mitigation.by,
                        scoreBeforePathwayMitigation: covered,
                        scoreBeforeControls: zoned.value,
                        mitigatedByComponents: byComponents.by
                    )
                )
            }
        }

        for connection in model.connections {
            guard let source = model.component(connection.source),
                  let target = model.component(connection.target) else { continue }
            guard source.threatsDisabled == false, target.threatsDisabled == false else { continue }

            let sourceTechnology = lookup.findById(source.technologyId)
            let targetTechnology = lookup.findById(target.technologyId)
            let sensitivity = SensitivityLadder.higher(source.effectiveSensitivity, target.effectiveSensitivity)
            let multiplier = ZoneMultiplier.valueForConnection(
                sourceZone: zonesByComponent[source.id],
                targetZone: zonesByComponent[target.id]
            )
            let crossesPrivilege = source.runsAs != target.runsAs

            for threat in catalogue.connectionThreats() {
                guard ThreatApplicability.appliesToConnection(
                    threat: threat,
                    kind: connection.kind,
                    crossesPrivilege: crossesPrivilege
                ) else { continue }
                let overrideKey = SeverityOverrideKey.forConnection(threatId: threat.id)
                let chosen = severity(for: threat, overrideKey: overrideKey)
                let base = RiskScore(severity: chosen.severity, sensitivity: sensitivity)
                let zoned = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard zoned.value > 0 else { continue }
                // Spec section 5.3: a link always uses the threat's own
                // controls, never a technology's mitigations.
                let controls = sharedControls(for: threat, keyedBy: ControlIdentity.connectionControl)
                let covered = ControlCoverage.apply(to: zoned.value, controls: controls)
                // Spec section 5.3: a link takes the source component's
                // upstream mitigations.
                guard let mitigation = mitigated(
                    threat: threat,
                    score: covered,
                    upstreamOf: source.id,
                    graph: graph,
                    technologyById: technologyById
                ) else { continue }
                let score = RiskScore(value: mitigation.score)

                raise(
                    ResolvedThreat(
                        threat: threat,
                        severity: chosen.severity,
                        source: .connection(
                            id: connection.id,
                            sourceName: Self.name(of: source, as: sourceTechnology),
                            targetName: Self.name(of: target, as: targetTechnology)
                        ),
                        sensitivity: sensitivity,
                        score: score,
                        controls: controls,
                        context: nil,
                        isTlsMitigated: ConnectionEncryption.isTlsMitigated(
                            threat: threat,
                            source: sourceTechnology,
                            target: targetTechnology
                        ),
                        overrideKey: overrideKey,
                        overriddenSeverityId: chosen.overriddenId,
                        mitigatedBy: mitigation.by,
                        scoreBeforePathwayMitigation: covered,
                        scoreBeforeControls: zoned.value
                    )
                )
            }
        }

        // Spec section 5.3: raised once per private zone, scored against a
        // fixed internal sensitivity, and reduced by that zone's own
        // multiplier. A public zone raises none.
        for zone in model.zones where zone.networkZone == .privateZone {
            let multiplier = ZoneMultiplier.value(for: zone)

            for threat in catalogue.zoneThreats() {
                guard ThreatApplicability.appliesToZone(
                    threat: threat,
                    boundary: zone.boundary
                ) else { continue }
                let overrideKey = SeverityOverrideKey.forZone(threatId: threat.id)
                let chosen = severity(for: threat, overrideKey: overrideKey)
                let base = RiskScore(severity: chosen.severity, sensitivity: .internalData)
                let zoned = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard zoned.value > 0 else { continue }
                let controls = sharedControls(for: threat, keyedBy: ControlIdentity.zoneControl)
                let score = RiskScore(value: ControlCoverage.apply(to: zoned.value, controls: controls))

                raise(
                    ResolvedThreat(
                        threat: threat,
                        severity: chosen.severity,
                        source: .zone(id: zone.id, name: zone.displayName),
                        sensitivity: .internalData,
                        score: score,
                        controls: controls,
                        context: threat.zoneContext,
                        isTlsMitigated: false,
                        overrideKey: overrideKey,
                        overriddenSeverityId: chosen.overriddenId,
                        // A zone sits nowhere in the connection graph, so
                        // nothing is upstream of it and nothing mitigates it.
                        mitigatedBy: [],
                        scoreBeforePathwayMitigation: score.value,
                        scoreBeforeControls: zoned.value
                    )
                )
            }
        }

        return resolved.sorted(by: Self.ordering)
    }

    /// Spec section 3: the likelihood stage runs after the `mitigates` edges
    /// and before the compensating control. It multiplies, because a
    /// likelihood finding and a control are separate evidence.
    private func likelihooded(_ threat: ResolvedThreat) -> ResolvedThreat {
        let likelihood = threat.threat.likelihood
        guard likelihood != .commodity else { return threat }
        let reduced = Likelihood.apply(to: threat.score.value, likelihood: likelihood)

        return ResolvedThreat(
            threat: threat.threat,
            severity: threat.severity,
            source: threat.source,
            sensitivity: threat.sensitivity,
            score: RiskScore(value: reduced),
            controls: threat.controls,
            context: threat.context,
            isTlsMitigated: threat.isTlsMitigated,
            overrideKey: threat.overrideKey,
            overriddenSeverityId: threat.overriddenSeverityId,
            mitigatedBy: threat.mitigatedBy,
            scoreBeforePathwayMitigation: threat.scoreBeforePathwayMitigation,
            scoreBeforeControls: threat.scoreBeforeControls,
            compensating: threat.compensating,
            scoreBeforeCompensation: threat.scoreBeforeCompensation,
            mitigatedByComponents: threat.mitigatedByComponents,
            likelihood: likelihood,
            scoreBeforeLikelihood: threat.score.value
        )
    }

    /// Spec section 5: a compensating control is applied last, after the zone
    /// reduction and after the pathway mitigation. Two on one threat give the
    /// stronger, not the sum, which is the rule the pathway mitigations follow.
    private func compensated(_ threat: ResolvedThreat) -> ResolvedThreat {
        let key = ThreatKey(threatId: threat.threat.id.value, sourceId: threat.source.id)
        guard let controls = model.compensatingControls[key], controls.isEmpty == false else {
            return threat
        }

        let strongest = controls.map(\.reducesRiskBy).max() ?? 0
        let reduced = max(1, Int((Double(threat.score.value) * (1 - Double(strongest) / 100)).rounded()))

        return ResolvedThreat(
            threat: threat.threat,
            severity: threat.severity,
            source: threat.source,
            sensitivity: threat.sensitivity,
            score: RiskScore(value: reduced),
            controls: threat.controls,
            context: threat.context,
            isTlsMitigated: threat.isTlsMitigated,
            overrideKey: threat.overrideKey,
            overriddenSeverityId: threat.overriddenSeverityId,
            mitigatedBy: threat.mitigatedBy,
            scoreBeforePathwayMitigation: threat.scoreBeforePathwayMitigation,
            scoreBeforeControls: threat.scoreBeforeControls,
            compensating: controls,
            scoreBeforeCompensation: threat.score.value,
            mitigatedByComponents: threat.mitigatedByComponents,
            likelihood: threat.likelihood,
            scoreBeforeLikelihood: threat.scoreBeforeLikelihood
        )
    }

    /// The severity a threat is scored with: the one the user overrode it to
    /// when the taxonomy knows that id, else the threat's own. An override to
    /// an id the taxonomy has never heard of is ignored rather than trusted;
    /// a catalogue update can retire a severity.
    private func severity(for threat: Threat, overrideKey: SeverityOverrideKey)
        -> (severity: ThreatSeverity, overriddenId: String?) {
        guard let overriddenId = model.severityOverrides[overrideKey],
              let overridden = catalogue.taxonomy().severity(id: overriddenId) else {
            return (threat.severity, nil)
        }
        return (overridden, overriddenId)
    }

    /// Spec section 5.3: a pathway threat escalates to the highest sensitivity
    /// among the components it directly feeds, when that is higher than its
    /// own. A component holding public data that feeds restricted data is a
    /// way into restricted data.
    private func escalated(
        threat: Threat,
        on component: Component,
        graph: UpstreamGraph,
        sensitivityById: [ComponentId: DataSensitivity]
    ) -> DataSensitivity {
        guard threat.isPathwayThreat else { return component.effectiveSensitivity }
        let downstream = graph.directlyDownstream(of: component.id).compactMap { sensitivityById[$0] }
        guard let highest = SensitivityLadder.highest(of: downstream) else {
            return component.effectiveSensitivity
        }
        return SensitivityLadder.higher(component.effectiveSensitivity, highest)
    }

    /// What the mitigations upstream of a component do to a threat's score.
    ///
    /// Nil means the threat is dropped. Spec section 5.3: it applies when the
    /// master toggle is on, that mitigation is enabled, a strictly upstream
    /// component's technology provides it, and the mitigation lists the threat
    /// id. Where two mitigations both answer, `remove` wins, and among two
    /// reductions the one leaving the lower score wins: the user gets the
    /// stronger of the controls they switched on, not the sum of them.
    private func mitigated(
        threat: Threat,
        score: Int,
        upstreamOf component: ComponentId,
        graph: UpstreamGraph,
        technologyById: [ComponentId: TechnologyId]
    ) -> (score: Int, by: [PathwayMitigationDefinition])? {
        let settings = model.pathwayMitigations
        guard settings.isMasterEnabled else { return (score, []) }

        let upstreamTechnologies = Set(
            graph.upstream(of: component).compactMap { technologyById[$0] }
        )
        guard upstreamTechnologies.isEmpty == false else { return (score, []) }

        var lowest = score
        var applied: [PathwayMitigationDefinition] = []

        for definition in catalogue.pathwayMitigations() {
            let config = settings.config(for: definition)
            guard config.isEnabled,
                  definition.mitigates(threat.id),
                  upstreamTechnologies.contains(where: definition.isProvidedBy) else { continue }

            applied.append(definition)

            switch PathwayMitigation.outcome(
                score: score,
                mode: config.mode,
                percent: config.reductionPercent
            ) {
            case .removed:
                return nil
            case .reduced(let to):
                lowest = min(lowest, to)
            case .unchanged:
                break
            }
        }

        return (lowest, applied)
    }

    private func componentControls(
        for threat: Threat,
        on technology: Technology,
        componentId: ComponentId
    ) -> [ResolvedControl] {
        let specific = technology.threatMitigations[threat.id] ?? []
        let descriptions: [(String, Bool)] = specific.isEmpty
            ? threat.controls.map { ($0.description, false) }
            : specific.map { ($0, true) }

        return descriptions.map { description, isTechnologySpecific in
            let key = ControlIdentity.componentControl(
                componentId: componentId,
                threatId: threat.id,
                description: description,
                isTechnologySpecific: isTechnologySpecific
            )
            return ResolvedControl(
                description: description,
                isTechnologySpecific: isTechnologySpecific,
                key: key,
                isImplemented: model.controlStatuses[key]?.isRecorded == true,
                status: model.controlStatuses[key] ?? .notImplemented
            )
        }
    }

    private func sharedControls(
        for threat: Threat,
        keyedBy make: (ThreatId, String) -> ControlKey
    ) -> [ResolvedControl] {
        threat.controls.map { control in
            let key = make(threat.id, control.description)
            return ResolvedControl(
                description: control.description,
                isTechnologySpecific: false,
                key: key,
                isImplemented: model.controlStatuses[key]?.isRecorded == true,
                status: model.controlStatuses[key] ?? .notImplemented
            )
        }
    }

    /// A link still raises its threats when an end's technology has left the
    /// catalogue: the threats belong to the link, and the sensitivity is stored
    /// on the component. The technology id stands in for the missing name.
    private static func name(of component: Component, as technology: Technology?) -> String {
        component.customName ?? technology?.name ?? component.technologyId.value
    }

    private static func ordering(_ a: ResolvedThreat, _ b: ResolvedThreat) -> Bool {
        if a.score.value != b.score.value { return a.score.value > b.score.value }
        if a.threat.id != b.threat.id { return a.threat.id.value < b.threat.id.value }
        return a.source.id < b.source.id
    }
}
