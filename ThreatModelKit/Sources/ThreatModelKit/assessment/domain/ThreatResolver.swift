/// One control offered against a resolved threat.
public struct ResolvedControl: Equatable, Sendable {
    public let description: String
    /// True when the control came from the technology rather than the threat.
    public let isTechnologySpecific: Bool
    public let key: ControlKey
    /// True when the model records this control as in place.
    public let isImplemented: Bool

    public init(description: String, isTechnologySpecific: Bool, key: ControlKey, isImplemented: Bool) {
        self.description = description
        self.isTechnologySpecific = isTechnologySpecific
        self.key = key
        self.isImplemented = isImplemented
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
        overriddenSeverityId: String?
    ) {
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

    public init(model: ThreatModel, catalogue: TechnologyCatalogue) {
        self.model = model
        self.catalogue = catalogue
    }

    public func resolve() -> [ResolvedThreat] {
        var resolved: [ResolvedThreat] = []
        // Spec section 5.3: a duplicate threat and source pair is raised once.
        var raised: Set<String> = []

        func raise(_ threat: ResolvedThreat) {
            let pair = "\(threat.threat.id.value)@\(threat.source.id)"
            guard raised.contains(pair) == false else { return }
            raised.insert(pair)
            resolved.append(threat)
        }

        // Derived, never stored. Spec section 5.2.
        var zonesByComponent: [ComponentId: Zone] = [:]
        for component in model.components {
            zonesByComponent[component.id] = ZoneContainment.zone(
                holding: component.centre,
                in: model.zones
            )
        }

        for component in model.components {
            guard component.threatsDisabled == false else { continue }
            guard let technology = catalogue.findById(component.technologyId) else { continue }

            let multiplier = ZoneMultiplier.value(for: zonesByComponent[component.id])

            for threat in catalogue.threatsFor(technologyId: component.technologyId) {
                let overrideKey = SeverityOverrideKey.forComponent(
                    technologyId: component.technologyId,
                    threatId: threat.id
                )
                let chosen = severity(for: threat, overrideKey: overrideKey)
                let base = RiskScore(severity: chosen.severity, sensitivity: component.sensitivity)
                let score = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard score.value > 0 else { continue }

                raise(
                    ResolvedThreat(
                        threat: threat,
                        severity: chosen.severity,
                        source: .component(
                            id: component.id,
                            name: component.customName ?? technology.name,
                            providerId: technology.provider
                        ),
                        sensitivity: component.sensitivity,
                        score: score,
                        controls: componentControls(
                            for: threat,
                            on: technology,
                            componentId: component.id
                        ),
                        context: technology.threatContext[threat.id],
                        isTlsMitigated: false,
                        overrideKey: overrideKey,
                        overriddenSeverityId: chosen.overriddenId
                    )
                )
            }
        }

        for connection in model.connections {
            guard let source = model.component(connection.source),
                  let target = model.component(connection.target) else { continue }
            guard source.threatsDisabled == false, target.threatsDisabled == false else { continue }

            let sourceTechnology = catalogue.findById(source.technologyId)
            let targetTechnology = catalogue.findById(target.technologyId)
            let sensitivity = SensitivityLadder.higher(source.sensitivity, target.sensitivity)
            let multiplier = ZoneMultiplier.valueForConnection(
                sourceZone: zonesByComponent[source.id],
                targetZone: zonesByComponent[target.id]
            )

            for threat in catalogue.connectionThreats() {
                let overrideKey = SeverityOverrideKey.forConnection(threatId: threat.id)
                let chosen = severity(for: threat, overrideKey: overrideKey)
                let base = RiskScore(severity: chosen.severity, sensitivity: sensitivity)
                let score = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard score.value > 0 else { continue }

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
                        // Spec section 5.3: a link always uses the threat's own
                        // controls, never a technology's mitigations.
                        controls: sharedControls(for: threat, keyedBy: ControlIdentity.connectionControl),
                        context: nil,
                        isTlsMitigated: ConnectionEncryption.isTlsMitigated(
                            threat: threat,
                            source: sourceTechnology,
                            target: targetTechnology
                        ),
                        overrideKey: overrideKey,
                        overriddenSeverityId: chosen.overriddenId
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
                let overrideKey = SeverityOverrideKey.forZone(threatId: threat.id)
                let chosen = severity(for: threat, overrideKey: overrideKey)
                let base = RiskScore(severity: chosen.severity, sensitivity: .internalData)
                let score = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard score.value > 0 else { continue }

                raise(
                    ResolvedThreat(
                        threat: threat,
                        severity: chosen.severity,
                        source: .zone(id: zone.id, name: zone.displayName),
                        sensitivity: .internalData,
                        score: score,
                        controls: sharedControls(for: threat, keyedBy: ControlIdentity.zoneControl),
                        context: threat.zoneContext,
                        isTlsMitigated: false,
                        overrideKey: overrideKey,
                        overriddenSeverityId: chosen.overriddenId
                    )
                )
            }
        }

        return resolved.sorted(by: Self.ordering)
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
                isImplemented: model.implementedControls.contains(key)
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
                isImplemented: model.implementedControls.contains(key)
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
