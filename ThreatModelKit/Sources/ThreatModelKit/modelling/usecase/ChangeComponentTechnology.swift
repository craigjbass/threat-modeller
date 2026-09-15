public protocol ChangeComponentTechnologyUseCase {
    func execute(_ request: ChangeComponentTechnologyRequest) -> ChangeComponentTechnologyResponse
}

public struct ChangeComponentTechnologyRequest: Equatable, Sendable {
    public let componentId: String
    public let technologyId: String

    public init(componentId: String, technologyId: String) {
        self.componentId = componentId
        self.technologyId = technologyId
    }
}

public enum ChangeComponentTechnologyResponse: Equatable, Sendable {
    /// The change, and every answer the new technology has no threat for.
    /// Each dropped answer reads `<threatId>`, sorted.
    case changed(droppedAnswers: [String])
    case unknownComponent
    case unknownTechnology
    /// The component already carries that technology, so nothing changed.
    case unchanged
}

/// Puts a different technology on a component that is already drawn.
///
/// A component drawn with the wrong technology used to be deleted and drawn
/// again, which lost its name, its place, its flows and every answer on it.
/// This keeps the component: the id, the name, the position, the zone, the
/// flows and the mitigates edges are the component's, not the technology's.
///
/// WARNING: the answers are not the component's. An answer belongs to a threat,
/// and a technology decides which threats a component raises. An answer on a
/// threat the new technology still raises is kept, and an answer on a threat it
/// no longer raises is dropped, because there is nothing left for it to answer.
/// The response names each threat dropped, so the window says what went.
public struct ChangeComponentTechnology: ChangeComponentTechnologyUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(
        _ request: ChangeComponentTechnologyRequest
    ) -> ChangeComponentTechnologyResponse {
        let componentId = ComponentId(request.componentId)
        let technologyId = TechnologyId(request.technologyId)

        return models.mutate(label: ChangeLabel.changeComponentTechnology) { model in
            guard let index = model.components.firstIndex(where: { $0.id == componentId }) else {
                return .unknownComponent
            }
            guard TechnologyLookup(model: model, catalogue: catalogue)
                .findById(technologyId) != nil else {
                return .unknownTechnology
            }
            guard model.components[index].technologyId != technologyId else {
                return .unchanged
            }

            model.components[index].technologyId = technologyId

            // The threats the component raises now that it is the other
            // technology. Read after the change, so the lookup answers for the
            // technology the component has.
            let kept = Set(
                TechnologyLookup(model: model, catalogue: catalogue)
                    .threatsFor(technologyId: technologyId)
                    .map(\.id)
            )

            var dropped: Set<String> = []
            let controlPrefix = ControlIdentity.componentPrefix(componentId)
            model.controlStatuses = model.controlStatuses.filter { key, _ in
                guard key.value.hasPrefix(controlPrefix) else { return true }
                guard let read = ControlIdentity.read(key) else { return true }
                guard kept.contains(read.threatId) == false else { return true }
                dropped.insert(read.threatId.value)
                return false
            }

            let overridePrefix = SeverityOverrideKey.componentPrefix(componentId)
            model.severityOverrides = model.severityOverrides.filter { key, _ in
                guard key.value.hasPrefix(overridePrefix) else { return true }
                let threatId = ThreatId(String(key.value.dropFirst(overridePrefix.count)))
                guard kept.contains(threatId) == false else { return true }
                dropped.insert(threatId.value)
                return false
            }

            let source = "component:\(componentId.value)"
            model.compensatingControls = model.compensatingControls.filter { key, _ in
                Self.keeps(key, source: source, kept: kept, dropped: &dropped)
            }
            model.likelihoodFindings = model.likelihoodFindings.filter { key, _ in
                Self.keeps(key, source: source, kept: kept, dropped: &dropped)
            }
            model.severityDecisions = model.severityDecisions.filter { key, _ in
                Self.keeps(key, source: source, kept: kept, dropped: &dropped)
            }

            return .changed(droppedAnswers: dropped.sorted())
        }
    }

    /// True when a key scoped to this component names a threat the new
    /// technology still raises. A key scoped to anything else is kept.
    private static func keeps(
        _ key: ThreatKey,
        source: String,
        kept: Set<ThreatId>,
        dropped: inout Set<String>
    ) -> Bool {
        let halves = key.value.components(separatedBy: "@")
        guard halves.count == 2, halves[1] == source else { return true }
        let threatId = ThreatId(halves[0])
        guard kept.contains(threatId) == false else { return true }
        dropped.insert(threatId.value)
        return false
    }
}
