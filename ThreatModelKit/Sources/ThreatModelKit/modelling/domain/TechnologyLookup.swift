/// Answers "what is this technology?" from the model first and the catalogue
/// second.
///
/// A user who names their own technology after one in the catalogue means
/// theirs: the model is the document in front of them, and the catalogue is a
/// library. One rule, in one place, so every reader agrees.
public struct TechnologyLookup {
    private let custom: [TechnologyId: CustomTechnology]
    private let customOrder: [CustomTechnology]
    private let catalogue: TechnologyCatalogue

    public init(model: ThreatModel, catalogue: TechnologyCatalogue) {
        customOrder = model.customTechnologies
        custom = Dictionary(
            model.customTechnologies.map { ($0.id, $0) },
            uniquingKeysWith: { _, later in later }
        )
        self.catalogue = catalogue
    }

    public func findById(_ id: TechnologyId) -> Technology? {
        custom[id]?.asTechnology ?? catalogue.findById(id)
    }

    /// A custom technology's threats are the catalogue's, named by it. One it
    /// names that the catalogue does not hold is dropped, the same way a
    /// dangling threat id in the vendored data is.
    public func threatsFor(technologyId: TechnologyId) -> [Threat] {
        guard let own = custom[technologyId] else {
            return catalogue.threatsFor(technologyId: technologyId)
        }
        return own.threatIds.compactMap { threatId in
            everyThreat().first { $0.id == threatId }
        }
    }

    /// The model's own first, so a user's own work is at hand.
    public func all() -> [Technology] {
        let ownIds = Set(customOrder.map(\.id))
        return customOrder.map(\.asTechnology)
            + catalogue.all().filter { ownIds.contains($0.id) == false }
    }

    /// The model's own provider first, when the model defines anything.
    public func providers() -> [Provider] {
        let own = Provider(
            id: CustomTechnology.provider,
            displayName: CustomTechnology.providerDisplayName
        )
        let rest = catalogue.providers().filter { $0.id != own.id }
        return customOrder.isEmpty ? rest : [own] + rest
    }

    /// Every threat the catalogue defines, wherever it defines it.
    ///
    /// WARNING: this walks every technology. At 277 technologies that is
    /// wasteful on every call. Add `allThreats()` to the catalogue port if the
    /// suite's time moves.
    private func everyThreat() -> [Threat] {
        catalogue.all().flatMap { catalogue.threatsFor(technologyId: $0.id) }
            + catalogue.connectionThreats()
            + catalogue.zoneThreats()
    }
}
