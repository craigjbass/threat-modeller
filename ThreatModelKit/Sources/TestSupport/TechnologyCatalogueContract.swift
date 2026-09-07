import Testing
import ThreatModelKit

/// The behaviour every `TechnologyCatalogue` must exhibit, expressed entirely in
/// Domain objects. Run it against the fake and the real gateway alike.
public func verifyTechnologyCatalogueContract(
    _ subject: TechnologyCatalogue,
    knownTechnologyId: TechnologyId
) throws {
    let unknownId = TechnologyId("no-such-technology")

    #expect(subject.all().isEmpty == false)

    let known = try #require(subject.findById(knownTechnologyId))
    #expect(known.id == knownTechnologyId)
    #expect(subject.findById(unknownId) == nil)

    let threats = subject.threatsFor(technologyId: knownTechnologyId)
    #expect(threats.map(\.id) == known.threatIds)
    #expect(subject.threatsFor(technologyId: unknownId).isEmpty)

    let taxonomy = subject.taxonomy()
    #expect(taxonomy.severities.isEmpty == false)
    #expect(taxonomy.severities.enumerated().allSatisfy { index, severity in
        severity.rank == index + 1
    })
    #expect(Set(taxonomy.severities.map(\.id)).count == taxonomy.severities.count)

    let providerIds = Set(subject.providers().map(\.id))
    let categoryIds = Set(taxonomy.categories.map(\.id))
    for technology in subject.all() {
        #expect(providerIds.contains(technology.provider))
        #expect(categoryIds.contains(technology.category))
    }

    for threat in threats {
        #expect(taxonomy.severity(id: threat.severity.id) == threat.severity)
    }
}
