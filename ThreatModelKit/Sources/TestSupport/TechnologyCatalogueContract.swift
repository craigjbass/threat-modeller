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

    let connectionThreats = subject.connectionThreats()
    #expect(connectionThreats.isEmpty == false)
    #expect(connectionThreats.allSatisfy { $0.isConnectionThreat })
    #expect(Set(connectionThreats.map(\.id)).count == connectionThreats.count)
    for threat in connectionThreats {
        #expect(taxonomy.severity(id: threat.severity.id) == threat.severity)
        #expect(threat.controls.isEmpty == false)
    }

    // A connection threat belongs to the link, never to a technology. No
    // technology may declare one as its own threat, or the same threat would
    // be raised twice from two different sources.
    let connectionThreatIds = Set(connectionThreats.map(\.id))
    for technology in subject.all() {
        #expect(Set(technology.threatIds).isDisjoint(with: connectionThreatIds))
    }

    let zoneThreats = subject.zoneThreats()
    #expect(zoneThreats.isEmpty == false)
    #expect(zoneThreats.allSatisfy { $0.isZoneThreat })
    #expect(Set(zoneThreats.map(\.id)).count == zoneThreats.count)
    for threat in zoneThreats {
        #expect(taxonomy.severity(id: threat.severity.id) == threat.severity)
        #expect(threat.controls.isEmpty == false)
        // A zone threat carries its own wording, because the same threat read
        // against a whole network zone says something different from the same
        // threat read against one service.
        #expect(threat.zoneContext?.isEmpty == false)
    }

    // A zone threat MAY also be a technology's own threat. `misconfiguration`
    // is both. The two sets are deliberately not disjoint, unlike connection
    // threats, which belong to the link alone.
    #expect(zoneThreats.allSatisfy { $0.isConnectionThreat == false })

    let mitigations = subject.pathwayMitigations()
    #expect(mitigations.isEmpty == false)
    #expect(Set(mitigations.map(\.id)).count == mitigations.count)
    for mitigation in mitigations {
        #expect(mitigation.label.isEmpty == false)
        #expect(mitigation.mitigatesThreatIds.isEmpty == false)
        #expect(mitigation.technologyIds.isEmpty == false)
        // Every technology named must be one the catalogue holds, or the
        // settings screen would offer a mitigation nothing can provide.
        for technologyId in mitigation.technologyIds {
            #expect(subject.findById(technologyId) != nil)
        }
    }
}
