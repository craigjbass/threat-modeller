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

    let version = subject.version()
    #expect(version.repository.isEmpty == false)
    #expect(version.tag.isEmpty == false)

    // Spec section 4.4: every catalogue holds the built-in actor and finds it
    // by its id.
    let actors = subject.threatActors()
    #expect(actors.isEmpty == false)
    #expect(Set(actors.map(\.id)).count == actors.count)
    for actor in actors {
        #expect(subject.findActor(actor.id) == actor)
        #expect(actor.name.isEmpty == false)
    }
    #expect(subject.findActor(ThreatActorId("no-such-actor")) == nil)

    // A sound catalogue reports no fault. Every gateway reads the same
    // catalogue the same way, so every gateway must agree it is sound.
    #expect(subject.faults() == [])
}

/// What every `TechnologyCatalogue` answers when one technology id is declared
/// twice. Run it against the fake and the real gateway alike, so neither can
/// trap and neither can keep a second row for the same id.
public func verifyDuplicateTechnologyIdContract(
    _ subject: TechnologyCatalogue,
    duplicatedId: TechnologyId,
    keptName: String
) throws {
    #expect(subject.faults() == [.duplicateTechnologyId(duplicatedId)])

    // The first entry read is kept, and it is kept once.
    #expect(subject.all().filter { $0.id == duplicatedId }.count == 1)
    let found = try #require(subject.findById(duplicatedId))
    #expect(found.name == keptName)
    #expect(subject.threatsFor(technologyId: duplicatedId).map(\.id) == found.threatIds)
}

/// What every `TechnologyCatalogue` answers when a technology names a threat
/// id no threat file declares. The threat is not read, and the fault names
/// the technology and the id.
public func verifyDanglingThreatIdContract(
    _ subject: TechnologyCatalogue,
    technologyId: TechnologyId,
    danglingThreatId: ThreatId
) throws {
    #expect(
        subject.faults()
            == [.danglingThreatId(technologyId: technologyId, threatId: danglingThreatId)]
    )

    let read = subject.threatsFor(technologyId: technologyId)
    #expect(read.contains { $0.id == danglingThreatId } == false)
}
