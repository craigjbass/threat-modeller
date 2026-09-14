/// One fault in a catalogue, found while the catalogue is read.
///
/// A fault never stops the application. The catalogue answers with what it
/// can read and names what it could not, so a bad catalogue tag fails a build
/// rather than the application.
public enum CatalogueFault: Equatable, Sendable {
    /// Two technologies declare the same id. The first one read is kept.
    case duplicateTechnologyId(TechnologyId)
    /// A technology names a threat id no threat file declares.
    case danglingThreatId(technologyId: TechnologyId, threatId: ThreatId)

    public var message: String {
        switch self {
        case .duplicateTechnologyId(let id):
            return "technology '\(id.value)' is declared more than once; the first one read is kept"
        case .danglingThreatId(let technologyId, let threatId):
            return "technology '\(technologyId.value)' names threat '\(threatId.value)', which no threat file declares"
        }
    }
}

/// Reads a set of technologies for the two faults a catalogue file can hold.
///
/// Every gateway audits with this one function, so the fake and the real
/// gateway give the same answer for the same input.
public enum CatalogueAudit {
    /// The technologies to keep, in the order read, and the ids declared twice.
    public static func deduplicate(
        _ technologies: [Technology]
    ) -> (kept: [Technology], duplicates: [TechnologyId]) {
        var seen: Set<TechnologyId> = []
        var kept: [Technology] = []
        var duplicates: [TechnologyId] = []
        for technology in technologies {
            if seen.insert(technology.id).inserted {
                kept.append(technology)
            } else {
                duplicates.append(technology.id)
            }
        }
        return (kept, duplicates)
    }

    /// Every fault in the technologies read, in the order the faults are found.
    public static func faults(
        technologies: [Technology],
        declaredThreatIds: Set<ThreatId>
    ) -> [CatalogueFault] {
        let (kept, duplicates) = deduplicate(technologies)
        var faults = duplicates.map(CatalogueFault.duplicateTechnologyId)
        for technology in kept {
            for threatId in technology.threatIds where declaredThreatIds.contains(threatId) == false {
                faults.append(.danglingThreatId(technologyId: technology.id, threatId: threatId))
            }
        }
        return faults
    }
}
