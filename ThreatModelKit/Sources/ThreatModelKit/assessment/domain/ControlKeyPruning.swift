/// Drops the control answers whose control wording has left the catalogue.
///
/// A control key carries a fingerprint of the wording it was minted from. When
/// the catalogue rewords a control, the new wording fingerprints differently
/// and the old key belongs to nothing: the user's tick is unreachable, and it
/// still travels in every save.
///
/// WARNING: a key is pruned only when the threat it names is still in the
/// catalogue and none of that threat's wordings fingerprint to it. A threat
/// the catalogue no longer holds, or a technology the catalogue no longer
/// holds, is catalogue drift, and drift keeps the answers so a downgrade of
/// the catalogue does not lose them.
public enum ControlKeyPruning {
    public struct Result: Equatable, Sendable {
        public let statuses: [ControlKey: ControlStatus]
        /// The keys dropped, sorted, so a diagnostic reads the same every run.
        public let pruned: [ControlKey]

        public init(statuses: [ControlKey: ControlStatus], pruned: [ControlKey]) {
            self.statuses = statuses
            self.pruned = pruned
        }
    }

    /// The model's control answers, with every unreachable answer dropped.
    public static func prune(
        _ model: ThreatModel,
        catalogue: TechnologyCatalogue
    ) -> Result {
        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        var fingerprintsByThreat: [ThreatId: Set<String>] = [:]

        func record(_ description: String, for threatId: ThreatId) {
            fingerprintsByThreat[threatId, default: []]
                .insert(ControlIdentity.fingerprint(of: description))
        }

        for technology in lookup.all() {
            for threat in lookup.threatsFor(technologyId: technology.id) {
                for control in threat.controls {
                    record(control.description, for: threat.id)
                }
                for description in technology.threatMitigations[threat.id] ?? [] {
                    record(description, for: threat.id)
                }
            }
        }
        for threat in catalogue.connectionThreats() + catalogue.zoneThreats() {
            for control in threat.controls {
                record(control.description, for: threat.id)
            }
        }

        var kept: [ControlKey: ControlStatus] = [:]
        var pruned: [ControlKey] = []
        for (key, status) in model.controlStatuses {
            guard let read = ControlIdentity.read(key) else {
                kept[key] = status
                continue
            }
            guard let known = fingerprintsByThreat[read.threatId] else {
                // The threat itself has left the catalogue: drift, not a
                // reworded control.
                kept[key] = status
                continue
            }
            if known.contains(read.fingerprint) {
                kept[key] = status
            } else {
                pruned.append(key)
            }
        }

        return Result(statuses: kept, pruned: pruned.sorted { $0.value < $1.value })
    }
}
