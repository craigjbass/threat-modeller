import Foundation

/// Keeps the last resolution, so one change costs one run of the resolver.
///
/// Drawing one change reads the model twice: the list of threats and the risk
/// summary beneath it. Both ask the same question of the same model, and the
/// resolver is the expensive part of both. This keeps the answer and the
/// revision it belongs to, and answers again only when the model has moved.
///
/// WARNING: the catalogue is not part of the key. A root that loads a library
/// changes what the same model raises, so that root calls `forget()`.
public final class ThreatResolutionCache: @unchecked Sendable {
    private let lock = NSLock()
    private var revision: Int?
    private var threats: [ResolvedThreat] = []

    public init() {}

    /// The threats this model raises, resolved once per change.
    public func resolved(
        _ models: ThreatModelGateway,
        _ catalogue: TechnologyCatalogue
    ) -> [ResolvedThreat] {
        let asked = models.revision
        lock.lock()
        if revision == asked {
            defer { lock.unlock() }
            return threats
        }
        lock.unlock()

        let resolved = ThreatResolver(model: models.current(), catalogue: catalogue).resolve()

        lock.lock()
        revision = asked
        threats = resolved
        lock.unlock()
        return resolved
    }

    /// Drops what is kept. The catalogue changed, so the answer is stale
    /// whatever the model's revision says.
    public func forget() {
        lock.lock()
        revision = nil
        threats = []
        lock.unlock()
    }
}
