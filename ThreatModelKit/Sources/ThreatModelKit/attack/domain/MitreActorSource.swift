import Foundation

/// The ATT&CK groups on this machine, as threat actors.
///
/// WARNING: the files are read the first time something asks for an actor, not
/// when the application starts. A project that faces no MITRE group parses
/// neither file and pays nothing at open time.
///
/// A machine that has never synchronised reads zero groups. The application
/// starts, and a `faces` entry naming a `mitre-` id then states that the
/// project holds no such actor and names the synchronise step.
public final class MitreActorSource: @unchecked Sendable {
    /// Every ATT&CK actor's id starts with this.
    public static let prefix = "mitre-"

    private let data: AttackDataGateway
    private let lock = NSLock()
    private var actorsValue: [ThreatActor]?
    private var groupsValue: [AttackGroup]?
    private var techniquesValue: [AttackTechnique]?
    private var techniquesByIdValue: [String: AttackTechnique]?

    public init(data: AttackDataGateway) {
        self.data = data
    }

    /// Every group on this machine, as a threat actor. Empty when nothing has
    /// been synchronised.
    public func actors() -> [ThreatActor] {
        lock.lock()
        if let actorsValue {
            defer { lock.unlock() }
            return actorsValue
        }
        lock.unlock()

        // Every group reads `targeted`: ATT&CK states no frequency, and a
        // named intrusion set is not commodity malware. A team that disagrees
        // writes a local `threat_actor` block, which overrides this whole.
        let built = groups().map { group in
            ThreatActor(
                id: ThreatActorId("\(Self.prefix)\(group.id)"),
                name: group.name,
                description: group.description,
                aliases: group.aliases,
                capability: .targeted,
                intent: "",
                performs: [],
                techniques: group.techniques
            )
        }

        lock.lock()
        actorsValue = built
        lock.unlock()
        return built
    }

    /// Every group on this machine, as the file states it. Empty when nothing
    /// has been synchronised. The MITRE id search reads it.
    public func groups() -> [AttackGroup] {
        lock.lock()
        if let groupsValue {
            defer { lock.unlock() }
            return groupsValue
        }
        lock.unlock()

        let text = data.read(fileName: AttackDataLocation.groupsFileName) ?? ""
        let built = AttackFiles.groups(from: text)

        lock.lock()
        groupsValue = built
        lock.unlock()
        return built
    }

    /// Every technique on this machine, in the order the file states them.
    /// Empty when nothing has been synchronised.
    public func techniques() -> [AttackTechnique] {
        lock.lock()
        if let techniquesValue {
            defer { lock.unlock() }
            return techniquesValue
        }
        lock.unlock()

        let text = data.read(fileName: AttackDataLocation.techniquesFileName) ?? ""
        let built = AttackFiles.techniques(from: text)

        lock.lock()
        techniquesValue = built
        techniquesByIdValue = Dictionary(
            built.map { ($0.id, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        lock.unlock()
        return built
    }

    /// The technique that id names, or nil when this machine holds no such
    /// technique. The report reads it to print a name beside an id.
    public func technique(_ id: String) -> AttackTechnique? {
        lock.lock()
        if let techniquesByIdValue {
            defer { lock.unlock() }
            return techniquesByIdValue[id]
        }
        lock.unlock()

        _ = techniques()

        lock.lock()
        defer { lock.unlock() }
        return techniquesByIdValue?[id]
    }

    /// Reads the files again. A synchronise calls it, so the window shows what
    /// just arrived.
    public func forget() {
        lock.lock()
        actorsValue = nil
        groupsValue = nil
        techniquesValue = nil
        techniquesByIdValue = nil
        lock.unlock()
    }
}
