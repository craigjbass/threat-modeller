/// Reading and writing one stanza of a system's `.governance` file.
///
/// The window's governance editor writes through these. Each reads the file,
/// changes one stanza and writes every other stanza back unchanged, because a
/// person deciding one entry is deciding nothing about the rest.
///
/// One writer states the canonical shape, so a stanza written here and the
/// same stanza written by `threatmodeller compile` are the same bytes.
public protocol ListGovernanceUseCase {
    func execute(_ request: ListGovernanceRequest) -> ListGovernanceResponse
}

public struct ListGovernanceRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String

    public init(root: String, systemName: String) {
        self.root = root
        self.systemName = systemName
    }
}

public enum ListGovernanceResponse: Equatable, Sendable {
    /// The stanzas the file states, and the path it was read from. A system
    /// with no file yet states nothing and no fault.
    case listed(source: GovernanceSource, path: String)
    case noSuchSystem
    case cannotRead(reason: String)
}

public struct ListGovernance: ListGovernanceUseCase {
    private let projects: ProjectSourceGateway
    private let sources: GovernanceSourceGateway

    public init(projects: ProjectSourceGateway, sources: GovernanceSourceGateway) {
        self.projects = projects
        self.sources = sources
    }

    public func execute(_ request: ListGovernanceRequest) -> ListGovernanceResponse {
        switch GovernanceFile.read(
            root: request.root,
            systemName: request.systemName,
            projects: projects,
            sources: sources
        ) {
        case .read(let source, let path):
            return .listed(source: source, path: path)
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotRead(reason: reason)
        }
    }
}

public protocol WriteRiskAcceptanceUseCase {
    func execute(_ request: WriteRiskAcceptanceRequest) -> WriteRiskAcceptanceResponse
}

public struct WriteRiskAcceptanceRequest: Equatable, Sendable {
    public let root: String
    /// The system's own file name, which names the file to write.
    public let systemName: String
    /// The name the system states for itself, which a new file's header
    /// names. Nil writes the file name.
    public let systemDisplayName: String?
    /// The threat the control answers, the way the controls file states it.
    public let threatId: String
    /// `component`, `zone` or `flow`.
    public let sourceKind: String
    public let sourceId: String
    /// The stanza to write. A stanza for the same control replaces it; any
    /// other control's stanza is added.
    public let accepted: SourceAcceptedRisk

    public init(
        root: String,
        systemName: String,
        systemDisplayName: String? = nil,
        threatId: String,
        sourceKind: String,
        sourceId: String,
        accepted: SourceAcceptedRisk
    ) {
        self.root = root
        self.systemName = systemName
        self.systemDisplayName = systemDisplayName
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
        self.accepted = accepted
    }
}

public enum WriteRiskAcceptanceResponse: Equatable, Sendable {
    case written(path: String)
    case noSuchSystem
    /// Why the stanza is not one the file's own parser would accept.
    case refused(reason: String)
    case cannotWrite(reason: String)

    public func describe(into message: inout String?) {
        switch self {
        case .written:
            message = nil
        case .noSuchSystem:
            message = "This project no longer holds that system."
        case .refused(let reason):
            message = "That entry was not written: \(reason)."
        case .cannotWrite(let reason):
            message = "That entry could not be written: \(reason)"
        }
    }
}

public struct WriteRiskAcceptance: WriteRiskAcceptanceUseCase {
    private let projects: ProjectSourceGateway
    private let sources: GovernanceSourceGateway

    public init(projects: ProjectSourceGateway, sources: GovernanceSourceGateway) {
        self.projects = projects
        self.sources = sources
    }

    public func execute(_ request: WriteRiskAcceptanceRequest) -> WriteRiskAcceptanceResponse {
        guard request.accepted.control.trimmingWhitespace().isEmpty == false else {
            return .refused(reason: "an accepted risk names its control")
        }
        if let fault = GovernanceStanza.dateFault(request.accepted.acceptedOn, named: "accepted_on")
            ?? GovernanceStanza.dateFault(request.accepted.reviewBy, named: "review_by") {
            return .refused(reason: fault)
        }

        let held: GovernanceSource
        let path: String
        switch GovernanceFile.read(
            root: request.root,
            systemName: request.systemName,
            named: request.systemDisplayName,
            projects: projects,
            sources: sources
        ) {
        case .read(let source, let at):
            held = source
            path = at
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        let changed = GovernanceStanza.changing(
            threats: held.threats,
            threatId: request.threatId,
            sourceKind: request.sourceKind,
            sourceId: request.sourceId
        ) { threat in
            var accepted = threat.accepted
            if let already = accepted.firstIndex(where: { $0.control == request.accepted.control }) {
                accepted[already] = request.accepted
            } else {
                accepted.append(request.accepted)
            }
            return SourceGovernedThreat(
                threatId: threat.threatId,
                sourceKind: threat.sourceKind,
                sourceId: threat.sourceId,
                accepted: accepted,
                work: threat.work,
                isStale: threat.isStale
            )
        }

        do {
            try projects.write(
                sources.write(
                    GovernanceSource(
                        systemName: held.systemName,
                        threats: changed,
                        actions: held.actions
                    )
                ),
                to: path
            )
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        return .written(path: path)
    }
}

public protocol WritePlannedWorkUseCase {
    func execute(_ request: WritePlannedWorkRequest) -> WritePlannedWorkResponse
}

/// Where a work stanza sits: on one governed threat, or among the actions the
/// `.arch` file declares.
public enum PlannedWorkPlace: Equatable, Sendable {
    case threat(threatId: String, sourceKind: String, sourceId: String)
    case action
}

public struct WritePlannedWorkRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String
    /// The name the system states for itself, which a new file's header
    /// names. Nil writes the file name.
    public let systemDisplayName: String?
    public let place: PlannedWorkPlace
    /// The stanza to write. A stanza with the same label replaces it; any
    /// other label's stanza is added.
    public let work: SourcePlannedWork

    public init(
        root: String,
        systemName: String,
        systemDisplayName: String? = nil,
        place: PlannedWorkPlace,
        work: SourcePlannedWork
    ) {
        self.root = root
        self.systemName = systemName
        self.systemDisplayName = systemDisplayName
        self.place = place
        self.work = work
    }
}

public enum WritePlannedWorkResponse: Equatable, Sendable {
    case written(path: String)
    case noSuchSystem
    /// Why the stanza is not one the file's own parser would accept.
    case refused(reason: String)
    case cannotWrite(reason: String)

    public func describe(into message: inout String?) {
        switch self {
        case .written:
            message = nil
        case .noSuchSystem:
            message = "This project no longer holds that system."
        case .refused(let reason):
            message = "That work was not written: \(reason)."
        case .cannotWrite(let reason):
            message = "That work could not be written: \(reason)"
        }
    }
}

public struct WritePlannedWork: WritePlannedWorkUseCase {
    private let projects: ProjectSourceGateway
    private let sources: GovernanceSourceGateway

    public init(projects: ProjectSourceGateway, sources: GovernanceSourceGateway) {
        self.projects = projects
        self.sources = sources
    }

    public func execute(_ request: WritePlannedWorkRequest) -> WritePlannedWorkResponse {
        guard request.work.label.trimmingWhitespace().isEmpty == false else {
            return .refused(reason: "planned work names a recommendation or an action")
        }
        if let fault = GovernanceStanza.dateFault(request.work.dueBy, named: "due_by") {
            return .refused(reason: fault)
        }
        if let effort = request.work.effort, SourcePlannedWork.efforts.contains(effort) == false {
            return .refused(
                reason: "effort is \"\(effort)\"; this application holds "
                    + SourcePlannedWork.efforts.map { "\"\($0)\"" }.joined(separator: ", ")
            )
        }
        guard SourcePlannedWork.statuses.contains(request.work.status) else {
            return .refused(
                reason: "status is \"\(request.work.status)\"; this application holds "
                    + SourcePlannedWork.statuses.map { "\"\($0)\"" }.joined(separator: ", ")
            )
        }

        let held: GovernanceSource
        let path: String
        switch GovernanceFile.read(
            root: request.root,
            systemName: request.systemName,
            named: request.systemDisplayName,
            projects: projects,
            sources: sources
        ) {
        case .read(let source, let at):
            held = source
            path = at
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        var threats = held.threats
        var actions = held.actions
        switch request.place {
        case .threat(let threatId, let sourceKind, let sourceId):
            threats = GovernanceStanza.changing(
                threats: threats,
                threatId: threatId,
                sourceKind: sourceKind,
                sourceId: sourceId
            ) { threat in
                var work = threat.work
                if let already = work.firstIndex(where: { $0.label == request.work.label }) {
                    work[already] = request.work
                } else {
                    work.append(request.work)
                }
                return SourceGovernedThreat(
                    threatId: threat.threatId,
                    sourceKind: threat.sourceKind,
                    sourceId: threat.sourceId,
                    accepted: threat.accepted,
                    work: work,
                    isStale: threat.isStale
                )
            }
        case .action:
            if let already = actions.firstIndex(where: { $0.label == request.work.label }) {
                actions[already] = request.work
            } else {
                actions.append(request.work)
            }
        }

        do {
            try projects.write(
                sources.write(
                    GovernanceSource(
                        systemName: held.systemName,
                        threats: threats,
                        actions: actions
                    )
                ),
                to: path
            )
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        return .written(path: path)
    }
}

/// The shared rules of the two writers.
enum GovernanceStanza {
    /// The threat blocks with one block changed. A key the file does not
    /// govern yet gets a new block at the end.
    static func changing(
        threats: [SourceGovernedThreat],
        threatId: String,
        sourceKind: String,
        sourceId: String,
        change: (SourceGovernedThreat) -> SourceGovernedThreat
    ) -> [SourceGovernedThreat] {
        var changed = threats
        let key = ThreatKey(threatId: threatId, sourceId: "\(sourceKind):\(sourceId)")
        if let already = changed.firstIndex(where: { $0.key == key }) {
            changed[already] = change(changed[already])
        } else {
            changed.append(
                change(
                    SourceGovernedThreat(
                        threatId: threatId,
                        sourceKind: sourceKind,
                        sourceId: sourceId
                    )
                )
            )
        }
        return changed
    }

    /// Why a date attribute would not parse, or nil for a date the parser
    /// takes. The message is the parser's own.
    static func dateFault(_ raw: String?, named attribute: String) -> String? {
        guard let raw else { return nil }
        guard case .failure(let fault) = GovernanceDate.read(raw) else { return nil }
        return fault.message(attribute: attribute, raw: raw)
    }
}

/// One system's `.governance` file, read for a change.
///
/// A system with no file yet reads as a file governing nothing, so writing the
/// first stanza writes the file.
enum GovernanceFile {
    enum Read {
        case read(GovernanceSource, path: String)
        case noSuchSystem
        case cannotRead(reason: String)
    }

    static func read(
        root: String,
        systemName: String,
        named displayName: String? = nil,
        projects: ProjectSourceGateway,
        sources: GovernanceSourceGateway
    ) -> Read {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: root)
        } catch {
            return .cannotRead(reason: String(describing: error))
        }
        guard let system = layout.systems.first(where: { $0.name == systemName }) else {
            return .noSuchSystem
        }

        let path = system.governancePath
        guard projects.exists(path: path) else {
            // A system with no file yet reads as a file governing nothing, and
            // the header names the system the way the architecture does.
            return .read(GovernanceSource(systemName: displayName ?? systemName), path: path)
        }
        guard let text = try? projects.read(path: path) else {
            return .cannotRead(reason: "\(path) could not be read")
        }
        let found = sources.read(text)
        guard let source = found.source, found.hasErrors == false else {
            return .cannotRead(
                reason: found.diagnostics.first?.described(in: path) ?? "\(path) does not parse"
            )
        }
        return .read(source, path: path)
    }
}
