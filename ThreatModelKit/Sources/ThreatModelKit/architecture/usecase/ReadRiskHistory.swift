import Foundation

public protocol ReadRiskHistoryUseCase {
    func execute(_ request: ReadRiskHistoryRequest) -> ReadRiskHistoryResponse
}

public struct ReadRiskHistoryRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String?
    /// At most this many commits, newest first.
    public let commits: Int

    public init(root: String, systemName: String? = nil, commits: Int = ReadRiskHistory.defaultCommits) {
        self.root = root
        self.systemName = systemName
        self.commits = commits
    }
}

/// Everything one history read found.
public struct RiskHistory: Equatable, Sendable {
    /// The rows, newest first.
    public let rows: [RiskHistoryRow]
    /// True when the bound left commits out.
    public let truncated: Bool
    /// What the newest sampled commit raised, for the comparison against the
    /// working tree. Empty when its files did not parse.
    public let previousThreats: [ComparedThreat]
    /// The catalogue that commit named.
    public let previousCatalogueTag: String?

    public init(
        rows: [RiskHistoryRow] = [],
        truncated: Bool = false,
        previousThreats: [ComparedThreat] = [],
        previousCatalogueTag: String? = nil
    ) {
        self.rows = rows
        self.truncated = truncated
        self.previousThreats = previousThreats
        self.previousCatalogueTag = previousCatalogueTag
    }

    public var previousCommit: SourceCommit? { rows.first?.commit }
}

public enum ReadRiskHistoryResponse: Equatable, Sendable {
    /// The rows, newest first, and what the newest one raised.
    case read(RiskHistory)
    case notARepository(reason: String)
    case noSuchSystem
    case cannotRead(reason: String)
}

/// Scores the model at each sampled commit, by reading the files that commit
/// holds. Nothing is stored.
public struct ReadRiskHistory: ReadRiskHistoryUseCase {
    /// What a run samples when nobody says otherwise. A five-year repository
    /// would otherwise compile thousands of times.
    public static let defaultCommits = 50

    private let projects: ProjectSourceGateway
    private let history: GitHistoryGateway
    private let catalogue: TechnologyCatalogue
    private let architectureSources: ArchitectureSourceGateway
    private let controlsSources: ControlsSourceGateway
    private let attackTreeSources: AttackTreeSourceGateway
    private let governanceSources: GovernanceSourceGateway
    private let layout: LayOutModelUseCase

    public init(
        projects: ProjectSourceGateway,
        history: GitHistoryGateway,
        catalogue: TechnologyCatalogue,
        architectureSources: ArchitectureSourceGateway,
        controlsSources: ControlsSourceGateway,
        attackTreeSources: AttackTreeSourceGateway,
        governanceSources: GovernanceSourceGateway,
        layout: LayOutModelUseCase
    ) {
        self.projects = projects
        self.history = history
        self.catalogue = catalogue
        self.architectureSources = architectureSources
        self.controlsSources = controlsSources
        self.attackTreeSources = attackTreeSources
        self.governanceSources = governanceSources
        self.layout = layout
    }

    public func execute(_ request: ReadRiskHistoryRequest) -> ReadRiskHistoryResponse {
        guard history.isRepository(root: request.root) else {
            return .notARepository(
                reason: "\(request.root) is not a git repository, so it holds no history"
            )
        }

        let discovered: ProjectLayout
        do {
            discovered = try projects.discover(root: request.root)
        } catch {
            return .cannotRead(reason: String(describing: error))
        }

        let systems = request.systemName.map { name in
            discovered.systems.filter { $0.name == name }
        } ?? discovered.systems
        guard systems.isEmpty == false else { return .noSuchSystem }

        let watched = systems.flatMap { system in
            (system.architecturePaths
                + system.controlsPaths
                + system.attackTreePaths
                + [system.governancePath])
                .map { relative($0, to: request.root) }
        }

        let commits: [SourceCommit]
        do {
            // One more than the bound, so the row list can say it truncated
            // rather than leaving a reader to guess.
            commits = try history.commits(
                root: request.root,
                touching: watched,
                limit: request.commits + 1
            )
        } catch {
            return .cannotRead(reason: String(describing: error))
        }

        let truncated = commits.count > request.commits
        let sampled = Array(commits.prefix(request.commits))

        var rows: [RiskHistoryRow] = []
        var previousThreats: [ComparedThreat] = []
        var previousCatalogueTag: String?

        for (index, commit) in sampled.enumerated() {
            let read = reading(at: commit, systems: systems, root: request.root)
            rows.append(RiskHistoryRow(commit: commit, numbers: read?.numbers))
            if index == 0 {
                previousThreats = read?.threats ?? []
                previousCatalogueTag = read?.numbers.catalogueTag
            }
        }

        return .read(
            RiskHistory(
                rows: rows,
                truncated: truncated,
                previousThreats: previousThreats,
                previousCatalogueTag: previousCatalogueTag
            )
        )
    }

    /// What one commit scored, and what it raised.
    private struct Reading {
        let numbers: RiskHistoryNumbers
        let threats: [ComparedThreat]
    }

    private func reading(
        at commit: SourceCommit,
        systems: [ProjectSystem],
        root: String
    ) -> Reading? {
        var totalScore = 0
        var byLevel: [String: Int] = [:]
        var worstScore = 0
        var threatCount = 0
        var acceptedRisks = 0
        var openAttackTrees = 0
        var catalogueTag: String?
        var readAnything = false
        var compared: [ComparedThreat] = []

        for system in systems {
            let parts = system.architecturePaths.compactMap { path in
                text(at: commit, path: path, root: root).map { SourcePart(file: path, text: $0) }
            }
            guard parts.isEmpty == false else { continue }

            let store = InMemoryThreatModelGateway()
            let imported = ImportArchitecture(
                models: store,
                catalogue: catalogue,
                sources: architectureSources,
                attackTreeSources: attackTreeSources,
                layout: layout
            ).execute(
                ImportArchitectureRequest(
                    text: parts.first?.text ?? "",
                    parts: system.isSplit ? parts : [],
                    directoryName: system.isSplit ? system.name : nil,
                    attackTreeTexts: system.attackTreePaths.compactMap {
                        text(at: commit, path: $0, root: root)
                    }
                )
            )
            guard case .imported(_, _, let tag) = imported else { return nil }
            catalogueTag = tag ?? catalogueTag

            for path in system.controlsPaths {
                guard let controlsText = text(at: commit, path: path, root: root) else { continue }
                let applied = ApplyControlAnswers(
                    models: store,
                    catalogue: catalogue,
                    sources: controlsSources
                ).execute(ApplyControlAnswersRequest(text: controlsText))
                if case .refused = applied { return nil }
            }

            if let governanceText = text(at: commit, path: system.governancePath, root: root) {
                let applied = ApplyGovernance(models: store, sources: governanceSources)
                    .execute(ApplyGovernanceRequest(text: governanceText))
                if case .refused = applied { return nil }
            }

            let assessed = AssessThreatModel(models: store, catalogue: catalogue)
                .execute(AssessThreatModelRequest())
            readAnything = true

            compared += assessed.threats.map(Self.compared)
            for threat in assessed.threats {
                totalScore += threat.riskScore
                worstScore = max(worstScore, threat.riskScore)
                byLevel[threat.riskLevel, default: 0] += 1
                threatCount += 1
                acceptedRisks += threat.controls
                    .filter { $0.statusId == ControlStatus.accepted.rawValue }
                    .count
            }
            openAttackTrees += assessed.attackTrees
                .filter { $0.isStale == false && $0.isOpen }
                .count
        }

        guard readAnything else { return nil }

        return Reading(
            numbers: RiskHistoryNumbers(
                totalScore: totalScore,
                byLevel: byLevel,
                worstScore: worstScore,
                threatCount: threatCount,
                acceptedRisks: acceptedRisks,
                openAttackTrees: openAttackTrees,
                catalogueTag: catalogueTag
            ),
            threats: compared
        )
    }

    /// One assessed threat, as the comparison reads it. Both sides of a
    /// comparison are built by this one function, so neither can read a field
    /// the other does not.
    public static func compared(_ threat: AssessedThreat) -> ComparedThreat {
        ComparedThreat(
            key: ThreatKey(threatId: threat.threatId, sourceId: threat.source.id),
            name: threat.name,
            sourceName: threat.source.displayName,
            riskScore: threat.riskScore,
            controlStatuses: Dictionary(
                threat.controls.map { ($0.description, $0.statusId) },
                uniquingKeysWith: { first, _ in first }
            ),
            acceptedControls: threat.controls
                .filter { $0.statusId == ControlStatus.accepted.rawValue }
                .map(\.description),
            reviewDates: Dictionary(
                threat.controls.compactMap { control in
                    control.reviewBy.map { (control.description, $0) }
                },
                uniquingKeysWith: { first, _ in first }
            )
        )
    }

    /// What one file of the project holds at one commit, or nil when that
    /// commit holds no such file.
    private func text(at commit: SourceCommit, path: String, root: String) -> String? {
        (try? history.file(root: root, at: commit.hash, path: relative(path, to: root))) ?? nil
    }

    /// `git show` names a path from the repository root, and a layout names it
    /// from the file system root.
    public static func relative(_ path: String, to root: String) -> String {
        let prefix = root.hasSuffix("/") ? root : root + "/"
        guard path.hasPrefix(prefix) else { return path }
        return String(path.dropFirst(prefix.count))
    }

    private func relative(_ path: String, to root: String) -> String {
        Self.relative(path, to: root)
    }
}
