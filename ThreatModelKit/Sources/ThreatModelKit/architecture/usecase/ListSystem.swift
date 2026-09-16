import Foundation

public protocol ListSystemUseCase {
    func execute(_ request: ListSystemRequest) -> ListSystemResponse
}

public struct ListSystemRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String

    public init(root: String, systemName: String) {
        self.root = root
        self.systemName = systemName
    }
}

/// What the systems picker states beside one system's name: the same
/// unanswered count and worst level `threatmodeller list` prints for it.
public struct SystemSummary: Equatable, Sendable {
    public let name: String
    /// True when the system's files did not parse. Every number is unknown
    /// rather than zero, the same rule `threatmodeller list` states for a row
    /// it cannot read.
    public let isUnparsed: Bool
    public let unanswered: Int
    public let worstLevel: String

    public init(name: String, isUnparsed: Bool, unanswered: Int = 0, worstLevel: String = "") {
        self.name = name
        self.isUnparsed = isUnparsed
        self.unanswered = unanswered
        self.worstLevel = worstLevel
    }
}

public enum ListSystemResponse: Equatable, Sendable {
    case listed(SystemSummary)
    case noSuchSystem
}

/// Says what the systems picker shows beside one system's name.
///
/// The executable and the window both read this, so the two say the same
/// numbers about the same system. The import runs on a store of its own, so
/// reading the numbers for the picker never changes the model on screen.
public struct ListSystem: ListSystemUseCase {
    private let projects: ProjectSourceGateway
    private let catalogue: TechnologyCatalogue
    private let architectureSources: ArchitectureSourceGateway
    private let controlsSources: ControlsSourceGateway
    private let attackTreeSources: AttackTreeSourceGateway

    public init(
        projects: ProjectSourceGateway,
        catalogue: TechnologyCatalogue,
        architectureSources: ArchitectureSourceGateway,
        controlsSources: ControlsSourceGateway,
        attackTreeSources: AttackTreeSourceGateway
    ) {
        self.projects = projects
        self.catalogue = catalogue
        self.architectureSources = architectureSources
        self.controlsSources = controlsSources
        self.attackTreeSources = attackTreeSources
    }

    public func execute(_ request: ListSystemRequest) -> ListSystemResponse {
        guard let layout = try? projects.discover(root: request.root) else {
            return .listed(SystemSummary(name: request.systemName, isUnparsed: true))
        }
        guard let system = layout.system(named: request.systemName) else {
            return .noSuchSystem
        }
        guard let architectureText = try? projects.read(path: system.architecturePath) else {
            return .listed(SystemSummary(name: system.name, isUnparsed: true))
        }

        // A store of its own: the same rule `CompileControls` follows, so
        // reading a system for the picker never changes what is drawn.
        let store = InMemoryThreatModelGateway()
        let imported = ImportArchitecture(
            models: store,
            catalogue: catalogue,
            sources: architectureSources,
            attackTreeSources: attackTreeSources,
            layout: nil
        ).execute(
            ImportArchitectureRequest(
                text: architectureText,
                attackTreeText: Self.text(at: system.attackTreePath, projects: projects),
                parts: system.isSplit ? Self.parts(of: system, projects: projects) : [],
                directoryName: system.isSplit ? system.name : nil,
                attackTreeTexts: system.isSplit ? Self.treeTexts(of: system, projects: projects) : []
            )
        )
        guard case .imported = imported else {
            return .listed(SystemSummary(name: system.name, isUnparsed: true))
        }

        if projects.exists(path: system.controlsPath),
           let controlsText = try? projects.read(path: system.controlsPath) {
            _ = ApplyControlAnswers(models: store, catalogue: catalogue, sources: controlsSources)
                .execute(ApplyControlAnswersRequest(text: controlsText))
        }

        let assessment = AssessThreatModel(models: store, catalogue: catalogue)
            .execute(AssessThreatModelRequest())
        let worst = assessment.threats.max { $0.riskScore < $1.riskScore }

        return .listed(
            SystemSummary(
                name: system.name,
                isUnparsed: false,
                unanswered: assessment.threats.filter(Self.isUnanswered).count,
                worstLevel: worst?.riskLevel ?? ""
            )
        )
    }

    /// A threat nobody has answered: no control carries an answer, and no
    /// compensating control stands. `threatmodeller list` counts the same
    /// way.
    private static func isUnanswered(_ threat: AssessedThreat) -> Bool {
        guard threat.compensatingLabels.isEmpty else { return false }
        return threat.controls.contains { $0.statusId != ControlStatus.notImplemented.rawValue }
            == false
    }

    /// The file at this path, or nil when the project holds no such file.
    private static func text(at path: String, projects: ProjectSourceGateway) -> String? {
        guard projects.exists(path: path) else { return nil }
        return try? projects.read(path: path)
    }

    /// Every architecture file of a split system, read.
    private static func parts(
        of system: ProjectSystem,
        projects: ProjectSourceGateway
    ) -> [SourcePart] {
        system.architecturePaths.compactMap { path in
            (try? projects.read(path: path)).map { SourcePart(file: path, text: $0) }
        }
    }

    /// Every attack tree file of a split system, read.
    private static func treeTexts(
        of system: ProjectSystem,
        projects: ProjectSourceGateway
    ) -> [String] {
        system.attackTreePaths
            .filter { projects.exists(path: $0) }
            .compactMap { try? projects.read(path: $0) }
    }
}
