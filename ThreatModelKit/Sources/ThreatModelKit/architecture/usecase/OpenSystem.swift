public protocol OpenSystemUseCase {
    func execute(_ request: OpenSystemRequest) -> OpenSystemResponse
}

public struct OpenSystemRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String

    public init(root: String, systemName: String) {
        self.root = root
        self.systemName = systemName
    }
}

public enum OpenSystemResponse: Equatable, Sendable {
    /// `catalogueTag` is the tag the `.arch` file states, or nil when it
    /// states none. The window compares it with the catalogue in use.
    case opened(name: String, warnings: [Diagnostic], catalogueTag: String? = nil)
    case refused(fileName: String, diagnostics: [Diagnostic])
    case noSuchSystem
    case cannotRead(reason: String)
}

/// Draws one system of a project.
public struct OpenSystem: OpenSystemUseCase {
    private let projects: ProjectSourceGateway
    private let imports: ImportArchitectureUseCase
    private let applies: ApplyControlAnswersUseCase
    private let governance: ApplyGovernanceUseCase?
    private let policy: ApplyPolicyUseCase?

    public init(
        projects: ProjectSourceGateway,
        imports: ImportArchitectureUseCase,
        applies: ApplyControlAnswersUseCase,
        governance: ApplyGovernanceUseCase? = nil,
        policy: ApplyPolicyUseCase? = nil
    ) {
        self.projects = projects
        self.imports = imports
        self.applies = applies
        self.governance = governance
        self.policy = policy
    }

    public func execute(_ request: OpenSystemRequest) -> OpenSystemResponse {
        let system: ProjectSystem
        do {
            guard let found = try projects.discover(root: request.root)
                .system(named: request.systemName) else {
                return .noSuchSystem
            }
            system = found
        } catch {
            return .cannotRead(reason: String(describing: error))
        }

        // Every architecture file of the system. A flat system holds one.
        var parts: [SourcePart] = []
        do {
            for path in system.architecturePaths {
                parts.append(SourcePart(file: path, text: try projects.read(path: path)))
            }
        } catch {
            return .cannotRead(reason: String(describing: error))
        }

        // The trees beside the architecture are part of the system, the way
        // the answers are.
        let attackTreeTexts = system.attackTreePaths
            .filter { projects.exists(path: $0) }
            .compactMap { try? projects.read(path: $0) }

        switch imports.execute(
            ImportArchitectureRequest(
                text: parts.first?.text ?? "",
                parts: system.isSplit ? parts : [],
                directoryName: system.isSplit ? system.name : nil,
                attackTreeTexts: attackTreeTexts
            )
        ) {
        case .imported(let name, let warnings, let catalogueTag):
            // The answers beside the architecture are part of the system, so
            // opening one reads both.
            var everyWarning = warnings
            for path in system.controlsPaths where projects.exists(path: path) {
                guard let controlsText = try? projects.read(path: path) else { continue }
                switch applies.execute(ApplyControlAnswersRequest(text: controlsText)) {
                case .applied(_, let controlWarnings):
                    everyWarning += controlWarnings
                case .refused(let diagnostics):
                    return .refused(
                        fileName: fileName(of: path),
                        diagnostics: diagnostics
                    )
                }
            }
            // Who carries each accepted risk is part of the system too. The
            // report and the threat card both read it; it moves no score.
            if let governance,
               projects.exists(path: system.governancePath),
               let governanceText = try? projects.read(path: system.governancePath) {
                switch governance.execute(ApplyGovernanceRequest(text: governanceText)) {
                case .applied:
                    break
                case .refused(let diagnostics):
                    return .refused(
                        fileName: fileName(of: system.governancePath),
                        diagnostics: diagnostics
                    )
                }
            }
            // The rules the project states for itself. The report says
            // whether this system keeps each one.
            if let policy,
               let layout = try? projects.discover(root: request.root),
               projects.exists(path: layout.policyPath),
               let policyText = try? projects.read(path: layout.policyPath) {
                switch policy.execute(ApplyPolicyRequest(text: policyText)) {
                case .applied:
                    break
                case .refused(let diagnostics):
                    return .refused(
                        fileName: ProjectConvention.policyFileName,
                        diagnostics: diagnostics
                    )
                }
            }
            return .opened(name: name, warnings: everyWarning, catalogueTag: catalogueTag)
        case .refused(let diagnostics):
            return .refused(
                fileName: fileName(of: system.architecturePath),
                diagnostics: diagnostics
            )
        }
    }

    private func fileName(of path: String) -> String {
        path.split(separator: "/").last.map(String.init) ?? path
    }
}
