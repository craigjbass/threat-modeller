import Foundation

public protocol CheckSystemUseCase {
    func execute(_ request: CheckSystemRequest) -> CheckSystemResponse
}

public struct CheckSystemRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String
    /// A risk level that overrides what the architecture file states, or nil.
    public let tolerance: String?

    public init(root: String, systemName: String, tolerance: String? = nil) {
        self.root = root
        self.systemName = systemName
        self.tolerance = tolerance
    }
}

/// One line `check` prints, and the group it prints it under.
public struct CheckFinding: Equatable, Hashable, Sendable {
    public enum Category: Equatable, Hashable, Sendable {
        case diagnostic
        case unanswered
        case stale
        case staleTree
        case governance
    }

    public let category: Category
    public let said: String

    public init(category: Category, said: String) {
        self.category = category
        self.said = said
    }
}

/// What `check` found in one system.
///
/// The executable and the window both read this, so the two say the same
/// words about the same project.
public struct SystemCheck: Equatable, Sendable {
    public let name: String
    /// False when a file did not parse. `check` exits 2 for it.
    public let didParse: Bool
    /// Why the architecture file could not be read, or nil. `check` exits 3
    /// for it.
    public let unreadable: String?
    /// Where a diagnostic is described: the controls file after a parse, the
    /// architecture file when the parse refused.
    public let diagnosticsPath: String
    public let controlsPath: String
    public let governancePath: String
    /// The controls text on disk, so a caller can name the line a threat's
    /// stanza sits on. Nil when the file does not exist.
    public let controlsText: String?
    public let diagnostics: [Diagnostic]
    public let unanswered: [UnansweredThreat]
    public let stale: [String]
    public let staleTrees: [String]
    /// Governance failures, unevidenced controls and policy breaches, as
    /// `CheckControlAnswers` answers them.
    public let governance: [String]
    /// The risk tolerance the answers were measured against. Empty when the
    /// files did not parse.
    public let tolerance: String

    public init(
        name: String,
        didParse: Bool,
        unreadable: String?,
        diagnosticsPath: String,
        controlsPath: String,
        governancePath: String,
        controlsText: String?,
        diagnostics: [Diagnostic],
        unanswered: [UnansweredThreat],
        stale: [String],
        staleTrees: [String],
        governance: [String],
        tolerance: String
    ) {
        self.name = name
        self.didParse = didParse
        self.unreadable = unreadable
        self.diagnosticsPath = diagnosticsPath
        self.controlsPath = controlsPath
        self.governancePath = governancePath
        self.controlsText = controlsText
        self.diagnostics = diagnostics
        self.unanswered = unanswered
        self.stale = stale
        self.staleTrees = staleTrees
        self.governance = governance
        self.tolerance = tolerance
    }

    /// True when `check` prints no failure for this system. A warning prints
    /// but does not fail.
    public var passes: Bool {
        didParse && unreadable == nil && unanswered.isEmpty && stale.isEmpty
            && staleTrees.isEmpty && governance.isEmpty
    }

    /// How many findings fail the check. Warnings are not counted.
    public var failureCount: Int {
        guard unreadable == nil else { return 1 }
        guard didParse else { return findings.count }
        return unanswered.count + stale.count + staleTrees.count + governance.count
    }

    /// The lines `check` prints for this system, in the order it prints them.
    public var findings: [CheckFinding] {
        if let unreadable {
            return [CheckFinding(category: .diagnostic, said: "threatmodeller: \(unreadable)")]
        }
        var found = diagnostics.map {
            CheckFinding(category: .diagnostic, said: $0.described(in: diagnosticsPath))
        }
        guard didParse else { return found }
        found += unanswered.map {
            CheckFinding(category: .unanswered, said: "\(controlsPath): \($0.described)")
        }
        found += stale.map {
            CheckFinding(
                category: .stale,
                said: "\(controlsPath): \($0) is answered but no longer raised"
            )
        }
        found += staleTrees.map {
            CheckFinding(category: .staleTree, said: "\(controlsPath): \($0)")
        }
        found += governance.map {
            CheckFinding(category: .governance, said: "\(governancePath): \($0)")
        }
        return found
    }

    /// What `check` says about the tolerance it measured against, or nil when
    /// nothing was measured.
    public var toleranceLine: String? {
        guard didParse else { return nil }
        return "\(name): checked against a \(tolerance) risk tolerance"
    }

    /// What `check` says about a system with no failure.
    public var allAnsweredLine: String { "\(name): every threat is answered" }
}

public enum CheckSystemResponse: Equatable, Sendable {
    case checked(SystemCheck)
    case noSuchSystem
}

/// Says what `threatmodeller check` says about one system: the same
/// categories, the same words.
///
/// The verb prints what this answers and the window lists it, so a pull
/// request never fails on a thing the window did not show.
public struct CheckSystem: CheckSystemUseCase {
    private let projects: ProjectSourceGateway
    private let checks: CheckControlAnswersUseCase

    public init(projects: ProjectSourceGateway, checks: CheckControlAnswersUseCase) {
        self.projects = projects
        self.checks = checks
    }

    public func execute(_ request: CheckSystemRequest) -> CheckSystemResponse {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: request.root)
        } catch {
            return .checked(
                Self.unreadable(name: request.systemName, reason: Self.described(error))
            )
        }
        guard let system = layout.systems.first(where: { $0.name == request.systemName }) else {
            return .noSuchSystem
        }

        let architectureText: String
        do {
            architectureText = try projects.read(path: system.architecturePath)
        } catch {
            return .checked(
                Self.unreadable(name: system.name, reason: Self.described(error), of: system)
            )
        }
        let controlsText = projects.exists(path: system.controlsPath)
            ? try? projects.read(path: system.controlsPath)
            : nil

        let response = checks.execute(
            CheckControlAnswersRequest(
                architectureText: architectureText,
                controlsText: controlsText,
                attackTreeText: text(at: system.attackTreePath),
                governanceText: text(at: system.governancePath),
                policyText: text(at: layout.policyPath),
                tolerance: request.tolerance,
                architectureParts: system.isSplit ? parts(of: system) : [],
                directoryName: system.isSplit ? system.name : nil,
                controlsParts: system.isSplit ? controlsTexts(of: system) : [:],
                attackTreeTexts: system.isSplit ? treeTexts(of: system) : [],
                architecturePath: system.architecturePath,
                vulnerabilityLockText: text(at: layout.vulnerabilityLockPath)
            )
        )

        switch response {
        case .refused(let diagnostics):
            return .checked(
                SystemCheck(
                    name: system.name,
                    didParse: false,
                    unreadable: nil,
                    diagnosticsPath: system.architecturePath,
                    controlsPath: system.controlsPath,
                    governancePath: system.governancePath,
                    controlsText: controlsText,
                    diagnostics: diagnostics,
                    unanswered: [],
                    stale: [],
                    staleTrees: [],
                    governance: [],
                    tolerance: ""
                )
            )
        case .checked(
            let unanswered,
            let stale,
            let staleTrees,
            let governance,
            let diagnostics,
            let tolerance
        ):
            return .checked(
                SystemCheck(
                    name: system.name,
                    didParse: true,
                    unreadable: nil,
                    diagnosticsPath: system.controlsPath,
                    controlsPath: system.controlsPath,
                    governancePath: system.governancePath,
                    controlsText: controlsText,
                    diagnostics: diagnostics,
                    unanswered: unanswered,
                    stale: stale,
                    staleTrees: staleTrees,
                    governance: governance,
                    tolerance: tolerance
                )
            )
        }
    }

    /// The file at this path, or nil when the project holds no such file.
    private func text(at path: String) -> String? {
        guard projects.exists(path: path) else { return nil }
        return try? projects.read(path: path)
    }

    /// Every architecture file of a split system, read.
    private func parts(of system: ProjectSystem) -> [SourcePart] {
        system.architecturePaths.compactMap { path in
            (try? projects.read(path: path)).map { SourcePart(file: path, text: $0) }
        }
    }

    /// Every controls file of a split system, by path.
    private func controlsTexts(of system: ProjectSystem) -> [String: String] {
        var held: [String: String] = [:]
        for path in system.controlsPaths where projects.exists(path: path) {
            held[path] = (try? projects.read(path: path)) ?? ""
        }
        return held
    }

    /// Every attack tree file of a split system, read.
    private func treeTexts(of system: ProjectSystem) -> [String] {
        system.attackTreePaths
            .filter { projects.exists(path: $0) }
            .compactMap { try? projects.read(path: $0) }
    }

    /// A system whose architecture file could not be read.
    private static func unreadable(
        name: String,
        reason: String,
        of system: ProjectSystem? = nil
    ) -> SystemCheck {
        SystemCheck(
            name: name,
            didParse: false,
            unreadable: reason,
            diagnosticsPath: system?.architecturePath ?? "",
            controlsPath: system?.controlsPath ?? "",
            governancePath: system?.governancePath ?? "",
            controlsText: nil,
            diagnostics: [],
            unanswered: [],
            stale: [],
            staleTrees: [],
            governance: [],
            tolerance: ""
        )
    }

    /// A read error, in the words the executable prints.
    private static func described(_ error: Error) -> String {
        switch error {
        case ProjectError.notADirectory(let path): "\(path) is not a directory"
        case ProjectError.cannotRead(let path, let reason): "cannot read \(path): \(reason)"
        case ProjectError.cannotWrite(let path, let reason): "cannot write \(path): \(reason)"
        default: String(describing: error)
        }
    }
}
