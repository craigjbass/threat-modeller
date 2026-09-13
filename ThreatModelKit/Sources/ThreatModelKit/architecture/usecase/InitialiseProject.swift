import Foundation

public protocol InitialiseProjectUseCase {
    func execute(_ request: InitialiseProjectRequest) -> InitialiseProjectResponse
}

/// What a project starts from.
public enum ProjectStart: Equatable, Sendable {
    /// A bundled example, or the first one when the id is nil.
    case example(id: String?)
    /// A system with a name and nothing else, for a user who already knows
    /// what they are about to draw.
    case empty(systemName: String)
}

public struct InitialiseProjectRequest: Equatable, Sendable {
    public let root: String
    public let start: ProjectStart

    public init(root: String, start: ProjectStart = .example(id: nil)) {
        self.root = root
        self.start = start
    }
}

public enum InitialiseProjectResponse: Equatable, Sendable {
    case created(systemName: String, path: String)
    /// The root already holds a system, so nothing was written.
    case alreadyHasSystems(names: [String])
    case noSuchSample
    /// An empty start was asked for with no name to give the system.
    case needsASystemName
    case notAProject(reason: String)
    case cannotWrite(reason: String)
}

/// Writes a bundled example into an empty project root.
///
/// A user who opens a directory with nothing in it gets a system to read rather
/// than an empty window. The example is one this application already ships, so
/// what a project starts from and what the samples browser opens are the same
/// thing.
///
/// It never writes over a system: a root that already holds one is refused.
public struct InitialiseProject: InitialiseProjectUseCase {
    private let projects: ProjectSourceGateway
    private let samples: SampleModelGateway
    private let files: ThreatModelFileGateway
    private let sources: ArchitectureSourceGateway

    public init(
        projects: ProjectSourceGateway,
        samples: SampleModelGateway,
        files: ThreatModelFileGateway,
        sources: ArchitectureSourceGateway
    ) {
        self.projects = projects
        self.samples = samples
        self.files = files
        self.sources = sources
    }

    public func execute(_ request: InitialiseProjectRequest) -> InitialiseProjectResponse {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: request.root)
        } catch ProjectError.notADirectory(let path) {
            return .notAProject(reason: "\(path) is not a directory")
        } catch {
            return .notAProject(reason: String(describing: error))
        }

        guard layout.systems.isEmpty else {
            return .alreadyHasSystems(names: layout.systems.map(\.name))
        }

        let model: ThreatModel
        let fileName: String

        switch request.start {
        case .example(let sampleId):
            let every = samples.all()
            let chosen = sampleId.map { id in every.first { $0.id == id } } ?? every.first
            guard let sample = chosen else { return .noSuchSample }

            do {
                model = try files.decode(try samples.document(id: sample.id))
            } catch {
                return .cannotWrite(reason: String(describing: error))
            }
            fileName = sample.id

        case .empty(let systemName):
            let name = systemName.trimmingCharacters(in: .whitespacesAndNewlines)
            guard name.isEmpty == false else { return .needsASystemName }
            let slug = ProjectConvention.fileName(forSystemNamed: name)
            guard slug.isEmpty == false else { return .needsASystemName }

            model = ThreatModel(name: name)
            fileName = slug
        }

        // A new project takes the convention directory, whatever the root held
        // before. The fallback to the root is for a project that already has
        // files there.
        let directory = ProjectConvention.path(
            request.root,
            type(of: projects).conventionDirectory
        )
        let path = ProjectConvention.path(
            directory,
            "\(fileName).\(ProjectConvention.architectureExtension)"
        )

        do {
            try projects.write(sources.write(ArchitectureSourceBuilder.source(from: model)), to: path)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }

        return .created(systemName: fileName, path: path)
    }
}
