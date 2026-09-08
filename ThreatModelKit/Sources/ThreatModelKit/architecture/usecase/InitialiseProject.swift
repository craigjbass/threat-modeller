public protocol InitialiseProjectUseCase {
    func execute(_ request: InitialiseProjectRequest) -> InitialiseProjectResponse
}

public struct InitialiseProjectRequest: Equatable, Sendable {
    public let root: String
    /// Which bundled example to write, or nil for the first one.
    public let sampleId: String?

    public init(root: String, sampleId: String? = nil) {
        self.root = root
        self.sampleId = sampleId
    }
}

public enum InitialiseProjectResponse: Equatable, Sendable {
    case created(systemName: String, path: String)
    /// The root already holds a system, so nothing was written.
    case alreadyHasSystems(names: [String])
    case noSuchSample
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

        let every = samples.all()
        let chosen: SampleModel?
        if let sampleId = request.sampleId {
            chosen = every.first { $0.id == sampleId }
        } else {
            chosen = every.first
        }
        guard let sample = chosen else { return .noSuchSample }

        let model: ThreatModel
        do {
            model = try files.decode(try samples.document(id: sample.id))
        } catch {
            return .cannotWrite(reason: String(describing: error))
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
            "\(sample.id).\(ProjectConvention.architectureExtension)"
        )

        do {
            try projects.write(sources.write(ArchitectureSourceBuilder.source(from: model)), to: path)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }

        return .created(systemName: sample.id, path: path)
    }
}
