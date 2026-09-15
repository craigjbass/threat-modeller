public protocol MoveTechnologyToLibraryUseCase {
    func execute(_ request: MoveTechnologyToLibraryRequest) -> MoveTechnologyToLibraryResponse
}

public struct MoveTechnologyToLibraryRequest: Equatable, Sendable {
    public let root: String
    /// The technology this model defines, by its identifier.
    public let technologyId: String
    /// The library it moves into. A project's own library is a `.lib` file in
    /// the project's `library` directory, and every system in the project
    /// reads it.
    public let libraryLabel: String

    public init(root: String, technologyId: String, libraryLabel: String) {
        self.root = root
        self.technologyId = technologyId
        self.libraryLabel = libraryLabel
    }
}

public enum MoveTechnologyToLibraryResponse: Equatable, Sendable {
    /// The identifier the technology now has, which is the library's own
    /// minting, and the file it was written to.
    case moved(technologyId: String, path: String)
    case unknownTechnology
    case notAProject(reason: String)
    case cannotWrite(reason: String)
    /// The library already states a technology with that identifier.
    case alreadyInTheLibrary(technologyId: String)
}

/// Moves a technology this model defines into a library file the project
/// holds.
///
/// A custom technology belongs to the system that defines it, so a team that
/// wants one in two systems wrote it twice. This writes it into
/// `<directory>/library/<label>.lib`, which every system in the project reads,
/// and another project vendors with `threatmodeller library add`.
///
/// The technology's identifier changes: a library mints `<label>-<id>`, the
/// way it mints every other identifier it states. Every component that named
/// the old identifier names the new one, so the diagram is unchanged.
public struct MoveTechnologyToLibrary: MoveTechnologyToLibraryUseCase {
    private let models: ThreatModelGateway
    private let projects: ProjectSourceGateway
    private let libraries: LibrarySourceGateway

    public init(
        models: ThreatModelGateway,
        projects: ProjectSourceGateway,
        libraries: LibrarySourceGateway
    ) {
        self.models = models
        self.projects = projects
        self.libraries = libraries
    }

    public func execute(
        _ request: MoveTechnologyToLibraryRequest
    ) -> MoveTechnologyToLibraryResponse {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: request.root)
        } catch {
            return .notAProject(reason: String(describing: error))
        }

        let technologyId = TechnologyId(request.technologyId)
        guard let technology = models.current().customTechnologies
            .first(where: { $0.id == technologyId }) else {
            return .unknownTechnology
        }

        let path = ProjectConvention.path(
            ProjectConvention.path(layout.directory, ProjectConvention.libraryDirectory),
            "\(request.libraryLabel).\(ProjectConvention.libraryExtension)"
        )

        // The library the project already holds under that label, or a new one.
        var source = LibrarySource(label: request.libraryLabel)
        if projects.exists(path: path) {
            guard let text = try? projects.read(path: path),
                  let read = libraries.read(text).source else {
                return .cannotWrite(reason: "\(path) does not parse")
            }
            source = read
        }

        // A library mints `<label>-<id>`, so the written id is the bare one.
        let bareId = Self.bare(technology.id.value)
        guard source.technologies.contains(where: { $0.id == bareId }) == false else {
            return .alreadyInTheLibrary(technologyId: "\(request.libraryLabel)-\(bareId)")
        }

        let written = LibrarySource(
            label: source.label,
            displayName: source.displayName,
            catalogueTag: source.catalogueTag,
            technologies: source.technologies + [
                SourceTechnology(
                    id: bareId,
                    name: technology.name,
                    category: technology.category.value,
                    description: technology.description,
                    threatIds: technology.threatIds.map(\.value),
                    encrypts: technology.enforcesEncryption,
                    controlDescriptions: technology.controls
                )
            ],
            threats: source.threats,
            mitigations: source.mitigations,
            threatActors: source.threatActors,
            categories: source.categories,
            severities: source.severities,
            strides: source.strides,
            overrides: source.overrides,
            classifications: source.classifications
        )

        do {
            try projects.write(libraries.write(written), to: path)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }

        let newId = TechnologyId("\(request.libraryLabel)-\(bareId)")
        return models.mutate(label: ChangeLabel.moveTechnologyToLibrary) { model in
            model.customTechnologies.removeAll { $0.id == technologyId }
            for index in model.components.indices
            where model.components[index].technologyId == technologyId {
                model.components[index].technologyId = newId
            }
            return .moved(technologyId: newId.value, path: path)
        }
    }

    /// The identifier without the minting a model gives its own technologies.
    /// `custom-3` becomes `3`; a name a person chose stays as it is.
    private static func bare(_ id: String) -> String {
        id.hasPrefix("custom-") ? String(id.dropFirst("custom-".count)) : id
    }
}
