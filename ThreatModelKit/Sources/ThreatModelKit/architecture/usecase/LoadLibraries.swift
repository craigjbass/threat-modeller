public protocol LoadLibrariesUseCase {
    func execute(_ request: LoadLibrariesRequest) -> LoadLibrariesResponse
}

public struct LoadLibrariesRequest: Equatable, Sendable {
    public let root: String

    public init(root: String) {
        self.root = root
    }
}

public enum LoadLibrariesResponse: Equatable, Sendable {
    case loaded(libraries: [Library], warnings: [Diagnostic])
    /// A library that does not load stops the project, because half a
    /// catalogue draws a diagram nobody can trust.
    case refused(fileName: String, diagnostics: [Diagnostic])
    case notAProject(reason: String)
}

/// Reads every library file a project holds.
///
/// The taxonomy is catalogue data, so the parser accepts any severity, stride
/// category or service category, and this use case is what refuses a value the
/// taxonomy does not hold.
public struct LoadLibraries: LoadLibrariesUseCase {
    private let projects: ProjectSourceGateway
    private let sources: LibrarySourceGateway
    private let catalogue: TechnologyCatalogue

    public init(
        projects: ProjectSourceGateway,
        sources: LibrarySourceGateway,
        catalogue: TechnologyCatalogue
    ) {
        self.projects = projects
        self.sources = sources
        self.catalogue = catalogue
    }

    public func execute(_ request: LoadLibrariesRequest) -> LoadLibrariesResponse {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: request.root)
        } catch ProjectError.notADirectory(let path) {
            return .notAProject(reason: "\(path) is not a directory")
        } catch {
            return .notAProject(reason: String(describing: error))
        }

        var libraries: [Library] = []
        var warnings: [Diagnostic] = []
        var labels: Set<String> = []
        let taxonomy = catalogue.taxonomy()

        for path in layout.libraryPaths {
            let fileName = String(path.split(separator: "/").last ?? "")

            let text: String
            do {
                text = try projects.read(path: path)
            } catch {
                return .refused(fileName: fileName, diagnostics: [Self.fault(String(describing: error))])
            }

            let read = sources.read(text)
            guard let source = read.source else {
                return .refused(fileName: fileName, diagnostics: read.diagnostics)
            }
            warnings += read.warnings

            guard labels.insert(source.label).inserted else {
                return .refused(
                    fileName: fileName,
                    diagnostics: [
                        Self.fault("this project already holds a library called \"\(source.label)\"")
                    ]
                )
            }

            let built = Library.build(from: source, taxonomy: taxonomy)
            guard let library = built.library else {
                return .refused(
                    fileName: fileName,
                    diagnostics: built.faults.map { Self.fault($0.message) }
                )
            }
            libraries.append(library)
        }

        return .loaded(libraries: libraries, warnings: warnings)
    }

    /// A fault of the file rather than of one token, so it names the first line.
    private static func fault(_ message: String) -> Diagnostic {
        Diagnostic(severity: .error, line: 1, column: 1, message: message)
    }
}
