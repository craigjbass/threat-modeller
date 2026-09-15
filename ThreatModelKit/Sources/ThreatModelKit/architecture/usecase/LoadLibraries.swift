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

            // A library states the catalogue tag it was written against. A
            // library written against another tag may name a threat this
            // catalogue no longer holds, so the reader is told which tag it
            // states and which tag is in use.
            if let stated = source.catalogueTag, stated != catalogue.version().tag {
                warnings.append(
                    Diagnostic(
                        severity: .warning,
                        line: 1,
                        column: 1,
                        message: "the library \"\(source.label)\" was written against catalogue "
                            + "\(stated), and the catalogue in use is \(catalogue.version().tag)"
                    )
                )
            }

            let built = Library.build(from: source, taxonomy: taxonomy)
            guard let library = built.library else {
                return .refused(
                    fileName: fileName,
                    diagnostics: built.faults.map { Self.fault($0.message) }
                )
            }

            // An override names a threat the catalogue holds. One that names
            // nothing is a fault a person fixes in the library file.
            let known = Set(Self.everyThreatId(of: catalogue))
            for id in library.overrides.keys where known.contains(id) == false {
                return .refused(
                    fileName: fileName,
                    diagnostics: [
                        Self.fault(
                            "the library \"\(source.label)\" overrides the threat "
                                + "\"\(id.value)\", which the catalogue does not hold"
                        )
                    ]
                )
            }

            // Two libraries that declare one word of the taxonomy is a fault
            // a person fixes in one of the two files, so the warning names
            // both libraries. The first one read stands.
            if library.classifications != nil,
               let other = libraries.first(where: { $0.classifications != nil }) {
                warnings.append(
                    Diagnostic(
                        severity: .warning,
                        line: 1,
                        column: 1,
                        message: "the library \"\(other.label)\" and the library "
                            + "\"\(library.label)\" both state a classification scheme; "
                            + "the one \"\(other.label)\" states stands"
                    )
                )
            }

            warnings += Self.clashes(of: library, against: libraries)
            libraries.append(library)
        }

        return .loaded(libraries: libraries, warnings: warnings)
    }

    /// Every threat id the catalogue holds, wherever it holds it.
    private static func everyThreatId(of catalogue: TechnologyCatalogue) -> [ThreatId] {
        catalogue.all().flatMap { catalogue.threatsFor(technologyId: $0.id).map(\.id) }
            + catalogue.connectionThreats().map(\.id)
            + catalogue.zoneThreats().map(\.id)
    }

    /// What this library declares that another library already declared.
    private static func clashes(of library: Library, against others: [Library]) -> [Diagnostic] {
        var said: [Diagnostic] = []

        func check(_ kind: String, _ id: String, _ owner: String?) {
            guard let owner else { return }
            said.append(
                Diagnostic(
                    severity: .warning,
                    line: 1,
                    column: 1,
                    message: "the \(kind) \"\(id)\" is declared by the library "
                        + "\"\(owner)\" and by the library \"\(library.label)\"; "
                        + "the one \"\(owner)\" states stands"
                )
            )
        }

        for category in library.categories {
            check(
                "category",
                category.id.value,
                others.first { $0.categories.contains { $0.id == category.id } }?.label
            )
        }
        for severity in library.severities {
            check(
                "severity",
                severity.id,
                others.first { $0.severities.contains { $0.id == severity.id } }?.label
            )
        }
        for stride in library.strides {
            check(
                "stride category",
                stride.id.value,
                others.first { $0.strides.contains { $0.id == stride.id } }?.label
            )
        }

        return said
    }

    /// A fault of the file rather than of one token, so it names the first line.
    private static func fault(_ message: String) -> Diagnostic {
        Diagnostic(severity: .error, line: 1, column: 1, message: message)
    }
}
