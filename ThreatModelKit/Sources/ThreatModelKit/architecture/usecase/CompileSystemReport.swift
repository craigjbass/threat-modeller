public protocol CompileSystemReportUseCase {
    func execute(_ request: CompileSystemReportRequest) -> CompileSystemReportResponse
}

public struct CompileSystemReportRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String

    public init(root: String, systemName: String) {
        self.root = root
        self.systemName = systemName
    }
}

public enum CompileSystemReportResponse: Equatable, Sendable {
    case written(path: String)
    case noSuchSystem
    case cannotWrite(reason: String)
}

/// Writes the Markdown report for one system of a project.
///
/// A report is an artefact, so it is written when a person asks for it and not
/// when they save.
public struct CompileSystemReport: CompileSystemReportUseCase {
    private let projects: ProjectSourceGateway
    private let markdown: ExportModelAsMarkdownUseCase

    public init(projects: ProjectSourceGateway, markdown: ExportModelAsMarkdownUseCase) {
        self.projects = projects
        self.markdown = markdown
    }

    public func execute(_ request: CompileSystemReportRequest) -> CompileSystemReportResponse {
        do {
            guard let system = try projects.discover(root: request.root)
                .system(named: request.systemName) else {
                return .noSuchSystem
            }

            try projects.write(
                markdown.execute(ExportModelAsMarkdownRequest()).markdown,
                to: system.reportPath
            )
            return .written(path: system.reportPath)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
    }
}
