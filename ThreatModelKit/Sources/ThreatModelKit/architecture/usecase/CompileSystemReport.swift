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
    private let templates: ReadReportTemplateUseCase
    private let markdown: ExportModelAsMarkdownUseCase

    public init(
        projects: ProjectSourceGateway,
        templates: ReadReportTemplateUseCase,
        markdown: ExportModelAsMarkdownUseCase
    ) {
        self.projects = projects
        self.templates = templates
        self.markdown = markdown
    }

    public func execute(_ request: CompileSystemReportRequest) -> CompileSystemReportResponse {
        do {
            guard let system = try projects.discover(root: request.root)
                .system(named: request.systemName) else {
                return .noSuchSystem
            }

            // A template the policy names but this use case cannot read stops
            // the write, the way it stops the command line run.
            var template: ReportTemplate?
            switch templates.execute(ReadReportTemplateRequest(root: request.root)) {
            case .none:
                break
            case .found(let found, _):
                template = found
            case .missing(let path):
                return .cannotWrite(reason: "there is no template at \(path)")
            case .didNotParse(let path, let diagnostics):
                return .cannotWrite(
                    reason: diagnostics.map { $0.described(in: path) }.joined(separator: "\n")
                )
            }

            try projects.write(
                markdown.execute(ExportModelAsMarkdownRequest(template: template)).markdown,
                to: system.reportPath
            )
            return .written(path: system.reportPath)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
    }
}
