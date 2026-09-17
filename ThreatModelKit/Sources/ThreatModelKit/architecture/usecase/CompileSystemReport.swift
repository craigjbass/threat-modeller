public protocol CompileSystemReportUseCase {
    func execute(_ request: CompileSystemReportRequest) -> CompileSystemReportResponse
}

public struct CompileSystemReportRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String
    /// The picture drawn for each of the top residual threats, by file name,
    /// keyed "<threat id>@<source id>". A caller that draws none passes none.
    public let threatPictures: [String: String]
    /// The picture drawn for each control, by file name, keyed by the id of
    /// the component the protection comes from.
    public let controlPictures: [String: String]
    /// What each of those file names draws, as SVG. This use case writes each
    /// one beside the report, so a reader opens the report with its pictures
    /// beside it.
    public let pictureFiles: [String: String]
    /// The file the caller drew the risk-over-time graph to, relative to the
    /// report, or nil when it drew none.
    public let riskOverTimePicture: String?
    /// What the model scored at each sampled commit, and what changed since
    /// the newest one. Empty when nobody sampled the history.
    public let history: [RiskHistoryRow]
    public let historyTruncated: Bool
    public let change: RiskChange?

    public init(
        root: String,
        systemName: String,
        threatPictures: [String: String] = [:],
        controlPictures: [String: String] = [:],
        pictureFiles: [String: String] = [:],
        riskOverTimePicture: String? = nil,
        history: [RiskHistoryRow] = [],
        historyTruncated: Bool = false,
        change: RiskChange? = nil
    ) {
        self.root = root
        self.systemName = systemName
        self.threatPictures = threatPictures
        self.controlPictures = controlPictures
        self.pictureFiles = pictureFiles
        self.riskOverTimePicture = riskOverTimePicture
        self.history = history
        self.historyTruncated = historyTruncated
        self.change = change
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

            // Each picture goes beside the report, the way the executable's
            // report verb writes it, so a link the report states resolves.
            let beside = String(
                system.reportPath.dropLast("\(request.systemName).md".count)
            )
            for (fileName, svg) in request.pictureFiles.sorted(by: { $0.key < $1.key }) {
                try projects.write(svg, to: beside + fileName)
            }

            try projects.write(
                markdown.execute(
                    ExportModelAsMarkdownRequest(
                        threatPictures: request.threatPictures,
                        controlPictures: request.controlPictures,
                        template: template,
                        riskOverTimePicture: request.riskOverTimePicture,
                        history: request.history,
                        historyTruncated: request.historyTruncated,
                        change: request.change
                    )
                ).markdown,
                to: system.reportPath
            )
            return .written(path: system.reportPath)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
    }
}
