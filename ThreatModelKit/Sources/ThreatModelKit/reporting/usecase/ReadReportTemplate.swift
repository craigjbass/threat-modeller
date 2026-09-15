public protocol ReadReportTemplateUseCase {
    func execute(_ request: ReadReportTemplateRequest) -> ReadReportTemplateResponse
}

public struct ReadReportTemplateRequest: Equatable, Sendable {
    public let root: String
    /// A path the caller states, which wins over the policy file the way a
    /// flag wins over a file.
    public let statedPath: String?

    public init(root: String, statedPath: String? = nil) {
        self.root = root
        self.statedPath = statedPath
    }
}

public enum ReadReportTemplateResponse: Equatable, Sendable {
    /// The project states no template, so the report keeps its shipped shape.
    case none
    case found(ReportTemplate)
    /// The named file is not there. The report must not be written.
    case missing(path: String)
    /// The named file is not a template. The report must not be written.
    case didNotParse(path: String, diagnostics: [Diagnostic])
}

/// Reads the template a report renders through.
///
/// One resolution for every writer: the command line's `report` verb and the
/// window's report paths read the template here, so the two cannot drift.
/// A relative path is read from the project root.
public struct ReadReportTemplate: ReadReportTemplateUseCase {
    private let projects: ProjectSourceGateway
    private let policies: PolicySourceGateway

    public init(projects: ProjectSourceGateway, policies: PolicySourceGateway) {
        self.projects = projects
        self.policies = policies
    }

    public func execute(_ request: ReadReportTemplateRequest) -> ReadReportTemplateResponse {
        guard let named = request.statedPath ?? statedByPolicy(root: request.root) else {
            return .none
        }
        let path = named.hasPrefix("/") ? named : ProjectConvention.path(request.root, named)
        guard let text = try? projects.read(path: path) else {
            return .missing(path: path)
        }
        let read = ReportTemplate.read(text)
        guard let template = read.template else {
            return .didNotParse(path: path, diagnostics: read.diagnostics)
        }
        return .found(template)
    }

    /// The template the policy file states, or nil when the project holds no
    /// policy, the policy states none, or the policy does not read.
    private func statedByPolicy(root: String) -> String? {
        guard let layout = try? projects.discover(root: root) else { return nil }
        guard projects.exists(path: layout.policyPath) else { return nil }
        guard let text = try? projects.read(path: layout.policyPath) else { return nil }
        return policies.read(text).source?.template
    }
}
