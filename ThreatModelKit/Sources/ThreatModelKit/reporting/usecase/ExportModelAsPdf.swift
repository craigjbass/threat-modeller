public protocol ExportModelAsPdfUseCase {
    func execute(_ request: ExportModelAsPdfRequest) -> ExportModelAsPdfResponse
}

public struct ExportModelAsPdfRequest: Equatable, Sendable {
    public init() {}
}

public enum ExportModelAsPdfResponse: Equatable, Sendable {
    case exported(bytes: [UInt8], fileName: String)
    case cannotRender(reason: String)
}

/// Asks the renderer for the report as PDF bytes.
public struct ExportModelAsPdf: ExportModelAsPdfUseCase {
    private let reports: BuildThreatModelReportUseCase
    private let renderer: ReportRenderer

    public init(reports: BuildThreatModelReportUseCase, renderer: ReportRenderer) {
        self.reports = reports
        self.renderer = renderer
    }

    public func execute(_ request: ExportModelAsPdfRequest) -> ExportModelAsPdfResponse {
        let report = reports.execute(BuildThreatModelReportRequest()).report

        do {
            return .exported(
                bytes: try renderer.render(report),
                fileName: "\(FileNaming.stem(from: report.modelName)).pdf"
            )
        } catch {
            return .cannotRender(reason: String(describing: error))
        }
    }
}
