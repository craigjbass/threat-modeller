import AppKit
import ThreatModelKit
import UniformTypeIdentifiers

/// Writes a report where the user says.
///
/// Nothing writes a file the user did not name, so every export goes through a
/// save panel. `chooseFile` is a closure so a test can run the whole path
/// without one.
@MainActor
struct ReportExporter {
    enum Kind: String, CaseIterable {
        case markdown
        case threatcl
        case pdf
        case image

        var menuTitle: String {
            switch self {
            case .markdown: "Export as Markdown\u{2026}"
            case .threatcl: "Export as threatcl\u{2026}"
            case .pdf: "Export as PDF\u{2026}"
            case .image: "Export as Image\u{2026}"
            }
        }

        var contentType: UTType {
            switch self {
            case .markdown: UTType(filenameExtension: "md") ?? .plainText
            case .threatcl: UTType(filenameExtension: "hcl") ?? .plainText
            case .pdf: .pdf
            case .image: .png
            }
        }
    }

    let session: ThreatModelSession
    /// Asks the user where the file goes, and returns nil when they cancel.
    var chooseFile: @MainActor (_ suggestedName: String, _ contentType: UTType) -> URL?
        = ReportExporter.savePanel

    func export(_ kind: Kind) {
        guard let export = data(for: kind) else { return }
        guard let url = chooseFile(export.fileName, kind.contentType) else { return }

        do {
            try export.data.write(to: url)
        } catch {
            session.reportExportFailed(String(describing: error))
        }
    }

    /// The bytes and the name, or nil when the report could not be produced.
    func data(for kind: Kind) -> (data: Data, fileName: String)? {
        switch kind {
        case .markdown:
            session.markdownExport()
        case .threatcl:
            session.threatclExport()
        case .pdf:
            session.pdfExport()
        case .image:
            image()
        }
    }

    private func image() -> (data: Data, fileName: String)? {
        let area = session.imageArea()
        do {
            return (
                try CanvasImageRenderer().png(
                    of: session.canvas,
                    risks: session.elementRisks,
                    area: area
                ),
                area.fileName
            )
        } catch {
            session.reportExportFailed(String(describing: error))
            return nil
        }
    }

    static func savePanel(suggestedName: String, contentType: UTType) -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        panel.allowedContentTypes = [contentType]
        panel.canCreateDirectories = true
        return panel.runModal() == .OK ? panel.url : nil
    }
}
