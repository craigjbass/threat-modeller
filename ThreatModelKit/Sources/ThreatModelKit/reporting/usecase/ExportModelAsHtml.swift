public protocol ExportModelAsHtmlUseCase {
    func execute(_ request: ExportModelAsHtmlRequest) -> ExportModelAsHtmlResponse
}

public struct ExportModelAsHtmlRequest: Equatable, Sendable {
    /// The picture drawn for each of the top residual threats, by file name,
    /// keyed "<threat id>@<source id>".
    public let threatPictures: [String: String]
    /// The picture drawn for each control, by file name, keyed by the id of
    /// the component the protection comes from.
    public let controlPictures: [String: String]
    /// What each of those file names draws, as SVG. A page holds its own
    /// pictures, so it opens with no folder of files beside it. A file name
    /// this does not carry stays a link.
    public let pictureSources: [String: String]
    /// The whole system as SVG, written under the title. Nil draws none.
    public let wholePicture: String?
    /// The team's own shape for the report, or nil for the shape this
    /// application ships. The page reads its front matter for the banner and
    /// the cover.
    public let template: ReportTemplate?

    public init(
        threatPictures: [String: String] = [:],
        controlPictures: [String: String] = [:],
        pictureSources: [String: String] = [:],
        wholePicture: String? = nil,
        template: ReportTemplate? = nil
    ) {
        self.template = template
        self.threatPictures = threatPictures
        self.controlPictures = controlPictures
        self.pictureSources = pictureSources
        self.wholePicture = wholePicture
    }
}

public struct ExportModelAsHtmlResponse: Equatable, Sendable {
    public let html: String
    /// What the save panel offers as a name.
    public let fileName: String

    public init(html: String, fileName: String) {
        self.html = html
        self.fileName = fileName
    }
}

/// Writes the report as one page a browser shows and prints.
///
/// The page is the Markdown report converted, not a second report: the
/// sections, their order and their wording come from
/// `ExportModelAsMarkdown`, so a change to the report reaches both.
///
/// The page holds its pictures and its stylesheet, so it opens from any
/// folder, needs no network, and prints to A4 as a PDF.
public struct ExportModelAsHtml: ExportModelAsHtmlUseCase {
    private let markdown: ExportModelAsMarkdownUseCase

    public init(markdown: ExportModelAsMarkdownUseCase) {
        self.markdown = markdown
    }

    public func execute(_ request: ExportModelAsHtmlRequest) -> ExportModelAsHtmlResponse {
        let written = markdown.execute(
            ExportModelAsMarkdownRequest(
                threatPictures: request.threatPictures,
                controlPictures: request.controlPictures,
                template: request.template
            )
        )
        let stem = String(written.fileName.dropLast(3))
        // The tab says what the report says, which is the model's own name,
        // not the file name it was written under.
        let title = written.markdown
            .split(separator: "\n", omittingEmptySubsequences: false)
            .first { $0.hasPrefix("# ") }
            .map { String($0.dropFirst(2)) } ?? stem

        return ExportModelAsHtmlResponse(
            html: MarkdownToHtml.html(
                of: written.markdown,
                title: title,
                pictures: request.pictureSources,
                wholePicture: request.wholePicture,
                banner: request.template?.frontMatter.banner,
                cover: cover(of: request.template, titled: title)
            ),
            fileName: "\(stem).html"
        )
    }

    /// What the cover page states, or nil when the template asks for none.
    /// A template that asks for a cover and names no title covers the report
    /// with the system's own name.
    private func cover(
        of template: ReportTemplate?,
        titled title: String
    ) -> MarkdownToHtml.Cover? {
        guard let front = template?.frontMatter, front.hasCover else { return nil }
        return MarkdownToHtml.Cover(
            title: front.coverTitle ?? title,
            subtitle: front.coverSubtitle
        )
    }
}
