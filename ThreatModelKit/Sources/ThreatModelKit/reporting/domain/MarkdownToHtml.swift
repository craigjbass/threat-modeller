import Foundation

/// Turns the report's Markdown into a page a browser shows and prints.
///
/// The report has one shape, written once by `ExportModelAsMarkdown`. This
/// converts that shape rather than writing the report a second time, so the
/// two can never drift.
///
/// It is not a Markdown parser. It reads the constructs the report writes and
/// nothing else: headings, tables, bullets at two depths, images, links,
/// `code`, `**bold**` and paragraphs. A line it does not know becomes a
/// paragraph, with every angle bracket escaped, so an unknown line shows as
/// text rather than as markup.
public enum MarkdownToHtml {
    /// A picture the page holds itself, by the file name the Markdown names.
    public typealias Pictures = [String: String]

    public static func html(
        of markdown: String,
        title: String,
        pictures: Pictures = [:],
        wholePicture: String? = nil
    ) -> String {
        var body: [String] = []
        var table: [String] = []
        var list: [String] = []
        /// True while the open list is a numbered one. A report numbers the
        /// scoring stages and the worst risks, and a numbered line written as
        /// a paragraph shows its own "1." on every line.
        var listIsNumbered = false
        var wroteWholePicture = false

        func closeTable() {
            guard table.isEmpty == false else { return }
            body.append(tableHtml(table))
            table = []
        }

        func closeList() {
            guard list.isEmpty == false else { return }
            let tag = listIsNumbered ? "ol" : "ul"
            body.append("<\(tag)>\n" + list.joined(separator: "\n") + "\n</\(tag)>")
            list = []
            listIsNumbered = false
        }

        /// Adds a line to the item above it rather than opening a list of its
        /// own, so an item that runs to a second line stays one item.
        func addUnder(_ text: String) {
            guard let last = list.last else {
                list.append("<li>\(text)</li>")
                return
            }
            list[list.count - 1] = last.replacingOccurrences(
                of: "</li>",
                with: "<br><span class=\"under\">\(text)</span></li>"
            )
        }

        for line in markdown.split(separator: "\n", omittingEmptySubsequences: false).map(String.init) {
            if line.hasPrefix("|") {
                closeList()
                table.append(line)
                continue
            }
            closeTable()

            if let picture = image(in: line) {
                closeList()
                body.append(figure(picture, pictures: pictures))
                continue
            }

            if line.hasPrefix("  - ") {
                // A nested bullet joins the item above it rather than opening
                // a list of its own: the report nests one level and no more.
                addUnder(inline(String(line.dropFirst(4))))
                continue
            }

            if list.isEmpty == false, line.hasPrefix("   "), line.trimmed().isEmpty == false {
                // An indented line under an item continues that item. Closing
                // the list here would start the next item's list again at one.
                addUnder(inline(line.trimmed()))
                continue
            }

            if line.hasPrefix("- ") {
                if listIsNumbered { closeList() }
                list.append("<li>\(inline(String(line.dropFirst(2))))</li>")
                continue
            }

            if let digits = numberedMarker(of: line) {
                if list.isEmpty == false, listIsNumbered == false { closeList() }
                listIsNumbered = true
                list.append("<li>\(inline(String(line.dropFirst(digits))))</li>")
                continue
            }
            closeList()

            if line.hasPrefix("#") {
                let level = min(6, line.prefix(while: { $0 == "#" }).count)
                let text = inline(String(line.dropFirst(level)).trimmed())
                body.append("<h\(level)>\(text)</h\(level)>")

                if level == 1, wroteWholePicture == false, let whole = wholePicture {
                    body.append("<figure class=\"whole\">\(whole)</figure>")
                    wroteWholePicture = true
                }
                continue
            }

            guard line.trimmed().isEmpty == false else { continue }
            body.append("<p>\(inline(line))</p>")
        }

        closeTable()
        closeList()

        return page(title: title, body: body.joined(separator: "\n"))
    }

    // MARK: one construct

    /// How many characters a numbered item's marker takes, or nil when the
    /// line starts with something else. `"12. text"` gives 4.
    static func numberedMarker(of line: String) -> Int? {
        let digits = line.prefix(while: \.isNumber).count
        guard digits > 0, line.dropFirst(digits).hasPrefix(". ") else { return nil }
        return digits + 2
    }

    /// The alt text and the file name of an image line, or nil.
    static func image(in line: String) -> (alt: String, name: String)? {
        let text = line.trimmed()
        guard text.hasPrefix("!["), text.hasSuffix(")"),
              let close = text.firstIndex(of: "]"),
              text.index(after: close) < text.endIndex,
              text[text.index(after: close)] == "("
        else { return nil }

        let alt = String(text[text.index(text.startIndex, offsetBy: 2) ..< close])
        let name = String(text[text.index(close, offsetBy: 2) ..< text.index(before: text.endIndex)])
        return (alt, name)
    }

    static func figure(_ picture: (alt: String, name: String), pictures: Pictures) -> String {
        // A page that holds its own pictures opens anywhere, with no folder of
        // files beside it. One the caller did not supply stays a link.
        guard let svg = pictures[picture.name] else {
            return "<figure><img alt=\"\(escaped(picture.alt))\" src=\"\(escaped(picture.name))\"></figure>"
        }
        return "<figure>\(stripped(svg))</figure>"
    }

    /// The SVG without its XML prologue, which a browser refuses inside a
    /// page.
    static func stripped(_ svg: String) -> String {
        var text = svg.trimmed()
        while text.hasPrefix("<?") || text.hasPrefix("<!") {
            guard let end = text.firstIndex(of: ">") else { break }
            text = String(text[text.index(after: end)...]).trimmed()
        }
        return text
    }

    static func tableHtml(_ rows: [String]) -> String {
        let bodyRows = rows.filter { row in
            row.contains(where: { $0 != "|" && $0 != "-" && $0 != " " && $0 != ":" })
        }
        guard let head = bodyRows.first else { return "" }

        var html = ["<table>", "<thead>", row(head, tag: "th"), "</thead>", "<tbody>"]
        for line in bodyRows.dropFirst() {
            html.append(row(line, tag: "td"))
        }
        html += ["</tbody>", "</table>"]
        return html.joined(separator: "\n")
    }

    static func row(_ line: String, tag: String) -> String {
        let cells = line
            .trimmed()
            .trimmingBoth("|")
            .components(separatedBy: "|")
            .map { "<\(tag)>\(inline($0.trimmed()))</\(tag)>" }
        return "<tr>" + cells.joined() + "</tr>"
    }

    /// What one line of text becomes: the markup escaped, then the report's
    /// own inline forms put back.
    static func inline(_ text: String) -> String {
        var built = escaped(text)
        built = links(built)
        built = wrapped(built, marker: "**", tag: "strong")
        built = wrapped(built, marker: "`", tag: "code")
        return built
    }

    /// `[text](target)` becomes an anchor. A target that is not http or https
    /// is written as text, so nothing in a report can open a scheme a reader
    /// did not expect.
    static func links(_ text: String) -> String {
        var built = ""
        var rest = Substring(text)

        while let open = rest.firstIndex(of: "["),
              let close = rest[open...].firstIndex(of: "]"),
              rest.index(after: close) < rest.endIndex,
              rest[rest.index(after: close)] == "(",
              let end = rest[close...].firstIndex(of: ")") {
            let label = String(rest[rest.index(after: open) ..< close])
            let target = String(rest[rest.index(close, offsetBy: 2) ..< end])

            built += rest[rest.startIndex ..< open]
            if target.hasPrefix("http://") || target.hasPrefix("https://") {
                built += "<a href=\"\(target)\">\(label)</a>"
            } else {
                built += "\(label) (\(target))"
            }
            rest = rest[rest.index(after: end)...]
        }

        return built + rest
    }

    /// Every pair of `marker` becomes one element. An odd marker is left as
    /// it was written.
    static func wrapped(_ text: String, marker: String, tag: String) -> String {
        let parts = text.components(separatedBy: marker)
        guard parts.count > 2 else { return text }

        var built = parts[0]
        var index = 1
        while index < parts.count {
            if index + 1 < parts.count || parts.count % 2 == 1 {
                built += "<\(tag)>\(parts[index])</\(tag)>"
            } else {
                built += marker + parts[index]
            }
            index += 1
            if index < parts.count {
                built += parts[index]
                index += 1
            }
        }
        return built
    }

    static func escaped(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }

    // MARK: the page

    /// The stylesheet is written into the page and sized for A4, so a reader
    /// who prints the page gets the report as a PDF with no other tool.
    public static let style = """
    @page { size: A4; margin: 16mm 14mm; }
    body { font: 10pt/1.45 -apple-system, 'Helvetica Neue', Arial, sans-serif;
           color: #16161a; background: #ffffff; margin: 0 auto; max-width: 190mm; padding: 12mm 8mm; }
    h1 { font-size: 22pt; margin: 0 0 8pt; }
    h2 { font-size: 15pt; margin: 22pt 0 6pt; padding-top: 6pt;
         border-top: 1px solid #d8d8de; page-break-after: avoid; }
    h3 { font-size: 11.5pt; margin: 14pt 0 4pt; page-break-after: avoid; }
    p, li { orphans: 3; widows: 3; }
    ul { margin: 4pt 0 8pt; padding-left: 16pt; }
    li { margin: 1pt 0; }
    .under { color: #55555f; }
    figure { margin: 8pt 0; page-break-inside: avoid; text-align: center; }
    figure svg, figure img { max-width: 100%; max-height: 210mm; height: auto;
                             border: 1px solid #e2e2e8; border-radius: 4px; }
    figure.whole svg { max-height: 240mm; }
    table { border-collapse: collapse; width: 100%; font-size: 8.5pt; margin: 6pt 0 12pt; }
    th, td { border: 1px solid #d8d8de; padding: 3pt 5pt; text-align: left; vertical-align: top; }
    th { background: #f4f4f7; font-weight: 600; }
    code { font: 9pt ui-monospace, Menlo, monospace; background: #f4f4f7; padding: 0 2px; }
    a { color: #2a4bd7; }
    @media print { body { max-width: none; padding: 0; } a { color: inherit; } }
    """

    static func page(title: String, body: String) -> String {
        """
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>\(escaped(title))</title>
        <style>
        \(style)
        </style>
        </head>
        <body>
        \(body)
        </body>
        </html>

        """
    }
}

extension String {
    func trimmed() -> String {
        var text = Substring(self)
        while let first = text.first, first == " " || first == "\t" || first == "\r" || first == "\n" {
            text = text.dropFirst()
        }
        while let last = text.last, last == " " || last == "\t" || last == "\r" || last == "\n" {
            text = text.dropLast()
        }
        return String(text)
    }

    /// The text without a leading and a trailing `character`.
    func trimmingBoth(_ character: Character) -> String {
        var text = Substring(self)
        if text.first == character { text = text.dropFirst() }
        if text.last == character { text = text.dropLast() }
        return String(text)
    }
}
