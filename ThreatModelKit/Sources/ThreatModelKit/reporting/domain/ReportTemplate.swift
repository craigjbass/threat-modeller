/// A team's own shape for the report.
///
/// The design in `docs/superpowers/specs/2026-09-15-report-template-design.md`
/// decides the language: a Markdown file with `{{slot}}` lines and no logic.
/// A slot line is replaced by that section, whole; every other line is copied
/// out byte for byte.
public struct ReportTemplate: Equatable, Sendable {
    /// One piece of a template: a line a team wrote, or a slot to fill.
    public enum Piece: Equatable, Sendable {
        case text(String)
        case slot(Slot)
    }

    /// The sections a template may name.
    public enum Slot: String, CaseIterable, Equatable, Sendable {
        case systemName = "system_name"
        case catalogueTag = "catalogue_tag"
        case documentControl = "document_control"
        case executiveSummary = "executive_summary"
        case scope
        case dataInventory = "data_inventory"
        case thirdParties = "third_parties"
        case knownVulnerabilities = "known_vulnerabilities"
        case policy
        case riskOverTime = "risk_over_time"
        case whatChanged = "what_changed"
        case rollups
        case threatPictures = "threat_pictures"
        case methodology
        case findings
        case leverage
        case attackPaths = "attack_paths"
        case attackTrees = "attack_trees"
        case protectionDependencies = "protection_dependencies"
        case recommendations
        case acceptedRisks = "accepted_risks"
        case assumptions
        case threatActors = "threat_actors"
        case glossary
        case threatRegister = "threat_register"
        case modelInventory = "model_inventory"
        case attackPathsAppendix = "attack_paths_appendix"
        case diagrams

        public static var names: String {
            allCases.map(\.rawValue).joined(separator: ", ")
        }
    }

    /// What the front matter states about the page.
    public struct FrontMatter: Equatable, Sendable {
        /// A line at the top of every page of the HTML and the PDF, and the
        /// first line of the Markdown. Nil for no banner.
        public let banner: String?
        /// Whether the page opens with a cover.
        public let hasCover: Bool
        /// The cover's title. Nil means the system's name.
        public let coverTitle: String?
        public let coverSubtitle: String?

        public init(
            banner: String? = nil,
            hasCover: Bool = false,
            coverTitle: String? = nil,
            coverSubtitle: String? = nil
        ) {
            self.banner = banner
            self.hasCover = hasCover
            self.coverTitle = coverTitle
            self.coverSubtitle = coverSubtitle
        }

        /// The fields the front matter holds. Anything else is a diagnostic.
        public static let fieldNames = ["banner", "cover", "cover_title", "cover_subtitle"]
    }

    public let frontMatter: FrontMatter
    public let pieces: [Piece]

    public init(frontMatter: FrontMatter = FrontMatter(), pieces: [Piece]) {
        self.frontMatter = frontMatter
        self.pieces = pieces
    }

    /// The slots this template names, in the order it names them.
    public var slots: [Slot] {
        pieces.compactMap { piece in
            if case .slot(let slot) = piece { return slot }
            return nil
        }
    }

    /// Reads a template file. A fault names what is wrong and what would be
    /// right; a template with a fault renders nothing.
    public static func read(_ text: String) -> ReportTemplateRead {
        var diagnostics: [Diagnostic] = []
        var lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)

        var frontMatter = FrontMatter()
        if lines.first?.trimmedHere() == "---" {
            var banner: String?
            var hasCover = false
            var coverTitle: String?
            var coverSubtitle: String?
            var closed = false
            var index = 1

            while index < lines.count {
                let line = lines[index]
                index += 1
                if line.trimmedHere() == "---" {
                    closed = true
                    break
                }
                if line.trimmedHere().isEmpty { continue }
                guard let colon = line.firstIndex(of: ":") else {
                    diagnostics.append(
                        Diagnostic(
                            severity: .error,
                            line: index,
                            column: 1,
                            message: "the front matter holds \"\(line.trimmedHere())\", "
                                + "which is not a name and a value"
                        )
                    )
                    continue
                }
                let name = String(line[line.startIndex ..< colon]).trimmedHere()
                let value = String(line[line.index(after: colon)...]).trimmedHere()
                switch name {
                case "banner": banner = value.isEmpty ? nil : value
                case "cover": hasCover = value == "true"
                case "cover_title": coverTitle = value.isEmpty ? nil : value
                case "cover_subtitle": coverSubtitle = value.isEmpty ? nil : value
                default:
                    diagnostics.append(
                        Diagnostic(
                            severity: .error,
                            line: index,
                            column: 1,
                            message: "the front matter holds no \"\(name)\"; it holds "
                                + FrontMatter.fieldNames.joined(separator: ", ")
                        )
                    )
                }
            }

            guard closed else {
                diagnostics.append(
                    Diagnostic(
                        severity: .error,
                        line: 1,
                        column: 1,
                        message: "the front matter has no closing \"---\" line"
                    )
                )
                return ReportTemplateRead(template: nil, diagnostics: diagnostics)
            }
            frontMatter = FrontMatter(
                banner: banner,
                hasCover: hasCover,
                coverTitle: coverTitle,
                coverSubtitle: coverSubtitle
            )
            lines = Array(lines.dropFirst(index))
            // A blank line after the front matter belongs to the front
            // matter, so a template starting with a heading writes no gap
            // above it.
            if lines.first?.trimmedHere().isEmpty == true { lines.removeFirst() }
        }

        var pieces: [Piece] = []
        var named: Set<Slot> = []
        for (offset, line) in lines.enumerated() {
            guard let name = slotName(of: line) else {
                pieces.append(.text(line))
                continue
            }
            guard let slot = Slot(rawValue: name) else {
                diagnostics.append(
                    Diagnostic(
                        severity: .error,
                        line: offset + 1,
                        column: 1,
                        message: "there is no section \"\(name)\"; this report writes "
                            + Slot.names
                    )
                )
                continue
            }
            guard named.insert(slot).inserted else {
                diagnostics.append(
                    Diagnostic(
                        severity: .error,
                        line: offset + 1,
                        column: 1,
                        message: "the section \"\(name)\" is named twice; "
                            + "a report writes each section once"
                    )
                )
                continue
            }
            pieces.append(.slot(slot))
        }

        guard diagnostics.contains(where: { $0.severity == .error }) == false else {
            return ReportTemplateRead(template: nil, diagnostics: diagnostics)
        }
        return ReportTemplateRead(
            template: ReportTemplate(frontMatter: frontMatter, pieces: pieces),
            diagnostics: diagnostics
        )
    }

    /// The name a slot line holds, or nil for a line that is not a slot. A
    /// slot stands on a line of its own, so `{{findings}}` inside a sentence
    /// is a sentence.
    static func slotName(of line: String) -> String? {
        let trimmed = line.trimmedHere()
        guard trimmed.hasPrefix("{{"), trimmed.hasSuffix("}}"), trimmed.count > 4 else {
            return nil
        }
        let inner = String(trimmed.dropFirst(2).dropLast(2)).trimmedHere()
        guard inner.isEmpty == false,
              inner.contains("{") == false,
              inner.contains("}") == false else { return nil }
        return inner
    }
}

/// What a read produced: a template when it could, and every fault it found.
public struct ReportTemplateRead: Equatable, Sendable {
    public let template: ReportTemplate?
    public let diagnostics: [Diagnostic]

    public init(template: ReportTemplate?, diagnostics: [Diagnostic]) {
        self.template = template
        self.diagnostics = diagnostics
    }

    public var hasErrors: Bool {
        diagnostics.contains { $0.severity == .error }
    }
}

private extension String {
    func trimmedHere() -> String {
        var characters = Array(self)
        while characters.first?.isWhitespace == true { characters.removeFirst() }
        while characters.last?.isWhitespace == true { characters.removeLast() }
        return String(characters)
    }
}
