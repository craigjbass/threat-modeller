import DiagramRendering
import Foundation
import ThreatModelKit

/// One line of a list, and the lines written under it.
struct ReportBullet: Equatable {
    let text: String
    /// The lines the report indents under this one: a note, a rationale, a
    /// source.
    var notes: [String] = []
}

/// A table of the report, drawn as a grid rather than as pipes.
struct ReportTable: Equatable {
    let columns: [String]
    let rows: [[String]]
}

/// One piece of a report section.
///
/// The stage draws a value, never Markdown and never HTML. A heading is the
/// report's own heading, so the stage and the file name the same sections.
enum ReportBlock: Equatable {
    /// A "##" heading of the report.
    case heading(String)
    /// A "###" heading of the report.
    case subheading(String)
    /// A bold line the report writes above a list.
    case lead(String)
    case paragraph(String)
    case bullets([ReportBullet])
    case numbered([ReportBullet])
    case table(ReportTable)
    /// A diagram a team wrote, in the language it wrote it in. The stage
    /// shows the text only for a kind it cannot draw.
    case fenced(kind: String, text: String)
    /// A picture the exporter drew, as the SVG the exporter writes.
    case picture(label: String, svg: String)
    /// The whole diagram, which the stage draws with the canvas rather than
    /// with an SVG, so it carries the mitigates marks and the status marks.
    case dataFlow
    /// What the stage says when nobody has sampled the history, with the
    /// action that samples it.
    case sampleHistory(String)
}

/// One section of the report, ready to draw.
struct ReportStageSection: Identifiable, Equatable {
    let slot: ReportTemplate.Slot
    /// What the left sidebar calls the section: its first report heading.
    let title: String
    let blocks: [ReportBlock]

    var id: String { slot.rawValue }
}

/// What the stage draws that is not text.
///
/// The pictures are the SVG the exporters write, so the stage and the file
/// cannot draw two different pictures.
struct ReportStagePictures: Equatable {
    /// The picture of each top residual threat, as SVG, keyed
    /// "<threat id>@<source id>".
    var threatPictures: [String: String] = [:]
    /// The picture of each control, as SVG, by the id of the component the
    /// protection comes from.
    var controlPictures: [String: String] = [:]
    /// The risk-over-time graph, as SVG, or nil when the history draws none.
    var riskOverTimeChart: String?
    /// What the model scored at each sampled commit, newest first.
    var history: [RiskHistoryRow] = []
    var historyTruncated = false
    /// What changed since the newest sampled commit, or nil.
    var change: RiskChange?

    static let none = ReportStagePictures()
}

/// The report as the stage draws it: the sections the template names, in the
/// order it names them.
///
/// The design is `docs/superpowers/specs/2026-09-16-report-stage-design.md`.
struct ReportStagePage: Equatable {
    /// The sections, in template order. A section the report has nothing for
    /// is left out, the way the file leaves it out.
    let sections: [ReportStageSection]
    /// The file the project renders through, or nil for the shape this
    /// application ships.
    var templatePath: String?
    /// What stops the report, one line each. Empty while the template reads.
    /// A page with a fault draws no sections, because the export writes no
    /// file either.
    var fault: [String] = []

    static let empty = ReportStagePage(sections: [])

    /// Builds one section per slot the template names.
    ///
    /// `pictures` carries the SVG the exporters write, so a section that holds
    /// a picture holds the exporter's own bytes.
    static func build(
        report: Report,
        template: ReportTemplate,
        pictures: ReportStagePictures = .none
    ) -> [ReportStageSection] {
        template.slots.compactMap { slot in
            let blocks = self.blocks(of: slot, in: report, pictures: pictures)
            guard blocks.isEmpty == false else { return nil }
            return ReportStageSection(
                slot: slot,
                title: title(of: slot, blocks: blocks, report: report),
                blocks: blocks
            )
        }
    }

    /// What the sidebar calls a section: the section's own first heading, or
    /// the slot's name for the two slots that write no heading.
    private static func title(
        of slot: ReportTemplate.Slot,
        blocks: [ReportBlock],
        report: Report
    ) -> String {
        for block in blocks {
            if case .heading(let heading) = block { return heading }
        }
        switch slot {
        case .systemName: return report.modelName
        case .catalogueTag: return "Catalogue"
        default: return slot.rawValue
        }
    }

    // MARK: one section per slot

    // swiftlint:disable:next cyclomatic_complexity
    private static func blocks(
        of slot: ReportTemplate.Slot,
        in report: Report,
        pictures: ReportStagePictures
    ) -> [ReportBlock] {
        switch slot {
        case .systemName: [.heading(report.modelName), .dataFlow]
        case .catalogueTag: catalogueTag(report)
        case .documentControl: documentControl(report.documentControl)
        case .executiveSummary: executiveSummary(report)
        case .scope: scope(report)
        case .dataInventory: dataInventory(report.dataInventory)
        case .thirdParties: thirdParties(report.thirdParties)
        case .knownVulnerabilities: knownVulnerabilities(report)
        case .policy: policy(report.policy)
        case .riskOverTime: riskOverTime(pictures)
        case .whatChanged: whatChanged(report.change ?? pictures.change, since: pictures.history.first?.commit)
        case .rollups: rollups(report)
        case .threatPictures: threatPictures(report, pictures: pictures.threatPictures)
        case .methodology: methodology(report.methodology)
        case .findings: findings(report)
        case .leverage: leverage(report.actions)
        case .attackPaths: attackPaths(report)
        case .attackTrees: attackTrees(report)
        case .protectionDependencies:
            protectionDependencies(report.protectionDependencies, pictures: pictures.controlPictures)
        case .recommendations: recommendations(report.recommendations)
        case .acceptedRisks: acceptedRisks(report.acceptedRisks)
        case .assumptions: assumptions(report)
        case .threatActors: threatActors(report.threatActors)
        case .glossary: glossary()
        case .threatRegister: threatRegister(report)
        case .modelInventory: modelInventory(report)
        case .attackPathsAppendix: attackPathsAppendix(report)
        case .diagrams: diagrams(report.diagrams)
        }
    }

    private static func catalogueTag(_ report: Report) -> [ReportBlock] {
        guard let tag = report.catalogueTag else { return [] }
        return [.paragraph("Assessed against threat catalogue \(tag).")]
    }

    private static func documentControl(_ control: DocumentControl) -> [ReportBlock] {
        guard control.statesSomething else { return [] }

        var blocks: [ReportBlock] = [.heading("Document control")]
        if let description = control.description {
            blocks.append(.paragraph(description))
        }

        var rows: [[String]] = [["System", control.systemName]]
        if let owner = control.owner { rows.append(["Owner", owner]) }
        if control.authors.isEmpty == false {
            rows.append(["Authors", control.authors.joined(separator: ", ")])
        }
        if let version = control.version { rows.append(["Version", version]) }
        if let created = control.created { rows.append(["Created", created]) }
        if let reviewed = control.reviewed { rows.append(["Reviewed", reviewed]) }
        if let catalogueTag = control.catalogueTag {
            rows.append(["Catalogue", catalogueTag])
        }
        for link in control.links { rows.append(["Link", link]) }
        for repository in control.repositories { rows.append(["Repository", repository]) }
        for attribute in control.attributes { rows.append([attribute.name, attribute.value]) }

        blocks.append(.table(ReportTable(columns: ["Field", "Value"], rows: rows)))
        return blocks
    }

    private static func executiveSummary(_ report: Report) -> [ReportBlock] {
        let summary = report.executiveSummary
        var blocks: [ReportBlock] = [.heading("Executive summary"), .paragraph(summary.verdict)]

        if summary.topRisks.isEmpty == false {
            blocks.append(.lead("Highest residual risk"))
            blocks.append(.numbered(summary.topRisks.map { threat in
                let level = RiskLevel(rawValue: threat.riskLevel)?.label ?? threat.riskLevel
                var notes: [String] = []
                if let element = report.components.first(where: { $0.name == threat.sourceName }) {
                    notes.append(
                        "The element holds \(element.sensitivityLabel) data"
                            + " and runs as \(element.privilegeLabel)."
                    )
                }
                if let raisedByTree = threat.raisedByTree {
                    notes.append("The tree \(raisedByTree) raises this threat.")
                }
                let key = ReportRecommendation.key(
                    threatId: threat.threatId,
                    sourceId: threat.sourceId
                )
                if summary.topRisksWithNoAction.contains(key) {
                    notes.append("No recommendation names this threat, so none is listed below.")
                }
                return ReportBullet(
                    text: "\(threat.name) \u{2014} \(threat.sourceName) \u{2014} \(level)"
                        + " (\(threat.riskScore) of \(ReportMethodology.highestScore)).",
                    notes: notes
                )
            }))
        }

        if summary.isReviewOverdue {
            blocks.append(.paragraph(
                "This model was last read again on \(summary.reviewedOn ?? "an unstated date"), "
                    + "more than \(DocumentControl.reviewIntervalDays) days ago."
            ))
        }

        if summary.acceptedRisksOverdue > 0 {
            blocks.append(.paragraph(
                summary.acceptedRisksOverdue == 1
                    ? "1 accepted risk is past its review date."
                    : "\(summary.acceptedRisksOverdue) accepted risks are past their review date."
            ))
        }

        if summary.unevidencedControls > 0 {
            blocks.append(.paragraph(
                "\(summary.unevidencedControls) of \(summary.implementedControls) implemented "
                    + "controls state no evidence."
            ))
        }

        blocks += doFirst(summary)

        blocks.append(.paragraph(
            "\(summary.unansweredCount) of \(summary.totalThreats) threats hold"
                + " no answered control and no compensating control."
        ))

        if summary.exclusionCount > 0 {
            blocks.append(.paragraph(
                summary.exclusionCount == 1
                    ? "This model states 1 exclusion, listed under Scope."
                    : "This model states \(summary.exclusionCount) exclusions, listed under Scope."
            ))
        }

        if summary.hardDependencyCount > 0 {
            blocks.append(.paragraph(
                summary.hardDependencyCount == 1
                    ? "This system stops when 1 third party stops."
                    : "This system stops when any of \(summary.hardDependencyCount) "
                        + "third parties stops."
            ))
        }

        if summary.openByImpact.isEmpty == false {
            blocks.append(.paragraph(
                "Those threats harm "
                    + summary.openByImpact
                        .map { "\($0.label.lowercased()) \($0.count)" }
                        .joined(separator: ", ")
                    + "."
            ))
        }
        return blocks
    }

    /// What the summary says to do first: the leverage actions when the model
    /// declares any, and the recommendations answering the worst threats
    /// otherwise.
    private static func doFirst(_ summary: ReportExecutiveSummary) -> [ReportBlock] {
        if summary.topLeverageActions.isEmpty == false {
            return [
                .lead("Do first"),
                .numbered(summary.topLeverageActions.map { action in
                    let threatWord = action.threatsMoved == 1 ? "threat" : "threats"
                    var second = "across \(action.threatsMoved) \(threatWord);"
                    second += action.worstBefore == action.worstAfter
                        ? " worst stays \(action.worstBefore)."
                        : " worst falls \(action.worstBefore) \u{2192} \(action.worstAfter)."
                    if let blocker = action.blockedBy {
                        second += " Blocked by \(blocker)."
                    }
                    return ReportBullet(
                        text: "\(action.text) \u{2014} removes \(action.removes)"
                            + " of \(action.totalResidual) residual points",
                        notes: [second]
                    )
                })
            ]
        }
        guard summary.topActions.isEmpty == false else { return [] }
        return [
            .lead("Do first"),
            .numbered(summary.topActions.map { action in
                ReportBullet(
                    text: "\(action.text) \u{2014} answers \(action.threatName)"
                        + " on \(action.sourceName)"
                        + " (\(action.riskScore) of \(ReportMethodology.highestScore))."
                )
            })
        ]
    }

    private static func scope(_ report: Report) -> [ReportBlock] {
        guard report.useCases.isEmpty == false
            || report.exclusions.isEmpty == false
            || report.users.isEmpty == false else { return [] }

        var blocks: [ReportBlock] = [.heading("Scope")]

        if report.useCases.isEmpty == false {
            blocks.append(.subheading("Use cases"))
            blocks.append(.bullets(report.useCases.map {
                ReportBullet(text: "\($0.label): \($0.text)")
            }))
        }
        if report.users.isEmpty == false {
            blocks.append(.subheading("Users"))
            blocks.append(.bullets(report.users.map {
                ReportBullet(text: MarkdownScope.line(for: $0))
            }))
        }
        if report.exclusions.isEmpty == false {
            blocks.append(.subheading("Exclusions"))
            blocks.append(.bullets(report.exclusions.map {
                ReportBullet(
                    text: "\($0.label): \($0.text)",
                    notes: ["Rationale: \($0.rationale)"]
                )
            }))
        }
        return blocks
    }

    private static func dataInventory(_ rows: [ReportAssetRow]) -> [ReportBlock] {
        guard rows.isEmpty == false else { return [] }

        var blocks: [ReportBlock] = [.heading("Data inventory")]
        blocks.append(.table(ReportTable(
            columns: ["Asset", "Classification", "Owner", "Held by", "Carried by", "Worst open threat"],
            rows: rows.map { row in
                let worst = row.worstOpenThreat.map { name in
                    row.worstOpenScore.map { "\(name) (\($0))" } ?? name
                }
                return [
                    row.name,
                    row.classificationLabel,
                    row.owner ?? "\u{2014}",
                    list(row.heldBy),
                    list(row.carriedBy),
                    worst ?? "None"
                ]
            }
        )))

        let described = rows.filter { $0.description.isEmpty == false }
        if described.isEmpty == false {
            blocks.append(.bullets(described.map {
                ReportBullet(text: "\($0.name): \($0.description)")
            }))
        }
        return blocks
    }

    /// One row per CVE per component, ordered by priority, under the sentence
    /// naming the thresholds the rows were ranked by.
    private static func knownVulnerabilities(_ report: Report) -> [ReportBlock] {
        let rows = report.knownVulnerabilities
        guard rows.isEmpty == false else { return [] }

        func number(_ value: Double?, digits: Int, held: Bool) -> String {
            guard held, let value else { return "\u{2014}" }
            return String(format: "%.\(digits)f", value)
        }

        return [
            .heading("Known vulnerabilities"),
            .paragraph(
                "The CVEs this system's components state, ranked by the CVE_Prioritizer rule with "
                    + "\(report.vulnerabilityThresholds.described). A known exploited vulnerability "
                    + "raises every threat on its component to Commodity."
            ),
            .table(ReportTable(
                columns: ["CVE", "Component", "Version", "CVSS", "EPSS", "KEV", "Priority"],
                rows: MarkdownKnownVulnerabilities.ordered(rows).map { row in
                    [
                        row.cveId,
                        row.componentName,
                        row.version.isEmpty ? "\u{2014}" : row.version,
                        number(row.cvss, digits: 1, held: row.isSynchronised),
                        number(row.epss, digits: 2, held: row.isSynchronised),
                        row.isSynchronised ? (row.isKnownExploited ? "Yes" : "No") : "\u{2014}",
                        row.priorityLabel ?? "not synchronised"
                    ]
                }
            ))
        ]
    }

    private static func thirdParties(_ parties: [ReportThirdParty]) -> [ReportBlock] {
        guard parties.isEmpty == false else { return [] }

        var blocks: [ReportBlock] = [.heading("Third parties")]
        blocks.append(.table(ReportTable(
            columns: ["Party", "Kind", "Paying", "Uptime", "Provides", "Assets", "Owner"],
            rows: parties.map { party in
                [
                    party.name,
                    party.kindLabel,
                    party.payingCustomer ? "Yes" : "No",
                    party.uptimeLabel,
                    list(party.provides),
                    list(party.assetNames),
                    party.owner ?? "\u{2014}"
                ]
            }
        )))

        let said = parties.filter {
            $0.description.isEmpty == false || $0.uptimeNotes.isEmpty == false
        }
        if said.isEmpty == false {
            blocks.append(.bullets(said.map { party in
                ReportBullet(
                    text: party.description.isEmpty
                        ? party.name
                        : "\(party.name): \(party.description)",
                    notes: party.uptimeNotes.isEmpty ? [] : ["Uptime: \(party.uptimeNotes)"]
                )
            }))
        }
        return blocks
    }

    private static func policy(_ rules: [ReportPolicyRule]) -> [ReportBlock] {
        guard rules.isEmpty == false else { return [] }

        return [
            .heading("Policy"),
            .paragraph("The rules this project enforces, and whether this system keeps them."),
            .table(ReportTable(
                columns: ["Rule", "Asks", "Holds"],
                rows: rules.map { rule in
                    let holds: String
                    if rule.breaches.isEmpty {
                        holds = "yes"
                    } else {
                        holds = rule.breaches.count == 1
                            ? "no \u{2014} 1 breach"
                            : "no \u{2014} \(rule.breaches.count) breaches"
                    }
                    return [rule.name, rule.asks, holds]
                }
            ))
        ]
    }

    private static func rollups(_ report: Report) -> [ReportBlock] {
        let tables = report.rollups
        let showsAssumed = report.assumedMitigations.isEmpty == false
        var blocks: [ReportBlock] = []

        if tables.bySourceKind.isEmpty == false {
            blocks.append(.heading("Where the risk sits"))
            blocks.append(.bullets(tables.bySourceKind.map {
                ReportBullet(text: "\($0.label): \($0.count)")
            }))
        }

        if tables.byZone.isEmpty == false {
            blocks.append(.heading("By zone"))
            blocks.append(.table(ReportTable(
                columns: showsAssumed
                    ? ["Zone", "Components", "Worst", "If assumed hold", "Levels"]
                    : ["Zone", "Components", "Worst", "Levels"],
                rows: tables.byZone.map { rollup in
                    let levels = rollup.byLevel
                        .map { "\($0.label) \($0.count)" }
                        .joined(separator: ", ")
                    let tail = [
                        "\(rollup.worstScore)",
                        levels.isEmpty ? "none" : levels
                    ]
                    guard showsAssumed else {
                        return [rollup.zoneName, "\(rollup.componentCount)"] + tail
                    }
                    return [
                        rollup.zoneName,
                        "\(rollup.componentCount)",
                        "\(rollup.worstScore)",
                        "\(rollup.worstScoreIfAssumptionsHold)",
                        levels.isEmpty ? "none" : levels
                    ]
                }
            )))
        }

        if tables.topResidual.isEmpty == false {
            blocks.append(.heading("Top residual risk"))
            blocks.append(.table(ReportTable(
                columns: showsAssumed
                    ? ["Threat", "Raised by", "Residual", "If assumed hold", "Before controls", "Level"]
                    : ["Threat", "Raised by", "Residual", "Before controls", "Level"],
                rows: tables.topResidual.map { threat in
                    guard showsAssumed else {
                        return [
                            threat.name,
                            threat.sourceName,
                            "\(threat.riskScore)",
                            "\(threat.inherentScore)",
                            threat.riskLevel
                        ]
                    }
                    return [
                        threat.name,
                        threat.sourceName,
                        "\(threat.riskScore)",
                        "\(threat.scoreIfAssumptionsHold)",
                        "\(threat.inherentScore)",
                        threat.riskLevel
                    ]
                }
            )))
        }
        return blocks
    }

    private static func methodology(_ methodology: ReportMethodology) -> [ReportBlock] {
        var blocks: [ReportBlock] = [
            .heading("Methodology"),
            .paragraph(
                "A threat's base score is its severity rank multiplied by the data"
                    + " sensitivity rank of what it puts at risk, from 1 to"
                    + " \(ReportMethodology.highestScore)."
            ),
            .table(ReportTable(
                columns: ["Level", "Lowest score", "Highest score"],
                rows: methodology.levelThresholds.map {
                    [$0.label, "\($0.lowest)", "\($0.highest)"]
                }
            )),
            .paragraph(
                "The stages run in this order, and each one takes the score the one before it left."
            ),
            .numbered(MarkdownMethodology.stages(methodology).map { ReportBullet(text: $0) }),
            .paragraph(
                "The project's risk tolerance is \(methodology.toleranceLabel)."
                    + " A likelihood finding answers a threat only when the threat"
                    + " sits at or below that level."
            ),
            .paragraph(
                "\"If the assumptions hold\" is the same arithmetic with every"
                    + " assumed mitigates edge counted as in place."
            )
        ]
        blocks.append(.subheading("Diagram legend"))
        blocks.append(.table(ReportTable(
            columns: ["Mark", "Meaning"],
            rows: MarkdownMethodology.legendRows.map { [$0.mark, $0.meaning] }
        )))
        return blocks
    }

    private static func findings(_ report: Report) -> [ReportBlock] {
        let cut = report.findings
        var blocks: [ReportBlock] = [.heading("Findings")]

        guard cut.above.isEmpty == false else {
            blocks.append(.paragraph(
                "No threat sits above the project's \(report.toleranceLabel) risk tolerance."
            ))
            return blocks
        }

        var opening = "Every threat above the project's \(report.toleranceLabel) risk tolerance."
        if cut.notShown > 0 {
            opening += " \(cut.notShown) more qualify and are in Appendix A."
        }
        blocks.append(.paragraph(opening))
        for threat in cut.above { blocks += stanza(threat) }
        return blocks
    }

    private static func leverage(_ actions: [ReportAction]) -> [ReportBlock] {
        guard actions.isEmpty == false else { return [] }

        var blocks: [ReportBlock] = [
            .heading("What removes the most risk"),
            .paragraph(
                "Each action is measured on its own against today's posture. Two"
                    + " actions that answer one threat do not remove the sum of"
                    + " their leverage: the stronger reduction wins, never the sum."
            ),
            .table(ReportTable(
                columns: ["Action", "Removes", "Threats moved", "Worst", "Blocked by"],
                rows: actions.map { action in
                    [
                        action.text,
                        action.removes == 0
                            ? "removes nothing at today's posture"
                            : "\(action.removes) of \(action.totalResidual)",
                        "\(action.threatsMoved)",
                        "\(action.worstBefore) \u{2192} \(action.worstAfter)",
                        action.blockedBy ?? "\u{2014}"
                    ]
                }
            ))
        ]

        let annotated = actions.filter {
            $0.note != nil || $0.sources.isEmpty == false || $0.governance != nil
        }
        if annotated.isEmpty == false {
            blocks.append(.bullets(annotated.map { action in
                var notes: [String] = []
                if let note = action.note { notes.append(note) }
                if let governance = action.governance { notes.append(governance) }
                notes += sourceNotes(action.sources)
                return ReportBullet(text: action.text, notes: notes)
            }))
        }
        return blocks
    }

    private static func attackPaths(_ report: Report) -> [ReportBlock] {
        var blocks: [ReportBlock] = [.heading("Attack paths")]

        guard report.attackPaths.isEmpty == false else {
            blocks.append(.paragraph("None."))
            return blocks
        }

        if report.attackPathPrefix.isEmpty == false {
            blocks.append(.paragraph(
                "Every path below starts at "
                    + report.attackPathPrefix.map(\.componentName).joined(separator: " \u{2192} ")
                    + "."
            ))
            blocks.append(.table(hops(report.attackPathPrefix)))
        }

        for (index, path) in report.attackPaths.enumerated() {
            var heading = "\(index + 1). "
                + path.hops.map(\.componentName).joined(separator: " \u{2192} ")
                + " \u{2014} worst \(path.worstScore)"
            if path.likelihoodLabel.isEmpty == false {
                heading += ", \(path.likelihoodLabel)"
            }
            blocks.append(.subheading(heading))
            blocks.append(.table(hops(path.hops)))
        }
        return blocks
    }

    private static func hops(_ hops: [ReportAttackPathHop]) -> ReportTable {
        ReportTable(
            columns: ["Hop", "Flow", "Worst threat", "Score", "Reduced by"],
            rows: hops.map { hop in
                [
                    hop.componentName,
                    hop.flowKindLabel ?? "\u{2014}",
                    hop.worstThreatName ?? "none",
                    "\(hop.riskScore)",
                    hop.reducedBy.isEmpty
                        ? "nothing reduces this hop"
                        : hop.reducedBy.joined(separator: ", ")
                ]
            }
        )
    }

    private static func attackPathsAppendix(_ report: Report) -> [ReportBlock] {
        let notListed = report.attackPathsNotListed
        let beyond = report.attackPathsBeyondAppendix
        guard notListed.isEmpty == false || beyond > 0 else { return [] }

        var blocks: [ReportBlock] = [.heading("Appendix C \u{2014} Attack paths not listed")]
        if notListed.isEmpty == false {
            blocks.append(.paragraph(
                "The trace found \(notListed.count) further paths. Each one scores"
                    + " at or below the paths above."
            ))
            blocks.append(.bullets(notListed.map {
                ReportBullet(
                    text: "\($0.startName) \u{2192} \($0.endName), worst \($0.worstScore)"
                )
            }))
        }
        if beyond > 0 {
            blocks.append(.paragraph(
                "The trace found \(beyond) further paths this report names nowhere."
            ))
        }
        return blocks
    }

    private static func attackTrees(_ report: Report) -> [ReportBlock] {
        let trees = report.attackTrees
        guard trees.isEmpty == false else { return [] }

        var blocks: [ReportBlock] = [.heading("Attack trees")]
        for tree in trees.sorted(by: { $0.score > $1.score }) {
            blocks.append(.subheading(treeHeading(tree)))
            if let description = tree.description {
                blocks.append(.paragraph(description))
            }
            blocks.append(.paragraph("Goal: \(tree.goalName) on \(tree.goalSourceName)."))
            if tree.sufficientControls.isEmpty == false {
                blocks.append(.lead("Sufficient controls"))
                blocks.append(.bullets(tree.sufficientControls.map {
                    ReportBullet(text: "\($0.description): \(MarkdownAttackTrees.said($0.state))")
                }))
            }
            blocks.append(.table(ReportTable(
                columns: ["Step", "Raised on", "State", "Closed by"],
                rows: tree.steps.map {
                    [$0.threatName, $0.sourceName, $0.state.rawValue, $0.closedBy ?? "\u{2014}"]
                }
            )))
        }
        blocks.append(.paragraph(
            "This model states \(count(trees.count, "tree"))."
                + " The walk found \(count(report.attackPathCount, "route"))."
        ))
        return blocks
    }

    private static func treeHeading(_ tree: BoundAttackTree) -> String {
        guard tree.isStale == false else { return "\(tree.name) \u{2014} no longer binds" }
        if let closedBy = tree.closedBy { return "\(tree.name) \u{2014} closed by \(closedBy)" }
        guard tree.isOpen else { return "\(tree.name) \u{2014} every route is closed" }
        return "\(tree.name) \u{2014} \(tree.scoreBefore) \u{2192} \(tree.score),"
            + " chain \(tree.chainPercentage)%"
    }

    private static func protectionDependencies(
        _ dependencies: [ReportProtectionDependency],
        pictures: [String: String] = [:]
    ) -> [ReportBlock] {
        guard dependencies.isEmpty == false else { return [] }

        var blocks: [ReportBlock] = [.heading("Protection dependencies")]
        for dependency in dependencies {
            blocks.append(.subheading(dependency.protectorName))
            if let svg = pictures[dependency.protectorId] {
                blocks.append(.picture(label: dependency.protectorName, svg: svg))
            }

            if dependency.protectsElements.isEmpty {
                blocks.append(.bullets(dependency.protects.map {
                    ReportBullet(text: "Answers: \($0)")
                }))
            } else {
                let threats = dependency.protectsElements.reduce(0) { $0 + $1.threats.count }
                let elements = dependency.protectsElements.count
                blocks.append(.paragraph(
                    "Answers \(threats) \(threats == 1 ? "threat" : "threats")"
                        + " on \(elements) \(elements == 1 ? "element" : "elements")."
                        + " Every risk below is what is left after this control."
                ))
                blocks.append(.table(ReportTable(
                    columns: ["Element", "Zone", "Threats answered, with the risk left"],
                    rows: dependency.protectsElements.map { element in
                        [
                            element.elementName,
                            element.zoneName ?? "\u{2014}",
                            element.threats
                                .map { "\($0.name) (\($0.riskLevel) \($0.riskScore))" }
                                .joined(separator: ", ")
                        ]
                    }
                )))
            }

            if dependency.unanswered.isEmpty {
                blocks.append(.bullets([
                    ReportBullet(text: "Nothing on this component is unanswered.")
                ]))
            } else {
                blocks.append(.bullets(dependency.unanswered.map { threat in
                    ReportBullet(
                        text: "Unanswered on this component: \(threat.name)"
                            + " (\(threat.riskLevel), \(threat.riskScore))"
                    )
                }))
            }
        }
        return blocks
    }

    private static func recommendations(
        _ recommendations: [ReportRecommendation]
    ) -> [ReportBlock] {
        guard recommendations.isEmpty == false else { return [] }

        return [
            .heading("Recommendations"),
            .bullets(recommendations.map { recommendation in
                var notes = [
                    "\(recommendation.threatName) on \(recommendation.sourceName),"
                        + " risk \(recommendation.riskScore)"
                ]
                if let note = recommendation.note { notes.append(note) }
                if let governance = recommendation.governance { notes.append(governance) }
                notes += sourceNotes(recommendation.sources)
                return ReportBullet(text: recommendation.text, notes: notes)
            })
        ]
    }

    private static func acceptedRisks(_ risks: [ReportAcceptedRisk]) -> [ReportBlock] {
        guard risks.isEmpty == false else { return [] }

        return [
            .heading("Accepted risks"),
            .paragraph(
                "Each row is a risk the organisation decided to carry. The score is the full "
                    + "score: accepting a risk lowers nothing."
            ),
            .table(ReportTable(
                columns: ["Threat", "Element", "Score", "Owner", "Accepted", "Review by", "Rationale"],
                rows: risks.map { risk in
                    let reviewBy = risk.reviewBy.map { risk.isOverdue ? "\($0) overdue" : $0 }
                    return [
                        risk.threatName,
                        risk.sourceName,
                        "\(risk.riskScore)",
                        cell(risk.owner),
                        cell(risk.acceptedOn),
                        cell(reviewBy),
                        cell(risk.rationale)
                    ]
                }
            ))
        ]
    }

    private static func assumptions(_ report: Report) -> [ReportBlock] {
        guard report.assumptions.isEmpty == false
            || report.assumedMitigations.isEmpty == false else { return [] }

        var blocks: [ReportBlock] = [.heading("Assumptions")]
        if report.assumptions.isEmpty == false {
            blocks.append(.bullets(report.assumptions.map { assumption in
                var text = "\(assumption.label): \(assumption.text)"
                if let owner = assumption.owner { text += " (\(owner))" }
                return ReportBullet(text: text)
            }))
        }
        if report.assumedMitigations.isEmpty == false {
            blocks.append(.subheading("Assumed mitigations"))
            blocks.append(.bullets(report.assumedMitigations.map { mitigation in
                ReportBullet(
                    text: "\(mitigation.protectorName) \u{2192} \(mitigation.protectedName),"
                        + " mitigates \(mitigation.threatIds.joined(separator: ", ")),"
                        + " \u{2212}\(mitigation.reducesRiskBy)%"
                )
            }))
        }
        return blocks
    }

    private static func threatActors(_ actors: [ReportThreatActor]) -> [ReportBlock] {
        guard actors.isEmpty == false else { return [] }

        return [
            .heading("Threat actors"),
            .paragraph(
                "This assessment is written against these adversaries. A threat no actor here "
                    + "performs keeps the catalogue's own likelihood."
            ),
            .table(ReportTable(
                columns: ["Actor", "Capability", "Intent", "Threats performed"],
                rows: actors.map { actor in
                    [
                        actor.name,
                        actor.capabilityLabel,
                        capitalised(actor.intent),
                        "\(actor.threatsPerformed)"
                    ]
                }
            ))
        ]
    }

    private static func glossary() -> [ReportBlock] {
        [
            .heading("Glossary"),
            .table(ReportTable(
                columns: ["Word", "What it means"],
                rows: MarkdownGlossary.entries.map { [$0.word, $0.meaning] }
            ))
        ]
    }

    private static func threatRegister(_ report: Report) -> [ReportBlock] {
        let summary = report.summary
        var counts = [
            ReportBullet(text: "Threats: \(summary.totalThreats)"),
            ReportBullet(
                text: "Controls recorded: \(summary.controlsRecorded)"
                    + " of \(summary.controlsOffered)"
            )
        ]
        for status in summary.byControlStatus {
            counts.append(
                ReportBullet(text: "Controls \(status.label.lowercased()): \(status.count)")
            )
        }
        for level in summary.byLevel {
            counts.append(ReportBullet(text: "\(level.label): \(level.count)"))
        }

        var blocks: [ReportBlock] = [
            .heading("Appendix A \u{2014} Full threat register"),
            .bullets(counts)
        ]
        guard report.threats.isEmpty == false else {
            blocks.append(.paragraph("None."))
            return blocks
        }
        for threat in report.threats { blocks += stanza(threat) }
        return blocks
    }

    private static func modelInventory(_ report: Report) -> [ReportBlock] {
        var blocks: [ReportBlock] = [.heading("Appendix B \u{2014} Model inventory")]

        blocks.append(.subheading("Components"))
        if report.components.isEmpty {
            blocks.append(.paragraph("None."))
        } else {
            blocks.append(.table(ReportTable(
                columns: ["Name", "Technology", "Status", "Sensitivity", "Privilege", "Zone", "Assets"],
                rows: report.components.map { component in
                    [
                        component.name,
                        component.technologyId,
                        component.statusLabel,
                        component.sensitivityLabel,
                        component.privilegeLabel,
                        component.zoneName ?? "\u{2014}",
                        component.assetNames.joined(separator: ", ")
                    ]
                }
            )))
        }

        blocks.append(.subheading("Connections"))
        if report.connections.isEmpty {
            blocks.append(.paragraph("None."))
        } else {
            blocks.append(.bullets(report.connections.map { connection in
                var text = "\(connection.sourceName) \u{2192} \(connection.targetName),"
                    + " by \(connection.kindLabel)"
                if let description = connection.description { text += ": \(description)" }
                return ReportBullet(text: text)
            }))
        }

        blocks.append(.subheading("Zones"))
        if report.zones.isEmpty {
            blocks.append(.paragraph("None."))
        } else {
            for zone in report.zones {
                blocks.append(.lead(zone.name))
                var notes = [
                    ReportBullet(text: "Network zone: \(zone.networkZoneLabel)"),
                    ReportBullet(text: "Network type: \(zone.networkTypeLabel)"),
                    ReportBullet(text: "Boundary: \(zone.boundaryLabel)")
                ]
                if let percent = zone.riskReductionPercent {
                    notes.append(ReportBullet(text: "Risk reduction: \(percent)%"))
                }
                notes.append(ReportBullet(
                    text: "Holds: "
                        + (zone.componentNames.isEmpty
                            ? "nothing"
                            : zone.componentNames.joined(separator: ", "))
                ))
                blocks.append(.bullets(notes))
            }
        }
        return blocks
    }

    /// What a diagram section shows: the label, the language and the text the
    /// team wrote. The window draws no Mermaid renderer, so the text is what a
    /// reader reads and copies.
    /// A diagram block, drawn where the window draws that kind.
    ///
    /// Mermaid is drawn. Every other kind, and mermaid this application does
    /// not read, keeps its text, with a line saying so, because a picture the
    /// window cannot draw says less than the text.
    private static func diagrams(_ diagrams: [ReportDiagram]) -> [ReportBlock] {
        guard diagrams.isEmpty == false else { return [] }

        var blocks: [ReportBlock] = [.heading("Diagrams")]
        for diagram in diagrams {
            blocks.append(.subheading(diagram.label))
            if diagram.kind.lowercased() == "mermaid",
               let drawing = MermaidDrawing.drawing(of: diagram.text) {
                blocks.append(.picture(label: diagram.label, svg: SvgWriter.svg(of: drawing)))
                continue
            }
            blocks.append(
                .paragraph(
                    diagram.kind.lowercased() == "mermaid"
                        ? "This window draws a mermaid flowchart. This diagram is not one,"
                            + " so the text is what it holds."
                        : "This window does not draw \(diagram.kind)."
                            + " The text is what it holds."
                )
            )
            blocks.append(.fenced(kind: diagram.kind, text: diagram.text))
        }
        return blocks
    }

    // MARK: the pictures and the history

    /// The report's Top residual risk in detail, the section
    /// `MarkdownThreatPictures` writes.
    private static func threatPictures(
        _ report: Report,
        pictures: [String: String]
    ) -> [ReportBlock] {
        let drawn = report.rollups.topResidual.filter {
            pictures[MarkdownThreatPictures.key(threatId: $0.threatId, sourceId: $0.sourceId)] != nil
        }
        guard drawn.isEmpty == false else { return [] }

        var blocks: [ReportBlock] = [.heading("Top residual risk in detail")]
        for threat in drawn {
            let key = MarkdownThreatPictures.key(
                threatId: threat.threatId,
                sourceId: threat.sourceId
            )
            guard let svg = pictures[key] else { continue }

            blocks.append(.subheading("\(threat.name) \u{2014} \(threat.sourceName)"))
            blocks.append(
                .picture(label: "\(threat.name) on \(threat.sourceName)", svg: svg)
            )
            blocks.append(
                .paragraph(
                    "Residual \(threat.riskScore) of \(threat.inherentScore) before controls."
                        + " Level \(threat.riskLevel)."
                )
            )

            let unanswered = threat.controls.filter { $0.isImplemented == false }
            if unanswered.isEmpty == false {
                blocks.append(.lead("Not answered by:"))
                blocks.append(
                    .bullets(unanswered.map { ReportBullet(text: $0.description) })
                )
            }
            if threat.mitigatedByComponentLabels.isEmpty == false {
                blocks.append(
                    .paragraph(
                        "Reduced by "
                            + threat.mitigatedByComponentLabels.joined(separator: ", ")
                            + "."
                    )
                )
            }
        }
        return blocks
    }

    /// The report's Risk over time section, drawn from the rows the Markdown
    /// writer reads. With fewer than two rows sampled it says so and offers
    /// the sampling action.
    private static func riskOverTime(_ pictures: ReportStagePictures) -> [ReportBlock] {
        var blocks: [ReportBlock] = [.heading("Risk over time")]
        guard pictures.history.count >= 2 else {
            blocks.append(
                .sampleHistory(
                    "No commit of this project is sampled yet. Sampling reads the git"
                        + " history and compiles the model once per commit."
                )
            )
            return blocks
        }

        if let chart = pictures.riskOverTimeChart {
            blocks.append(
                .picture(label: "Total residual risk at each sampled commit", svg: chart)
            )
        }
        blocks.append(
            .table(
                ReportTable(
                    columns: [
                        "Date", "Commit", "Author", "Total", "Worst",
                        "Threats", "Accepted", "Open trees", "Catalogue"
                    ],
                    rows: pictures.history.map { row in
                        guard let numbers = row.numbers else {
                            return [
                                MarkdownRiskOverTime.day(row.commit.date),
                                row.commit.shortHash,
                                row.commit.author,
                                "did not parse", "", "", "", "", ""
                            ]
                        }
                        return [
                            MarkdownRiskOverTime.day(row.commit.date),
                            row.commit.shortHash,
                            row.commit.author,
                            "\(numbers.totalScore)",
                            "\(numbers.worstScore)",
                            "\(numbers.threatCount)",
                            "\(numbers.acceptedRisks)",
                            "\(numbers.openAttackTrees)",
                            numbers.catalogueTag ?? "\u{2014}"
                        ]
                    }
                )
            )
        )
        if pictures.historyTruncated {
            blocks.append(
                .paragraph(
                    "This is the newest \(pictures.history.count) commits that touched a"
                        + " threat model file. The project holds more."
                )
            )
        }
        return blocks
    }

    /// The report's What changed section, from the same change the Markdown
    /// writer reads.
    private static func whatChanged(_ change: RiskChange?, since commit: SourceCommit?) -> [ReportBlock] {
        guard let change, let commit, change.isEmpty == false else { return [] }

        var blocks: [ReportBlock] = [.heading("What changed")]
        blocks.append(
            .paragraph(
                "Since \(commit.shortHash) on \(MarkdownRiskOverTime.day(commit.date))."
                    + " \(change.direction)"
            )
        )
        if let catalogueMoved = change.catalogueMoved {
            blocks.append(
                .paragraph(
                    "\(catalogueMoved). A score that moved with it is not a posture change."
                )
            )
        }

        for (heading, items) in [
            ("Threats raised", change.raised),
            ("Threats no longer raised", change.gone),
            ("Controls whose status changed", change.controlsChanged),
            ("Risks newly accepted", change.acceptedAdded),
            ("Review dates moved", change.reviewDatesMoved)
        ] where items.isEmpty == false {
            blocks.append(.lead(heading))
            blocks.append(.bullets(items.map { ReportBullet(text: $0) }))
        }

        if change.scoreDeltas.isEmpty == false {
            blocks.append(.lead("Score by element"))
            blocks.append(
                .table(
                    ReportTable(
                        columns: ["Element", "Then", "Now", "Change"],
                        rows: change.scoreDeltas.map { delta in
                            [
                                delta.name,
                                "\(delta.then)",
                                "\(delta.now)",
                                "\(delta.delta > 0 ? "+" : "")\(delta.delta)"
                            ]
                        }
                    )
                )
            )
        }
        return blocks
    }

    // MARK: one threat, written the way the report writes it

    private static func stanza(_ threat: ReportThreat) -> [ReportBlock] {
        var blocks: [ReportBlock] = [
            .subheading("\(threat.name) \u{2014} \(threat.sourceName)"),
            .paragraph(threat.description)
        ]

        var facts = [
            ReportBullet(text: "Raised by: \(threat.sourceKind)"),
            ReportBullet(text: "Severity: \(threat.severityLabel)")
        ]
        facts.append(ReportBullet(
            text: threat.inherentScore == threat.riskScore
                ? "Risk: \(threat.riskLevel) (\(threat.riskScore))"
                : "Risk: \(threat.riskLevel) (\(threat.riskScore)),"
                    + " before controls \(threat.inherentScore)"
        ))

        if threat.likelihoodRationale != nil
            || threat.likelihoodLabel != Likelihood.commodity.label {
            let scoreChanged = threat.scoreBeforeLikelihood != threat.riskScore
            let reason = threat.likelihoodRationale == nil ? ", \(threat.likelihoodReason)" : ""
            var notes: [String] = []
            if let rationale = threat.likelihoodRationale {
                notes.append("Rationale: \(rationale)")
            }
            notes += sourceNotes(threat.likelihoodSources)
            facts.append(ReportBullet(
                text: "Likelihood: \(threat.likelihoodLabel)\(reason)"
                    + (scoreChanged
                        ? " (\(threat.scoreBeforeLikelihood) \u{2192} \(threat.riskScore))"
                        : ""),
                notes: notes
            ))
        }

        if let decision = threat.severityDecision {
            facts.append(ReportBullet(
                text: "Severity decided: \(decision.fromLabel) \u{2192} \(decision.toLabel)",
                notes: ["Rationale: \(decision.rationale)"] + sourceNotes(decision.sources)
            ))
        }
        if let scoreBeforeTree = threat.scoreBeforeTree {
            facts.append(ReportBullet(text: "Before the attack tree: \(scoreBeforeTree)"))
        }
        if let raisedByTree = threat.raisedByTree {
            facts.append(ReportBullet(text: "Raised by the tree: \(raisedByTree)"))
        }
        if threat.scoreIfAssumptionsHold != threat.riskScore {
            facts.append(ReportBullet(
                text: "If the assumptions hold: \(threat.scoreIfAssumptionsHold)"
            ))
        }
        if threat.assetsAtRisk.isEmpty == false {
            facts.append(ReportBullet(
                text: "Assets at risk: \(threat.assetsAtRisk.joined(separator: ", "))"
            ))
        }
        if threat.impactLabels.isEmpty == false {
            facts.append(ReportBullet(
                text: "Impact: \(threat.impactLabels.joined(separator: ", "))"
            ))
        }
        if threat.strideLabels.isEmpty == false {
            facts.append(ReportBullet(
                text: "STRIDE: \(threat.strideLabels.joined(separator: ", "))"
            ))
        }
        if let overriddenBy = threat.overriddenBy {
            facts.append(ReportBullet(text: "Changed by the library: \(overriddenBy)"))
        }
        if threat.mitreTechniqueIds.isEmpty == false {
            let named = threat.mitreTechniqueIds.map { id -> String in
                guard let said = threat.mitreTechniqueNames[id] else { return id }
                return "\(id) \(said)"
            }
            facts.append(ReportBullet(
                text: "MITRE ATT&CK: \(named.joined(separator: ", "))"
            ))
        }
        if threat.performedByLabels.isEmpty == false {
            facts.append(ReportBullet(
                text: "Performed by: \(threat.performedByLabels.joined(separator: ", "))"
            ))
        }
        for compensating in threat.compensating {
            facts.append(ReportBullet(
                text: "Compensated by: \(compensating.label)"
                    + " (\(compensating.reducesRiskBy)%,"
                    + " \(threat.scoreBeforeCompensation) \u{2192} \(threat.riskScore))"
                    + (compensating.evidence.map { ", \($0)" } ?? ""),
                notes: ["Rationale: \(compensating.rationale)"]
                    + sourceNotes(compensating.sources)
            ))
        }
        if threat.pathwayMitigationLabels.isEmpty == false {
            facts.append(ReportBullet(
                text: "Answered upstream by: "
                    + threat.pathwayMitigationLabels.joined(separator: ", ")
            ))
        }
        if threat.mitigatedByComponentLabels.isEmpty == false {
            facts.append(ReportBullet(
                text: "Reduced by: "
                    + threat.mitigatedByComponentLabels.joined(separator: ", ")
            ))
        }
        blocks.append(.bullets(facts))

        if threat.controls.isEmpty == false {
            blocks.append(.lead("Controls"))
            blocks.append(.bullets(threat.controls.map { control in
                ReportBullet(
                    text: "\(control.isImplemented ? "\u{2611}" : "\u{2610}") \(control.description)"
                        + " \u{2014} \(control.statusLabel)"
                        + (control.evidence.map { " \u{2014} \($0)" } ?? "")
                )
            }))
        }
        return blocks
    }

    // MARK: the small shapes every section shares

    private static func sourceNotes(_ sources: [String]) -> [String] {
        sources.map { "Source: \($0)" }
    }

    private static func list(_ names: [String]) -> String {
        names.isEmpty ? "\u{2014}" : names.joined(separator: ", ")
    }

    private static func cell(_ text: String?) -> String {
        guard let text, text.isEmpty == false else { return "\u{2014}" }
        return text
    }

    private static func count(_ number: Int, _ word: String) -> String {
        "\(number) \(word)\(number == 1 ? "" : "s")"
    }

    private static func capitalised(_ text: String) -> String {
        guard let first = text.first else { return text }
        return first.uppercased() + text.dropFirst()
    }
}
