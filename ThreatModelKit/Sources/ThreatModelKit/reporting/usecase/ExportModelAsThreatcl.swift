public protocol ExportModelAsThreatclUseCase {
    func execute(_ request: ExportModelAsThreatclRequest) -> ExportModelAsThreatclResponse
}

public struct ExportModelAsThreatclRequest: Equatable, Sendable {
    public init() {}
}

public struct ExportModelAsThreatclResponse: Equatable, Sendable {
    public let hcl: String
    public let fileName: String

    public init(hcl: String, fileName: String) {
        self.hcl = hcl
        self.fileName = fileName
    }
}

/// Writes the report as threatcl HCL.
///
/// threatcl is a third-party format with its own shape, so this application
/// honours that shape rather than inventing one. The blocks and the words are
/// the ones `spec.hcl` of the release named in `specVersion` states: one
/// `threatmodel`, an `information_asset` per named asset, a `usecase` per use
/// case, an `exclusion` per exclusion and per assumption, a
/// `third_party_dependency` per party, a labelled `threat` per assessed
/// threat with its `risk` and its `control` blocks, and one
/// `data_flow_diagram_v2` holding the trust zones, the elements and the
/// flows.
public struct ExportModelAsThreatcl: ExportModelAsThreatclUseCase {
    /// The threatcl specification this output is written for. The release is
    /// named in the README beside it.
    public static let specVersion = "0.8.1"

    private let reports: BuildThreatModelReportUseCase

    public init(reports: BuildThreatModelReportUseCase) {
        self.reports = reports
    }

    public func execute(_ request: ExportModelAsThreatclRequest) -> ExportModelAsThreatclResponse {
        let report = reports.execute(BuildThreatModelReportRequest()).report
        var lines: [String] = []

        lines.append("spec_version = \(HCL.string(Self.specVersion))")
        lines.append("")
        lines.append("threatmodel \(HCL.string(report.modelName)) {")
        // The author is required. The model's own authors when it names any,
        // and its owner when it does not.
        let authors = report.documentControl.authors
        lines.append(
            "  author = "
                + HCL.string(
                    authors.isEmpty
                        ? (report.documentControl.owner ?? "unstated")
                        : authors.joined(separator: ", ")
                )
        )
        lines.append(
            "  description = "
                + HCL.string(
                    report.documentControl.description?.isEmpty == false
                        ? report.documentControl.description ?? ""
                        : "\(report.summary.totalThreats) threats"
                            + " across \(report.components.count) components,"
                            + " assessed against threat catalogue"
                            + " \(report.catalogueTag ?? "unknown")."
                )
        )
        if let link = report.documentControl.links.first {
            lines.append("  link = \(HCL.string(link))")
        }
        if report.documentControl.repositories.isEmpty == false {
            lines.append("  repository = \(HCL.list(report.documentControl.repositories))")
        }

        // An information_asset name is what a threat's information_asset_refs
        // names, so both read the same word.
        for asset in report.dataInventory {
            lines.append("")
            lines.append("  information_asset \(HCL.string(asset.name)) {")
            if asset.description.isEmpty == false {
                lines.append("    description = \(HCL.string(asset.description))")
            }
            lines.append(
                "    information_classification = "
                    + HCL.string(Self.classification(of: asset.classificationLabel))
            )
            lines.append("  }")
        }

        for useCase in report.useCases {
            lines.append("")
            lines.append("  usecase {")
            lines.append("    description = \(HCL.string("\(useCase.label): \(useCase.text)"))")
            lines.append("  }")
        }

        // threatcl states one kind of exclusion, and this model states two
        // things that are excluded from the assessment: what the model does
        // not cover, and what it takes on trust without checking.
        for exclusion in report.exclusions {
            lines.append("")
            lines.append("  exclusion {")
            lines.append(
                "    description = "
                    + HCL.string("\(exclusion.label): \(exclusion.text) \(exclusion.rationale)")
            )
            lines.append("  }")
        }
        for assumption in report.assumptions {
            lines.append("")
            lines.append("  exclusion {")
            lines.append(
                "    description = "
                    + HCL.string("Assumed: \(assumption.label): \(assumption.text)")
            )
            lines.append("  }")
        }

        for party in report.thirdParties {
            lines.append("")
            lines.append("  third_party_dependency \(HCL.string(party.name)) {")
            lines.append(
                "    description = "
                    + HCL.string(
                        party.description.isEmpty
                            ? "\(party.name) provides \(party.provides.joined(separator: ", "))"
                            : party.description
                    )
            )
            lines.append("    saas = \(HCL.string(party.kindLabel == "SaaS" ? "true" : "false"))")
            lines.append(
                "    open_source = "
                    + HCL.string(party.kindLabel == "Open source" ? "true" : "false")
            )
            lines.append(
                "    infrastructure = "
                    + HCL.string(party.kindLabel == "Infrastructure" ? "true" : "false")
            )
            lines.append(
                "    paying_customer = \(HCL.string(party.payingCustomer ? "true" : "false"))"
            )
            lines.append(
                "    uptime_dependency = \(HCL.string(party.uptimeLabel.lowercased()))"
            )
            if party.uptimeNotes.isEmpty == false {
                lines.append("    uptime_notes = \(HCL.string(party.uptimeNotes))")
            }
            lines.append("  }")
        }

        // A threat's label must be unique in the file, and this model raises
        // one threat on many elements, so the label names both.
        var used: Set<String> = []
        for threat in report.threats {
            var label = "\(threat.name) on \(threat.sourceName)"
            if used.insert(label).inserted == false {
                label = "\(label) (\(threat.sourceId))"
                _ = used.insert(label)
            }

            lines.append("")
            lines.append("  threat \(HCL.string(label)) {")
            lines.append("    description = \(HCL.string(threat.description))")
            if threat.impactLabels.isEmpty == false {
                lines.append("    impacts = \(HCL.list(threat.impactLabels))")
            }
            let stride = threat.strideLabels.map(Self.stride(of:))
            if stride.isEmpty == false {
                lines.append("    stride = \(HCL.list(stride))")
            }
            if threat.assetsAtRisk.isEmpty == false {
                lines.append("    information_asset_refs = \(HCL.list(threat.assetsAtRisk))")
            }

            lines.append("")
            lines.append("    risk {")
            lines.append(
                "      likelihood = \(HCL.string(Self.likelihood(of: threat.likelihoodLabel)))"
            )
            lines.append("      impact = \(HCL.string(Self.impact(of: threat.severityLabel)))")
            lines.append("      severity = \(HCL.string(Self.severity(of: threat.riskLevel)))")
            lines.append(
                "      rationale = "
                    + HCL.string(
                        threat.likelihoodRationale
                            ?? "Residual \(threat.riskScore) of \(threat.inherentScore) "
                                + "before controls, on \(threat.sourceName)."
                    )
            )
            lines.append("    }")

            for control in threat.controls {
                lines.append("")
                lines.append("    control \(HCL.string(control.description)) {")
                lines.append("      description = \(HCL.string(control.description))")
                lines.append("      implemented = \(control.isImplemented)")
                if let evidence = control.evidence {
                    lines.append("      implementation_notes = \(HCL.string(evidence))")
                }
                lines.append(
                    "      risk_reduction = \(Self.riskReduction(of: control.statusLabel))"
                )
                lines.append("    }")
            }

            for compensating in threat.compensating {
                lines.append("")
                lines.append("    control \(HCL.string(compensating.label)) {")
                lines.append("      description = \(HCL.string(compensating.rationale))")
                lines.append("      implemented = true")
                lines.append("      risk_reduction = \(compensating.reducesRiskBy)")
                lines.append("    }")
            }

            lines.append("  }")
        }

        lines += diagram(of: report)

        for diagram in report.diagrams where diagram.kind == "mermaid" {
            lines.append("")
            lines.append("  mermaid \(HCL.string(diagram.label)) {")
            lines.append("    content = <<-EOT")
            lines += diagram.text
                .split(separator: "\n", omittingEmptySubsequences: false)
                .map { "      " + $0 }
            if diagram.text.hasSuffix("\n") { lines.removeLast() }
            lines.append("    EOT")
            lines.append("  }")
        }

        lines.append("}")
        lines.append("")

        return ExportModelAsThreatclResponse(
            hcl: lines.joined(separator: "\n"),
            fileName: "\(FileNaming.stem(from: report.modelName)).hcl"
        )
    }

    /// The one `data_flow_diagram_v2`: the trust zones, the elements each
    /// zone holds, the elements outside every zone, and the flows.
    private func diagram(of report: Report) -> [String] {
        guard report.components.isEmpty == false else { return [] }

        var lines = ["", "  data_flow_diagram_v2 \(HCL.string("\(report.modelName) DFD")) {"]

        for zone in report.zones {
            let held = report.components.filter { zone.componentIds.contains($0.id) }
            guard held.isEmpty == false else { continue }
            lines.append("")
            lines.append("    trust_zone \(HCL.string(zone.name)) {")
            for component in held {
                lines.append("      \(Self.element(of: component)) \(HCL.string(component.name)) {")
                // threatcl states an information_asset on a data store, and
                // the inventory says which store holds which asset.
                if Self.element(of: component) == "data_store",
                   let asset = Self.asset(held: component, in: report) {
                    lines.append("        information_asset = \(HCL.string(asset))")
                }
                lines.append("      }")
            }
            lines.append("    }")
        }

        let loose = report.components.filter { component in
            report.zones.contains { $0.componentIds.contains(component.id) } == false
        }
        if loose.isEmpty == false { lines.append("") }
        for component in loose {
            lines.append("    \(Self.element(of: component)) \(HCL.string(component.name)) {")
            if Self.element(of: component) == "data_store",
               let asset = Self.asset(held: component, in: report) {
                lines.append("      information_asset = \(HCL.string(asset))")
            }
            lines.append("    }")
        }

        for connection in report.connections {
            lines.append("")
            lines.append("    flow \(HCL.string(connection.kindLabel)) {")
            lines.append("      from = \(HCL.string(connection.sourceName))")
            lines.append("      to = \(HCL.string(connection.targetName))")
            lines.append("      protocol = \(HCL.string(connection.kindLabel))")
            lines.append("    }")
        }

        lines.append("  }")
        return lines
    }

    /// The first named asset this component holds, or nil when it holds
    /// none. A data store states one, and threatcl reads it.
    static func asset(held component: ReportComponent, in report: Report) -> String? {
        if let own = component.assetNames.first { return own }
        return report.dataInventory.first { $0.heldBy.contains(component.name) }?.name
    }

    /// What kind of element threatcl draws this component as. An actor is
    /// outside the system, a store holds data, and everything else runs.
    static func element(of component: ReportComponent) -> String {
        switch component.shapeId {
        case "actor": "external_element"
        case "store": "data_store"
        default: "process"
        }
    }

    /// threatcl holds three classifications. A project's own scheme may hold
    /// more, so anything at or above `Confidential` that is not `Restricted`
    /// travels as `Confidential`, and only `Public` travels as public.
    static func classification(of label: String) -> String {
        switch label.lowercased() {
        case "public": "Public"
        case "restricted": "Restricted"
        default: "Confidential"
        }
    }

    /// threatcl states STRIDE in its own words.
    static func stride(of label: String) -> String {
        switch label.lowercased() {
        case "spoofing": "Spoofing"
        case "tampering": "Tampering"
        case "repudiation": "Repudiation"
        case "information disclosure": "Info Disclosure"
        case "denial of service": "Denial Of Service"
        case "elevation of privilege": "Elevation Of Privilege"
        default: label
        }
    }

    /// A likelihood tier, in threatcl's five words. A commodity attack is one
    /// anybody can run, so it is the likeliest; research is the least likely.
    static func likelihood(of label: String) -> String {
        switch label.lowercased() {
        case "commodity": "high"
        case "targeted": "medium"
        case "research": "low"
        default: "medium"
        }
    }

    /// The severity a threat carries, as threatcl's impact.
    static func impact(of severityLabel: String) -> String {
        switch severityLabel.lowercased() {
        case "critical": "very_high"
        case "high": "high"
        case "medium": "medium"
        case "low": "low"
        default: "very_low"
        }
    }

    /// The risk level, in threatcl's five words.
    static func severity(of riskLevel: String) -> String {
        switch riskLevel.lowercased() {
        case "critical": "critical"
        case "high": "high"
        case "medium": "medium"
        case "low": "low"
        default: "info"
        }
    }

    /// What a control takes off the risk, from the answer a person wrote. An
    /// implemented control takes the whole risk in threatcl's terms; one
    /// nobody has answered takes none.
    static func riskReduction(of statusLabel: String) -> Int {
        switch statusLabel.lowercased() {
        case "implemented": 100
        case "accepted", "not applicable": 0
        default: 0
        }
    }
}

/// HCL quotes strings the way JSON does, and interpolates on `${`. Both are
/// escaped here, because a threat description is catalogue text this
/// application does not control.
enum HCL {
    static func string(_ text: String) -> String {
        var result = "\""
        var previous: Character?
        for character in text {
            switch character {
            case "\"":
                result.append("\\\"")
            case "\\":
                result.append("\\\\")
            case "\n":
                result.append("\\n")
            case "\t":
                result.append("\\t")
            case "{" where previous == "$":
                // `${` starts an interpolation, and `$${` is the literal.
                result.append("${")
            default:
                result.append(character)
            }
            previous = character
        }
        return result + "\""
    }

    static func list(_ values: [String]) -> String {
        "[" + values.map(string).joined(separator: ", ") + "]"
    }
}
