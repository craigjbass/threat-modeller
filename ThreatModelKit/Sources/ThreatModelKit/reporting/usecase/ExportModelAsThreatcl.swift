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
/// honours that shape rather than inventing one: a `spec_version`, one
/// `threatmodel` block, one `information_asset` block per component, and one
/// `threat` block per assessed threat.
public struct ExportModelAsThreatcl: ExportModelAsThreatclUseCase {
    /// The threatcl specification this output is written for.
    public static let specVersion = "0.1.6"

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
        lines.append("  author = \(HCL.string("threat-modeller"))")
        lines.append(
            "  description = "
                + HCL.string(
                    "\(report.summary.totalThreats) threats"
                        + " across \(report.components.count) components,"
                        + " assessed against threat catalogue"
                        + " \(report.catalogueTag ?? "unknown")."
                )
        )

        for component in report.components {
            lines.append("")
            lines.append("  information_asset \(HCL.string(component.name)) {")
            lines.append(
                "    description = "
                    + HCL.string("\(component.technologyId) in \(component.zoneName ?? "no zone")")
            )
            lines.append(
                "    information_classification = "
                    + HCL.string(component.sensitivityLabel)
            )
            lines.append("  }")
        }

        for connection in report.connections {
            lines.append("")
            lines.append(
                "  usecase {"
            )
            lines.append(
                "    description = "
                    + HCL.string("\(connection.sourceName) sends data to \(connection.targetName)")
            )
            lines.append("  }")
        }

        for threat in report.threats {
            lines.append("")
            lines.append("  threat {")
            lines.append(
                "    description = "
                    + HCL.string("\(threat.name) (\(threat.sourceName)): \(threat.description)")
            )
            lines.append("    impacts = \(HCL.list(threat.strideLabels))")
            lines.append("    stride = \(HCL.list(threat.strideLabels))")
            if threat.controls.isEmpty == false {
                lines.append(
                    "    control = "
                        + HCL.string(threat.controls.map(\.description).joined(separator: "; "))
                )
            }
            lines.append("  }")
        }

        lines.append("}")
        lines.append("")

        return ExportModelAsThreatclResponse(
            hcl: lines.joined(separator: "\n"),
            fileName: "\(FileNaming.stem(from: report.modelName)).hcl"
        )
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
