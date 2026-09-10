import AppKit
import CoreGraphics
import CoreText
import Foundation
import ThreatModelKit

/// Draws a report onto US Letter pages with Core Text.
///
/// Spec section 12: the page layout is checked by eye and is not unit tested.
/// What is tested is that the bytes are a PDF, that the page count is at least
/// one, and that the model's name is in the text.
nonisolated struct PDFReportRenderer: ReportRenderer {
    private static let pageSize = CGSize(width: 612, height: 792)
    private static let margin = 54.0

    func render(_ report: Report) throws -> [UInt8] {
        let text = Self.attributedText(for: report)
        let data = NSMutableData()

        guard let consumer = CGDataConsumer(data: data as CFMutableData) else {
            throw ReportRenderError.cannotStartDocument
        }
        var mediaBox = CGRect(origin: .zero, size: Self.pageSize)
        guard let context = CGContext(consumer: consumer, mediaBox: &mediaBox, nil) else {
            throw ReportRenderError.cannotStartDocument
        }

        let frameRect = CGRect(
            x: Self.margin,
            y: Self.margin,
            width: Self.pageSize.width - Self.margin * 2,
            height: Self.pageSize.height - Self.margin * 2
        )
        let path = CGPath(rect: frameRect, transform: nil)
        let framesetter = CTFramesetterCreateWithAttributedString(text)

        var start = 0
        repeat {
            context.beginPDFPage(nil)
            let frame = CTFramesetterCreateFrame(
                framesetter,
                CFRangeMake(start, 0),
                path,
                nil
            )
            CTFrameDraw(frame, context)
            context.endPDFPage()

            let drawn = CTFrameGetVisibleStringRange(frame)
            // A page that draws nothing would loop forever. One page with the
            // header on it is the least this can produce.
            guard drawn.length > 0 else { break }
            start += drawn.length
        } while start < text.length

        context.closePDF()
        return [UInt8](data as Data)
    }

    private static func attributedText(for report: Report) -> NSAttributedString {
        let text = NSMutableAttributedString()

        text.append(line(report.modelName, size: 22, weight: .bold, spacingAfter: 10))
        if let catalogueTag = report.catalogueTag {
            text.append(
                line(
                    "Assessed against threat catalogue \(catalogueTag).",
                    size: 10,
                    weight: .regular,
                    spacingAfter: 14
                )
            )
        }

        text.append(heading("Summary"))
        text.append(body("Threats: \(report.summary.totalThreats)"))
        text.append(
            body(
                "Controls recorded: \(report.summary.controlsRecorded)"
                    + " of \(report.summary.controlsOffered)"
            )
        )
        for level in report.summary.byLevel {
            text.append(body("\(level.label): \(level.count)"))
        }

        text.append(heading("Components"))
        if report.components.isEmpty {
            text.append(body("None."))
        }
        for component in report.components {
            text.append(
                body(
                    "\(component.name) \u{2014} \(component.technologyId),"
                        + " \(component.sensitivityLabel),"
                        + " \(component.zoneName ?? "no zone")"
                )
            )
        }

        text.append(heading("Connections"))
        if report.connections.isEmpty {
            text.append(body("None."))
        }
        for connection in report.connections {
            text.append(body("\(connection.sourceName) \u{2192} \(connection.targetName)"))
        }

        text.append(heading("Zones"))
        if report.zones.isEmpty {
            text.append(body("None."))
        }
        for zone in report.zones {
            text.append(
                body(
                    "\(zone.name) \u{2014} \(zone.networkZoneLabel),"
                        + " \(zone.networkTypeLabel)"
                )
            )
        }

        text.append(heading("Threats"))
        if report.threats.isEmpty {
            text.append(body("None."))
        }
        for threat in report.threats {
            text.append(
                line(
                    "\(threat.name) \u{2014} \(threat.sourceName)",
                    size: 12,
                    weight: .bold,
                    spacingAfter: 2
                )
            )
            text.append(body(threat.description))
            let scoreText = threat.inherentScore == threat.riskScore
                ? "\(threat.riskLevel) (\(threat.riskScore))"
                : "\(threat.riskLevel) (\(threat.riskScore)), before controls \(threat.inherentScore)"
            text.append(
                body(
                    "\(threat.sourceKind) \u{00B7} \(threat.severityLabel)"
                        + " \u{00B7} \(scoreText)"
                )
            )
            // A finding is worth printing even when the stage floored at 1
            // both before and after: the tier, the rationale and the
            // sources are the evidence this block exists to publish.
            if threat.likelihoodRationale != nil || threat.likelihoodLabel != Likelihood.commodity.label {
                let scoreChanged = threat.scoreBeforeLikelihood != threat.riskScore
                text.append(
                    body(
                        "Likelihood: \(threat.likelihoodLabel)"
                            + (scoreChanged
                                ? " (\(threat.scoreBeforeLikelihood) \u{2192} \(threat.riskScore))"
                                : "")
                    )
                )
                if let rationale = threat.likelihoodRationale {
                    text.append(body("  Rationale: \(rationale)"))
                }
                for source in threat.likelihoodSources {
                    text.append(body("  Source: \(source)"))
                }
            }
            if let decision = threat.severityDecision {
                text.append(body("Severity decided: \(decision.fromLabel) \u{2192} \(decision.toLabel)"))
                text.append(body("  Rationale: \(decision.rationale)"))
                for source in decision.sources {
                    text.append(body("  Source: \(source)"))
                }
            }
            if threat.scoreIfAssumptionsHold != threat.riskScore {
                text.append(body("If the assumptions hold: \(threat.scoreIfAssumptionsHold)"))
            }
            for compensating in threat.compensating {
                text.append(
                    body(
                        "Compensated by \(compensating.label)"
                            + " (\(compensating.reducesRiskBy)%,"
                            + " \(threat.scoreBeforeCompensation) \u{2192} \(threat.riskScore)):"
                            + " \(compensating.rationale)"
                    )
                )
                for source in compensating.sources {
                    text.append(body("  Source: \(source)"))
                }
            }
            for control in threat.controls {
                text.append(
                    body(
                        "\(control.isImplemented ? "\u{2713}" : "\u{25A1}") \(control.description)"
                            + " \u{2014} \(control.statusLabel)"
                    )
                )
            }
            text.append(body(""))
        }

        return text
    }

    private static func heading(_ title: String) -> NSAttributedString {
        line(title, size: 15, weight: .bold, spacingBefore: 12, spacingAfter: 4)
    }

    private static func body(_ content: String) -> NSAttributedString {
        line(content, size: 10, weight: .regular, spacingAfter: 3)
    }

    private static func line(
        _ content: String,
        size: CGFloat,
        weight: NSFont.Weight,
        spacingBefore: CGFloat = 0,
        spacingAfter: CGFloat = 0
    ) -> NSAttributedString {
        let paragraph = NSMutableParagraphStyle()
        paragraph.paragraphSpacingBefore = spacingBefore
        paragraph.paragraphSpacing = spacingAfter
        paragraph.lineBreakMode = .byWordWrapping

        return NSAttributedString(
            string: content + "\n",
            attributes: [
                .font: NSFont.systemFont(ofSize: size, weight: weight),
                .paragraphStyle: paragraph
            ]
        )
    }
}
