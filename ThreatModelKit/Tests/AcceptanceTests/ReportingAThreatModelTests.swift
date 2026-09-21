import Testing
import ThreatModelKit
import TestSupport

/// Given a threat model with components, a link and a zone
/// When I export it
/// Then Markdown, threatcl and the picture all say the same thing about it
struct ReportingAThreatModelTests {
    private let app = TestDependencies()

    private func aModelWorthReporting() -> (source: String, target: String) {
        _ = app.renameThreatModel().execute(RenameThreatModelRequest(name: "Payments"))
        guard case .added(let source) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        ), case .added(let target) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 400, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the components were not added")
            return ("", "")
        }
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: source, targetComponentId: target)
        )
        _ = app.addZone().execute(AddZoneRequest(x: -100, y: -100, width: 900, height: 700))
        return (source, target)
    }

    @Test func writesEverythingTheSidebarShowsIntoTheReport() throws {
        _ = aModelWorthReporting()
        let assessment = app.assessThreatModel().execute(AssessThreatModelRequest())

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        #expect(report.modelName == "Payments")
        #expect(report.components.count == 2)
        #expect(report.connections.count == 1)
        #expect(report.zones.count == 1)
        // A report can never disagree with what the user saw on screen.
        #expect(report.threats.count == assessment.threats.count)
        #expect(report.threats.map(\.name) == assessment.threats.map(\.name))
        #expect(report.summary.totalThreats == assessment.threats.count)
    }

    @Test func rollsUpEveryKindOfThreatIntoTheZoneAndGivesEachTopRiskAReason() throws {
        _ = aModelWorthReporting()

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        #expect(report.threats.contains { $0.sourceKind == "Component" })
        #expect(report.threats.contains { $0.sourceKind == "Connection" })
        #expect(report.threats.contains { $0.sourceKind == "Zone" })

        let rollup = try #require(report.rollups.byZone.first)
        let counted = rollup.byLevel.reduce(0) { $0 + $1.count }
        #expect(counted == report.threats.count)

        for kind in ["Component", "Connection", "Zone"] {
            let threat = try #require(report.threats.first { $0.sourceKind == kind })
            let reasons = ReportExecutiveSummary.reasons(
                for: threat,
                components: report.components,
                connections: report.connections,
                zones: report.zones
            )
            #expect(reasons.isEmpty == false)
        }
    }

    @Test func writesTheSameModelAsMarkdown() {
        _ = aModelWorthReporting()

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest())

        #expect(markdown.fileName == "Payments.md")
        #expect(markdown.markdown.hasPrefix("# Payments\n"))
        #expect(markdown.markdown.contains("### Components"))
        #expect(markdown.markdown.contains("| EC2 | aws-ec2 | Live | Restricted |"))
        #expect(markdown.markdown.contains("EC2 \u{2192} RDS"))
        #expect(markdown.markdown.contains("### Zones"))
        #expect(markdown.markdown.contains("- Holds: EC2, RDS"))
        #expect(markdown.markdown.contains("## Appendix A \u{2014} Full threat register"))
    }

    @Test func writesTheSameModelAsThreatcl() {
        _ = aModelWorthReporting()

        let threatcl = app.exportModelAsThreatcl().execute(ExportModelAsThreatclRequest())

        #expect(threatcl.fileName == "Payments.hcl")
        #expect(threatcl.hcl.contains("threatmodel \"Payments\" {"))
        // The components are the diagram's own elements, and the flows join
        // them, the way the threatcl specification states them.
        #expect(threatcl.hcl.contains("      process \"EC2\" {"))
        #expect(threatcl.hcl.contains("      data_store \"RDS\" {"))
        #expect(threatcl.hcl.contains("      from = \"EC2\""))
        #expect(threatcl.hcl.contains("      to = \"RDS\""))
        #expect(threatcl.hcl.contains("  threat \""))
    }

    @Test func saysWhatThePictureShouldDraw() {
        _ = aModelWorthReporting()

        let area = app.exportModelAsImage().execute(ExportModelAsImageRequest())

        #expect(area.fileName == "Payments.png")
        #expect(area.isEmpty == false)
        // The zone is the widest thing on the model, so the picture holds it
        // with a margin on each side.
        #expect(area.x == -140)
        #expect(area.width == 900 + 80)
    }

    @Test func writesTheSectionsInTheOrderAReaderNeedsThem() throws {
        let (source, _) = aModelWorthReporting()
        // Recommendations write no heading with nothing to recommend, so this
        // check on the order needs one recommendation on the books.
        let threat = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats.first
        )
        app.modelStore.mutate { model in
            model.recommendations[
                ThreatKey(threatId: threat.threatId, sourceId: "component:\(source)")
            ] = [Recommendation(text: "Rotate the credential on a schedule.")]
        }

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        let order = [
            "## Executive summary",
            "## Methodology",
            "### Diagram legend",
            "## Findings",
            "## Attack paths",
            "## Recommendations",
            "## Glossary",
            "## Appendix A \u{2014} Full threat register",
            "## Appendix B \u{2014} Model inventory"
        ]
        var last = markdown.startIndex
        for heading in order {
            let found = try #require(
                markdown.range(of: heading, range: last..<markdown.endIndex),
                "the report has no \(heading) after the section before it"
            )
            last = found.upperBound
        }
    }

    @Test func writesNoSummaryBulletsAndKeepsTheControlCounts() {
        _ = aModelWorthReporting()

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("## Summary") == false)
        #expect(markdown.contains("- Controls recorded: "))
        #expect(markdown.contains("### Components"))
        #expect(markdown.contains("### Connections"))
        #expect(markdown.contains("### Zones"))
    }

    @Test func saysTheSameThingAfterTheFileIsSavedAndOpenedAgain() throws {
        _ = aModelWorthReporting()
        let before = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown
        guard case .saved(let data) = app.saveThreatModel().execute(SaveThreatModelRequest()) else {
            Issue.record("the model was not saved")
            return
        }

        let reopened = TestDependencies()
        _ = reopened.openThreatModel().execute(OpenThreatModelRequest(data: data))

        #expect(
            reopened.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown
                == before
        )
    }

    // MARK: issue #264 — the report states the numbers it already computes

    /// Acceptance criterion: a model with a tree that raises risk, a
    /// `mitigates` edge, a breached policy rule and two compensating
    /// controls. The report holds the tree percentage, the edge percentage,
    /// the breach text and both control dates.
    @Test func statesTheNumbersTheReportAlreadyComputes() throws {
        guard case .added(let serverId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        ), case .added(let databaseId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 400, y: 0, sensitivity: "restricted")
        ), case .added(let guardId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-waf", x: -400, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the components were not added")
            return
        }

        app.modelStore.mutate { model in
            model.attackTrees = [
                SourceAttackTree(
                    id: "read-every-record",
                    name: "Read every record",
                    raisesRiskBy: 40,
                    goal: SourceTreeTarget(
                        threatId: "misconfiguration", sourceKind: "component", sourceId: databaseId
                    ),
                    root: .step(SourceTreeStep(
                        target: SourceTreeTarget(
                            threatId: "credential-theft", sourceKind: "component", sourceId: serverId
                        )
                    ))
                )
            ]
            model.mitigatesEdges = [
                MitigatesEdge(
                    source: ComponentId(guardId),
                    target: ComponentId(serverId),
                    threatIds: [ThreatId("credential-theft")]
                )
            ]
            // The edge lowers a score through the control a person says it
            // implements, and that control states how much it takes off.
            let guarded = ControlIdentity.componentControl(
                componentId: ComponentId(serverId),
                threatId: ThreatId("credential-theft"),
                description: "Enforce IMDSv2 to block SSRF-based credential theft",
                isTechnologySpecific: true
            )
            model.controlStatuses[guarded] = .implemented
            model.controlMitigatedBy[guarded] = [
                ControlMitigation(edgeId: "\(guardId)->\(serverId)", reducesRiskBy: 50)
            ]
            model.compensatingControls[
                ThreatKey(threatId: "dos-attack", sourceId: "component:\(serverId)")
            ] = [
                CompensatingControl(
                    label: "Rate limiter",
                    reducesRiskBy: 10,
                    rationale: "a rate limiter throttles the flood",
                    proof: ControlProof(
                        evidence: .tested,
                        reference: "test-a",
                        verifiedOn: GovernanceDate(year: 2026, month: 1, day: 5)
                    )
                ),
                CompensatingControl(
                    label: "Autoscaling",
                    reducesRiskBy: 20,
                    rationale: "autoscaling absorbs the flood",
                    proof: ControlProof(
                        evidence: .audited,
                        reference: "test-b",
                        verifiedOn: GovernanceDate(year: 2026, month: 2, day: 10)
                    )
                )
            ]
            model.policy = PolicySource(maxOpenAtLevel: .low)
        }

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        // The tree percentage.
        let tree = try #require(report.attackTrees.first { $0.id == "read-every-record" })
        #expect(tree.raisesRiskBy == 40)

        // The edge percentage.
        let credentialTheft = try #require(
            report.threats.first {
                $0.threatId == "credential-theft" && $0.sourceId == "component:\(serverId)"
            }
        )
        let edgeIndex = try #require(credentialTheft.mitigatedByComponentLabels.firstIndex(of: "WAF"))
        #expect(credentialTheft.mitigatedByComponentReductions[edgeIndex] == 50)

        // The breach text.
        let policyRule = try #require(report.policy.first { $0.name == "max_open_at_level" })
        #expect(policyRule.holds == false)
        let breachText = try #require(policyRule.breaches.first { $0.contains("misconfiguration") })

        // Both control dates.
        let dosAttack = try #require(
            report.threats.first { $0.threatId == "dos-attack" && $0.sourceId == "component:\(serverId)" }
        )
        #expect(dosAttack.compensating.count == 2)
        let dates = dosAttack.compensating.compactMap(\.evidence)
        #expect(dates.contains { $0.contains("2026-01-05") })
        #expect(dates.contains { $0.contains("2026-02-10") })

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown
        #expect(markdown.contains("Raises the goal by 40% when every step is open."))
        #expect(markdown.contains("WAF (50%)"))
        #expect(markdown.contains(breachText))
        #expect(markdown.contains("verified 2026-01-05"))
        #expect(markdown.contains("verified 2026-02-10"))
    }
}
