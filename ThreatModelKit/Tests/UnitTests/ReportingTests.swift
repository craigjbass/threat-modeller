import Testing
import ThreatModelKit
import TestSupport

@Suite("What a report says")
struct ReportingTests {
    private let app = TestDependencies()

    @discardableResult
    private func add(_ technologyId: String, sensitivity: String = "confidential") -> String {
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 100, y: 100, sensitivity: sensitivity)
        ) else {
            Issue.record("the component was not added")
            return ""
        }
        return componentId
    }

    private func report() -> Report {
        app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report
    }

    @Test func saysNothingAboutAnEmptyModel() {
        let report = report()

        #expect(report.components.isEmpty)
        #expect(report.connections.isEmpty)
        #expect(report.zones.isEmpty)
        #expect(report.threats.isEmpty)
        #expect(report.summary.totalThreats == 0)
    }

    @Test func namesTheCatalogueItWasAssessedAgainst() {
        #expect(report().catalogueTag?.isEmpty == false)
    }

    @Test func carriesTheComponentAndItsThreats() throws {
        add("aws-ec2")

        let report = report()

        let component = try #require(report.components.first)
        #expect(component.technologyId == "aws-ec2")
        #expect(component.sensitivityLabel.isEmpty == false)
        #expect(component.zoneName == nil)
        #expect(report.threats.isEmpty == false)
        let threat = try #require(report.threats.first)
        #expect(threat.sourceKind == "Component")
        #expect(threat.sourceName == component.name)
        // The assessment names STRIDE by id; a report names it by label.
        #expect(threat.strideLabels.allSatisfy { $0.first?.isUppercase == true })
    }

    @Test func saysWhichControlsAreRecorded() throws {
        add("aws-ec2")
        let key = try #require(report().threats.first?.controls.first).description
        let control = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest())
                .threats.first?.controls.first
        )
        _ = app.recordControlImplemented().execute(
            RecordControlImplementedRequest(controlKey: control.key)
        )

        let recorded = try #require(report().threats.first?.controls.first { $0.description == key })

        #expect(recorded.isImplemented)
        #expect(report().summary.controlsRecorded == 1)
    }

    @Test func namesTheZoneHoldingAComponent() throws {
        add("aws-ec2")
        _ = app.addZone().execute(
            AddZoneRequest(x: -100, y: -100, width: 800, height: 700)
        )

        let report = report()

        #expect(try #require(report.components.first).zoneName != nil)
        let zone = try #require(report.zones.first)
        #expect(zone.componentNames.count == 1)
        #expect(zone.riskReductionPercent != nil)
    }

    @Test func namesBothEndsOfAConnection() throws {
        let source = add("aws-ec2")
        let target = add("aws-rds")
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: source, targetComponentId: target)
        )

        let connection = try #require(report().connections.first)

        #expect(connection.sourceName.isEmpty == false)
        #expect(connection.targetName.isEmpty == false)
        #expect(connection.sourceName != connection.targetName)
    }

    @Test func namesAComponentsPrivilege() throws {
        let id = add("aws-ec2")
        _ = app.setComponentProperties().execute(
            SetComponentPropertiesRequest(
                componentId: id,
                name: nil,
                sensitivity: "internal",
                threatsDisabled: false,
                runsAs: "root"
            )
        )

        let component = try #require(report().components.first)

        #expect(component.privilegeLabel == "Root")
    }

    @Test func namesAConnectionsKindAndDescription() throws {
        let source = add("aws-ec2")
        let target = add("aws-rds")
        guard case .connected(let connectionId) = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: source, targetComponentId: target)
        ) else {
            Issue.record("the components were not connected")
            return
        }
        _ = app.setConnectionProperties().execute(
            SetConnectionPropertiesRequest(connectionId: connectionId, kind: "ipc", description: "XPC call")
        )

        let connection = try #require(report().connections.first)

        #expect(connection.kindLabel == "Local IPC")
        #expect(connection.description == "XPC call")
    }

    @Test func namesAZonesBoundary() throws {
        guard case .added(let zoneId) = app.addZone().execute(
            AddZoneRequest(x: -100, y: -100, width: 800, height: 700)
        ) else {
            Issue.record("the zone was not added")
            return
        }
        _ = app.setZoneProperties().execute(
            SetZonePropertiesRequest(
                zoneId: zoneId,
                name: nil,
                networkZone: "private",
                networkType: "generic",
                riskReductionEnabled: true,
                riskReductionPercent: 20,
                boundary: "privilege"
            )
        )

        let zone = try #require(report().zones.first)

        #expect(zone.boundaryLabel == "Privilege Boundary")
    }
}

@Suite("Writing a report as Markdown")
struct MarkdownExportTests {
    private let app = TestDependencies()

    private func markdown() -> String {
        app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown
    }

    @Test func opensWithTheModelName() {
        #expect(markdown().hasPrefix("# Untitled\n"))
    }

    @Test func namesTheFileAfterTheModel() {
        _ = app.renameThreatModel().execute(RenameThreatModelRequest(name: "Payments/Live"))

        let response = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest())

        // A slash is a path separator, so the name a save panel offers cannot
        // carry one.
        #expect(response.fileName == "Payments-Live.md")
    }

    @Test func saysSoWhenThereIsNothingToSay() {
        let markdown = markdown()

        #expect(markdown.contains("## Components\n\nNone."))
        #expect(markdown.contains("## Connections\n\nNone."))
        #expect(markdown.contains("## Zones\n\nNone."))
        #expect(markdown.contains("## Threats\n\nNone."))
    }

    @Test func writesTheComponentsAsATable() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        )

        let markdown = markdown()

        #expect(markdown.contains("| Name | Technology | Sensitivity | Privilege | Zone | Assets |"))
        #expect(markdown.contains("| --- | --- | --- | --- | --- | --- |"))
        #expect(markdown.contains("| EC2 | aws-ec2 | Restricted | User | \u{2014} |  |"))
    }

    @Test func writesEachComponentsAssetsInTheAssetsColumn() {
        let architecture = """
        system "Vault" {
          component "secrets" {
            technology = "aws-ec2"
            data       = "confidential"

            asset "ssh-keys" { data = "restricted" }
          }
        }
        """
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: architecture))

        let markdown = markdown()

        // The component states "confidential", but its "ssh-keys" asset
        // states "restricted". The score uses the higher of the two, so the
        // table names the sensitivity the score used, not the one declared.
        #expect(markdown.contains("| EC2 | aws-ec2 | Restricted | User | \u{2014} | ssh-keys |"))
    }

    @Test func writesEachConnectionsKindAndDescription() throws {
        let architecture = """
        system "Endpoint" {
          component "devtools" { technology = "aws-ec2" }
          component "secrets"  { technology = "aws-rds" }

          flow devtools -> secrets {
            kind        = "ipc"
            description = "XPC call to read a secret"
          }
        }
        """
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: architecture))

        let markdown = markdown()

        #expect(
            markdown.contains(
                "- EC2 \u{2192} RDS, by Local IPC: XPC call to read a secret"
            )
        )
    }

    @Test func writesAZonesBoundary() throws {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 100, y: 100, sensitivity: "internal")
        )
        guard case .added(let zoneId) = app.addZone().execute(
            AddZoneRequest(x: -100, y: -100, width: 800, height: 700)
        ) else {
            Issue.record("the zone was not added")
            return
        }
        _ = app.setZoneProperties().execute(
            SetZonePropertiesRequest(
                zoneId: zoneId,
                name: nil,
                networkZone: "private",
                networkType: "generic",
                riskReductionEnabled: true,
                riskReductionPercent: 20,
                boundary: "privilege"
            )
        )

        let markdown = markdown()

        #expect(markdown.contains("- Boundary: Privilege Boundary"))
    }

    @Test func writesAControlAsATickBox() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )

        let markdown = markdown()

        #expect(markdown.contains("Controls:"))
        #expect(markdown.contains("- [ ] "))
        #expect(markdown.contains("\u{2014} Not implemented"))
        #expect(markdown.contains("- [x] ") == false)
    }

    @Test func writesWhatCompensatedAThreatAndWhatItBought() throws {
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the component was not added")
            return
        }
        let threat = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats.first
        )
        app.modelStore.mutate { model in
            model.compensatingControls[
                ThreatKey(threatId: threat.threatId, sourceId: "component:\(componentId)")
            ] = [
                CompensatingControl(
                    label: "Watched by the SIEM",
                    reducesRiskBy: 50,
                    rationale: "It alerts on use."
                )
            ]
        }

        let markdown = markdown()

        #expect(markdown.contains("- Compensated by: Watched by the SIEM (50%,"))
        #expect(markdown.contains("  - Rationale: It alerts on use."))
    }

    @Test func writesWhatAMitigatesEdgeReduced() throws {
        guard case .added(let guardId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-waf", x: 0, y: 0, sensitivity: "internal")
        ), case .added(let storeId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 200, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the components were not added")
            return
        }
        app.modelStore.mutate { model in
            model.mitigatesEdges = [
                MitigatesEdge(
                    source: ComponentId(guardId),
                    target: ComponentId(storeId),
                    threatIds: [ThreatId("credential-theft")],
                    reducesRiskBy: 75
                )
            ]
        }

        let markdown = markdown()

        #expect(markdown.contains("- Reduced by: WAF"))
    }

    @Test func countsTheControlsByStatus() throws {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )
        let control = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats.first?.controls.first
        )
        _ = app.recordControlImplemented().execute(
            RecordControlImplementedRequest(controlKey: control.key)
        )

        let markdown = markdown()

        #expect(markdown.contains("- Controls implemented: 1"))
        #expect(markdown.contains("- Controls not implemented: "))
    }

    @Test func countsTheThreatsInTheSummary() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )

        let markdown = markdown()

        #expect(markdown.contains("## Summary"))
        #expect(markdown.contains("- Threats: "))
        #expect(markdown.contains("- Controls recorded: 0 of "))
    }
}

@Suite("Writing a report as threatcl HCL")
struct ThreatclExportTests {
    private let app = TestDependencies()

    private func hcl() -> String {
        app.exportModelAsThreatcl().execute(ExportModelAsThreatclRequest()).hcl
    }

    @Test func opensWithTheSpecVersionAndOneThreatModelBlock() {
        let hcl = hcl()

        #expect(hcl.hasPrefix("spec_version = \"0.1.6\"\n"))
        #expect(hcl.contains("threatmodel \"Untitled\" {"))
        #expect(hcl.hasSuffix("}\n"))
    }

    @Test func namesTheFileAfterTheModel() {
        #expect(
            app.exportModelAsThreatcl().execute(ExportModelAsThreatclRequest()).fileName
                == "Untitled.hcl"
        )
    }

    @Test func writesEachComponentAsAnInformationAsset() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        )

        let hcl = hcl()

        #expect(hcl.contains("  information_asset \"EC2\" {"))
        #expect(hcl.contains("    information_classification = \"Restricted\""))
    }

    @Test func writesEachThreatAsAThreatBlock() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )

        let hcl = hcl()

        #expect(hcl.contains("  threat {"))
        #expect(hcl.contains("    stride = ["))
        #expect(hcl.contains("    control = \""))
    }

    @Test func writesEachConnectionAsAUseCase() {
        guard case .added(let source) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        ), case .added(let target) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 400, y: 0, sensitivity: "internal")
        ) else {
            Issue.record("the components were not added")
            return
        }
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: source, targetComponentId: target)
        )

        #expect(hcl().contains("  usecase {"))
    }

    @Test func escapesWhatHclWouldReadAsSomethingElse() {
        _ = app.renameThreatModel().execute(
            RenameThreatModelRequest(name: "The \"${env}\" model \\ 1")
        )

        let hcl = hcl()

        #expect(hcl.contains("threatmodel \"The \\\"$${env}\\\" model \\\\ 1\" {"))
    }
}

@Suite("Saying what the picture should draw")
struct ImageExportTests {
    private let app = TestDependencies()

    private func area() -> ExportModelAsImageResponse {
        app.exportModelAsImage().execute(ExportModelAsImageRequest())
    }

    @Test func drawsASquareWhenThereIsNothingToDraw() {
        let area = area()

        #expect(area.isEmpty)
        #expect(area.width == 400)
        #expect(area.height == 400)
        #expect(area.fileName == "Untitled.png")
    }

    @Test func leavesAMarginAroundTheOneComponent() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 100, y: 200, sensitivity: "internal")
        )

        let area = area()

        #expect(area.isEmpty == false)
        #expect(area.x == 60)
        #expect(area.y == 160)
        // A node is 160 by 72, plus a 40 point margin on each side.
        #expect(area.width == 240)
        #expect(area.height == 152)
    }

    @Test func holdsEveryComponentAndEveryZone() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 600, y: 400, sensitivity: "internal")
        )
        _ = app.addZone().execute(AddZoneRequest(x: -200, y: -150, width: 300, height: 300))

        let area = area()

        #expect(area.x == -240)
        #expect(area.y == -190)
        // From the zone's left edge to the far node's right edge, plus a
        // 40 point margin on each side.
        #expect(area.width == 960 + 80)
        #expect(area.height == 622 + 80)
    }

    @Test func namesTheFileAfterTheModel() {
        _ = app.renameThreatModel().execute(RenameThreatModelRequest(name: "Payments"))

        #expect(area().fileName == "Payments.png")
    }
}

@Suite("Asking a renderer for the report as PDF")
struct PdfExportTests {
    private let app = TestDependencies()

    @Test func handsBackWhatTheRendererDrew() throws {
        _ = app.renameThreatModel().execute(RenameThreatModelRequest(name: "Payments"))

        let response = app.exportModelAsPdf().execute(ExportModelAsPdfRequest())

        guard case .exported(let bytes, let fileName) = response else {
            Issue.record("expected .exported, got \(response)")
            return
        }
        #expect(fileName == "Payments.pdf")
        #expect(String(decoding: bytes, as: UTF8.self).hasPrefix("%PDF-"))
        #expect(String(decoding: bytes, as: UTF8.self).contains("Payments"))
    }

    @Test func saysSoWhenTheRendererCannotDraw() {
        let export = ExportModelAsPdf(
            reports: app.buildThreatModelReport(),
            renderer: RefusingReportRenderer()
        )

        let response = export.execute(ExportModelAsPdfRequest())

        guard case .cannotRender(let reason) = response else {
            Issue.record("expected .cannotRender, got \(response)")
            return
        }
        #expect(reason.contains("cannotStartDocument"))
    }
}

private struct RefusingReportRenderer: ReportRenderer {
    func render(_ report: Report) throws -> [UInt8] {
        throw ReportRenderError.cannotStartDocument
    }
}
