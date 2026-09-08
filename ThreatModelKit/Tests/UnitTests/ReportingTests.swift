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

        #expect(markdown.contains("| Name | Technology | Sensitivity | Zone |"))
        #expect(markdown.contains("| --- | --- | --- | --- |"))
        #expect(markdown.contains("| aws-ec2 | Restricted | \u{2014} |"))
    }

    @Test func writesAControlAsATickBox() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )

        let markdown = markdown()

        #expect(markdown.contains("Controls:"))
        #expect(markdown.contains("- [ ] "))
        #expect(markdown.contains("- [x] ") == false)
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
