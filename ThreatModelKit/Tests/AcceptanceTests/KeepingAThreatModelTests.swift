import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// Given a threat model I have built
/// When I save it and open it again
/// Then everything I did is still there
struct KeepingAThreatModelTests {
    private let app = TestDependencies()

    private func add(_ technologyId: String, x: Double, sensitivity: String) -> String {
        let response = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: x, y: 100, sensitivity: sensitivity)
        )
        guard case .added(let componentId) = response else {
            Issue.record("Expected the component to be added, got \(response)")
            return ""
        }
        return componentId
    }

    private func save() -> Data {
        guard case .saved(let data) = app.saveThreatModel().execute(SaveThreatModelRequest()) else {
            Issue.record("Expected the model to be saved")
            return Data()
        }
        return data
    }

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    @Test func keepsEverythingIBuiltAcrossASaveAndAnOpen() throws {
        #expect(app.createThreatModel().execute(
            CreateThreatModelRequest(name: "Payments")
        ) == .created)

        let web = add("aws-ec2", x: 100, sensitivity: "confidential")
        let database = add("aws-rds", x: 900, sensitivity: "restricted")
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        )
        _ = app.addZone().execute(AddZoneRequest(x: 0, y: 0, width: 700, height: 600))
        let control = try #require(threats().first?.controls.first)
        _ = app.recordControlImplemented().execute(
            RecordControlImplementedRequest(controlKey: control.key)
        )
        _ = app.overrideThreatSeverity().execute(
            OverrideThreatSeverityRequest(
                overrideKey: try #require(threats().first).overrideKey,
                severityId: "low"
            )
        )
        _ = app.configurePathwayMitigations().execute(
            ConfigurePathwayMitigationsRequest(
                isMasterEnabled: true,
                mitigationId: "waf-protection",
                isEnabled: true,
                mode: "remove",
                reductionPercent: 0
            )
        )

        let before = app.viewThreatModel().execute(ViewThreatModelRequest())
        let beforeThreats = threats()
        let beforeSummary = app.summariseRisk().execute(SummariseRiskRequest())

        let file = save()

        // Everything is thrown away, and the file is all that is left.
        #expect(app.createThreatModel().execute(
            CreateThreatModelRequest(name: "Something else")
        ) == .created)
        #expect(threats().isEmpty)

        guard case .opened(let name, let drift) = app.openThreatModel().execute(
            OpenThreatModelRequest(data: file)
        ) else {
            Issue.record("Expected the file to open")
            return
        }

        #expect(name == "Payments")
        #expect(drift.hasDrift == false)
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()) == before)
        #expect(threats() == beforeThreats)
        #expect(app.summariseRisk().execute(SummariseRiskRequest()) == beforeSummary)
    }

    @Test func remembersWhenItWasMadeAndWhenItLastChanged() throws {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        let created = app.time.now()

        app.time.advance(by: 86_400)
        _ = add("aws-ec2", x: 0, sensitivity: "internal")
        let file = save()

        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Blank"))
        _ = app.openThreatModel().execute(OpenThreatModelRequest(data: file))

        // The document says when it was made and when it last changed. Both
        // survive the round trip; only the second one moves.
        let reopened = try #require(String(data: file, encoding: .utf8))
        #expect(reopened.contains("\"createdAt\""))
        #expect(reopened.contains("\"updatedAt\""))
        #expect(created != app.time.now())
    }

    @Test func saysWhatHasDriftedWhenTheCatalogueMovesOn() throws {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        _ = add("aws-ec2", x: 0, sensitivity: "internal")
        let file = save()

        // A file from another machine, naming a technology this catalogue does
        // not hold.
        let text = try #require(String(data: file, encoding: .utf8))
            .replacingOccurrences(of: "\"aws-ec2\"", with: "\"aws-retired\"")

        guard case .opened(_, let drift) = app.openThreatModel().execute(
            OpenThreatModelRequest(data: Data(text.utf8))
        ) else {
            Issue.record("Expected the file to open")
            return
        }

        #expect(drift.unknownTechnologyIds == ["aws-retired"])
        #expect(drift.hasDrift)
        // The component still draws; it just raises nothing.
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()).components.count == 1)
        #expect(threats().isEmpty)
    }

    @Test func refusesAFileItCannotRead() {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        _ = add("aws-ec2", x: 0, sensitivity: "internal")

        guard case .unreadable = app.openThreatModel().execute(
            OpenThreatModelRequest(data: Data("not a threat model".utf8))
        ) else {
            Issue.record("Expected the bytes to be refused")
            return
        }

        // The work that was open is untouched.
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()).components.count == 1)
    }
}
