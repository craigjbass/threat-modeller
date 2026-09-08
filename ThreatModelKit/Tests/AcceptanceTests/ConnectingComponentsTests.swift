import Testing
import ThreatModelKit
import TestSupport

/// Given two technologies on my threat model
/// When I connect one to the other
/// Then the link raises its own threats, scored for the more sensitive end
struct ConnectingComponentsTests {
    private let app = TestDependencies()

    private func add(_ technologyId: String, x: Double, y: Double, sensitivity: String) -> String {
        let response = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: x, y: y, sensitivity: sensitivity)
        )
        guard case .added(let componentId) = response else {
            Issue.record("Expected the component to be added, got \(response)")
            return ""
        }
        return componentId
    }

    private func assess() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    private func linkThreats() -> [AssessedThreat] {
        assess().filter {
            if case .connection = $0.source { return true } else { return false }
        }
    }

    @Test func raisesTheLinksThreatsWhenTwoComponentsAreConnected() throws {
        let web = add("aws-ec2", x: 0, y: 0, sensitivity: "confidential")
        let database = add("aws-rds", x: 300, y: 0, sensitivity: "restricted")

        #expect(app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        ) == .connected(connectionId: "id-3"))

        let onTheLink = linkThreats()
        #expect(onTheLink.map(\.threatId) == ["connection-mitm", "connection-dos"])
        #expect(onTheLink.allSatisfy { $0.source.displayName == "EC2 \u{2192} RDS" })

        // The link is scored against restricted, the higher of the two ends.
        let mitm = try #require(onTheLink.first { $0.threatId == "connection-mitm" })
        #expect(mitm.sensitivityId == "restricted")
        #expect(mitm.riskScore == 8)
        #expect(mitm.riskLevel == "high")
        #expect(mitm.controls.map(\.description) == ["Enforce TLS on every hop"])

        // RDS enforces encryption, so the man-in-the-middle threat is flagged.
        // The flag does not change either score.
        let flood = try #require(onTheLink.first { $0.threatId == "connection-dos" })
        #expect(mitm.isTlsMitigated)
        #expect(flood.isTlsMitigated == false)
        #expect(flood.riskScore == 4)
    }

    @Test func showsTheCanvasAsTheModelIsBuilt() throws {
        let web = add("aws-ec2", x: 40, y: 80, sensitivity: "confidential")
        let database = add("aws-rds", x: 300, y: 80, sensitivity: "restricted")
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        )

        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())

        #expect(canvas.components.map(\.name) == ["EC2", "RDS"])
        #expect(canvas.components.first?.x == 40)
        #expect(canvas.components.first?.y == 80)
        #expect(canvas.connections.map(\.sourceComponentId) == [web])
        #expect(canvas.connections.map(\.targetComponentId) == [database])
    }

    @Test func movesAComponentWithoutChangingItsThreats() throws {
        let web = add("aws-ec2", x: 0, y: 0, sensitivity: "confidential")
        let before = assess().map(\.threatId)

        #expect(app.moveComponents().execute(
            MoveComponentsRequest(moves: [ComponentMove(componentId: web, x: 250, y: 130)])
        ) == .moved(count: 1))

        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(canvas.components.first?.x == 250)
        #expect(canvas.components.first?.y == 130)
        #expect(assess().map(\.threatId) == before)
    }

    @Test func refusesASecondLinkBetweenTheSamePair() throws {
        let web = add("aws-ec2", x: 0, y: 0, sensitivity: "internal")
        let database = add("aws-rds", x: 300, y: 0, sensitivity: "internal")
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        )

        #expect(app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        ) == .duplicateConnection(connectionId: "id-3"))

        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()).connections.count == 1)
    }

    @Test func removingAComponentTakesItsLinkAndTheLinksThreatsWithIt() throws {
        let web = add("aws-ec2", x: 0, y: 0, sensitivity: "internal")
        let database = add("aws-rds", x: 300, y: 0, sensitivity: "internal")
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        )
        #expect(linkThreats().isEmpty == false)

        #expect(app.removeComponents().execute(
            RemoveComponentsRequest(componentIds: [web])
        ) == .removed(componentIds: [web], connectionIds: ["id-3"]))

        #expect(linkThreats().isEmpty)
        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(canvas.components.map(\.name) == ["RDS"])
        #expect(canvas.connections.isEmpty)
    }

    @Test func removingOnlyTheLinkLeavesBothComponents() throws {
        let web = add("aws-ec2", x: 0, y: 0, sensitivity: "internal")
        let database = add("aws-rds", x: 300, y: 0, sensitivity: "internal")
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        )

        #expect(app.removeConnection().execute(
            RemoveConnectionRequest(connectionId: "id-3")
        ) == .removed)

        #expect(linkThreats().isEmpty)
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()).components.count == 2)
    }
}
