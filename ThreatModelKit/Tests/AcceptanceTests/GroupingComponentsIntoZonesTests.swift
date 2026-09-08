import Testing
import ThreatModelKit
import TestSupport

/// Given components on my threat model
/// When I draw a private network zone around them
/// Then their risk falls, and the zone raises threats of its own
struct GroupingComponentsIntoZonesTests {
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

    private func addZone(x: Double, y: Double, width: Double, height: Double) -> String {
        let response = app.addZone().execute(
            AddZoneRequest(x: x, y: y, width: width, height: height)
        )
        guard case .added(let zoneId) = response else {
            Issue.record("Expected the zone to be added, got \(response)")
            return ""
        }
        return zoneId
    }

    private func assess() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    private func score(_ threatId: String, from sourceId: String) -> Int? {
        assess().first { $0.threatId == threatId && $0.source.id == sourceId }?.riskScore
    }

    private func zoneThreats() -> [AssessedThreat] {
        assess().filter {
            if case .zone = $0.source { return true } else { return false }
        }
    }

    @Test func lowersTheRiskOfAComponentTheZoneCaptures() throws {
        let web = add("aws-ec2", x: 100, y: 100, sensitivity: "confidential")
        #expect(score("credential-theft", from: "component:\(web)") == 12)

        _ = addZone(x: 0, y: 0, width: 600, height: 500)

        // 12 reduced by the default 20 per cent is 9.6, which rounds to 10.
        #expect(score("credential-theft", from: "component:\(web)") == 10)
        let theft = try #require(assess().first { $0.threatId == "credential-theft" })
        #expect(theft.riskLevel == "high")
    }

    @Test func raisesTheZonesOwnThreatsForAPrivateZone() throws {
        let zone = addZone(x: 0, y: 0, width: 600, height: 500)

        let raised = zoneThreats()
        #expect(raised.map(\.threatId).sorted() == ["lateral-movement", "misconfiguration"])
        #expect(raised.allSatisfy { $0.source.id == "zone:\(zone)" })
        #expect(raised.allSatisfy { $0.source.displayName == "Private Zone" })
        #expect(raised.allSatisfy { $0.sensitivityId == "internal" })

        let lateral = try #require(raised.first { $0.threatId == "lateral-movement" })
        #expect(lateral.riskScore == 5)
        #expect(lateral.context == "Pivoting between resources inside the network zone")
    }

    @Test func leavesEverythingAloneForAPublicZone() throws {
        let web = add("aws-ec2", x: 100, y: 100, sensitivity: "confidential")
        let zone = addZone(x: 0, y: 0, width: 600, height: 500)

        #expect(app.setZoneProperties().execute(
            SetZonePropertiesRequest(
                zoneId: zone,
                name: "Internet",
                networkZone: "public",
                networkType: "generic",
                riskReductionEnabled: true,
                riskReductionPercent: 20
            )
        ) == .updated)

        #expect(score("credential-theft", from: "component:\(web)") == 12)
        #expect(zoneThreats().isEmpty)
    }

    @Test func lowersALinkOnlyWhenBothEndsAreInPrivateZones() throws {
        let web = add("aws-ec2", x: 100, y: 100, sensitivity: "internal")
        let database = add("aws-rds", x: 1100, y: 100, sensitivity: "internal")
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        )
        let link = try #require(
            app.viewThreatModel().execute(ViewThreatModelRequest()).connections.first
        ).id

        // Man-in-the-middle is medium (2) against internal data (2), so 4.
        #expect(score("connection-mitm", from: "connection:\(link)") == 4)

        // One end inside a private zone changes nothing.
        let left = addZone(x: 0, y: 0, width: 600, height: 500)
        #expect(score("connection-mitm", from: "connection:\(link)") == 4)

        // Both ends inside private zones takes the lower of the two reductions.
        let right = addZone(x: 1000, y: 0, width: 600, height: 500)
        _ = app.setZoneProperties().execute(
            SetZonePropertiesRequest(
                zoneId: left, name: nil, networkZone: "private", networkType: "vpc",
                riskReductionEnabled: true, riskReductionPercent: 25
            )
        )
        _ = app.setZoneProperties().execute(
            SetZonePropertiesRequest(
                zoneId: right, name: nil, networkZone: "private", networkType: "subnet",
                riskReductionEnabled: true, riskReductionPercent: 75
            )
        )

        // 25 per cent is the lower reduction, so 4 becomes 3.
        #expect(score("connection-mitm", from: "connection:\(link)") == 3)
    }

    @Test func restoresTheRiskWhenAComponentMovesOutOfTheZone() throws {
        let web = add("aws-ec2", x: 100, y: 100, sensitivity: "confidential")
        _ = addZone(x: 0, y: 0, width: 600, height: 500)
        #expect(score("credential-theft", from: "component:\(web)") == 10)

        #expect(app.moveComponents().execute(
            MoveComponentsRequest(moves: [ComponentMove(componentId: web, x: 2000, y: 2000)])
        ) == .moved(count: 1))

        #expect(score("credential-theft", from: "component:\(web)") == 12)
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest())
                    .components.first?.zoneId == nil)
    }

    @Test func restoresTheRiskWhenTheZoneMovesOffTheComponent() throws {
        let web = add("aws-ec2", x: 100, y: 100, sensitivity: "confidential")
        let zone = addZone(x: 0, y: 0, width: 600, height: 500)
        #expect(score("credential-theft", from: "component:\(web)") == 10)

        #expect(app.resizeZone().execute(
            ResizeZoneRequest(zoneId: zone, x: 3000, y: 3000, width: 600, height: 500)
        ) == .resized)

        #expect(score("credential-theft", from: "component:\(web)") == 12)
    }

    @Test func leavesTheComponentsBehindWhenTheZoneIsRemoved() throws {
        let web = add("aws-ec2", x: 100, y: 100, sensitivity: "confidential")
        let zone = addZone(x: 0, y: 0, width: 600, height: 500)

        #expect(app.removeZone().execute(RemoveZoneRequest(zoneId: zone)) == .removed)

        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(canvas.zones.isEmpty)
        #expect(canvas.components.map(\.id) == [web])
        #expect(canvas.components.first?.zoneId == nil)
        #expect(score("credential-theft", from: "component:\(web)") == 12)
        #expect(zoneThreats().isEmpty)
    }

    @Test func showsTheZoneOnTheCanvasAsItIsDrawn() throws {
        let web = add("aws-ec2", x: 100, y: 100, sensitivity: "confidential")
        let zone = addZone(x: 0, y: 0, width: 600, height: 500)

        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        let drawn = try #require(canvas.zones.first)
        #expect(drawn.id == zone)
        #expect(drawn.name == "Private Zone")
        #expect(drawn.x == 0)
        #expect(drawn.width == 600)
        #expect(canvas.components.first { $0.id == web }?.zoneId == zone)
    }
}
