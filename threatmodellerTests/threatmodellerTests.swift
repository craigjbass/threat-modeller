import CoreGraphics
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The session is the delivery mechanism's translator. These tests run it on
/// the fake catalogue, not the vendored one: a catalogue update must never
/// break a delivery-mechanism test.
@MainActor
struct ThreatModelSessionTests {
    private func session() -> ThreatModelSession {
        ThreatModelSession(useCases: TestDependencies())
    }

    @Test func loadsThePaletteOnLaunch() {
        let session = session()

        #expect(session.palette.map(\.id) == ["aws", "gcp"])
        #expect(session.threats.isEmpty)
        #expect(session.canvas.components.isEmpty)
    }

    @Test func raisesScoredThreatsWhenATechnologyIsAdded() {
        let session = session()

        session.add(technologyId: "aws-ec2", x: 0, y: 0)

        #expect(session.threats.map(\.threatId) == [
            "credential-theft",
            "misconfiguration",
            "dos-attack"
        ])
        #expect(session.threats.first?.riskScore == 8)
        #expect(session.threats.first?.riskLevel == "high")
        #expect(session.errorMessage == nil)
    }

    @Test func reportsATechnologyThatIsNotInTheCatalogue() {
        let session = session()

        session.add(technologyId: "aws-imaginary", x: 0, y: 0)

        #expect(session.threats.isEmpty)
        #expect(session.errorMessage == "That technology is not in the catalogue.")
    }

    @Test func showsTheComponentItAdded() throws {
        let session = session()

        session.add(technologyId: "aws-ec2", x: 120, y: 60)

        let drawn = try #require(session.canvas.components.first)
        #expect(drawn.name == "EC2")
        #expect(drawn.x == 120)
        #expect(drawn.y == 60)
    }

    @Test func showsAndScoresALinkBetweenTwoComponents() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 300, y: 0)
        let ids = session.canvas.components.map(\.id)

        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])

        #expect(session.canvas.connections.count == 1)
        #expect(session.threats.contains { $0.threatId == "connection-mitm" })
        #expect(session.errorMessage == nil)
    }

    @Test func saysNothingWhenTheUserRepeatsALink() {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 300, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])

        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])

        #expect(session.canvas.connections.count == 1)
        #expect(session.errorMessage == nil)
    }

    @Test func movesAComponentToItsNewPosition() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        let id = try #require(session.canvas.components.first).id

        session.move([ComponentMove(componentId: id, x: 90, y: 45)])

        #expect(session.canvas.components.first?.x == 90)
        #expect(session.canvas.components.first?.y == 45)
    }

    @Test func removingAComponentTakesItsLinkWithIt() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 300, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])

        let removed = session.removeComponents([ids[0]])

        #expect(removed.connectionIds.count == 1)
        #expect(session.canvas.components.map(\.name) == ["RDS"])
        #expect(session.canvas.connections.isEmpty)
        #expect(session.threats.contains { $0.threatId == "connection-mitm" } == false)
    }

    @Test func removesOnlyTheLinkWhenAskedFor() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 300, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])
        let connectionId = try #require(session.canvas.connections.first).id

        session.removeConnection(connectionId)

        #expect(session.canvas.connections.isEmpty)
        #expect(session.canvas.components.count == 2)
        #expect(session.errorMessage == nil)
    }

    @Test func stepsRepeatedDoubleClicksSoTheyDoNotStack() {
        let session = session()

        session.addAtDefaultPoint(technologyId: "aws-ec2")
        session.addAtDefaultPoint(technologyId: "aws-ec2")

        let points = session.canvas.components.map { CGPoint(x: $0.x, y: $0.y) }
        #expect(points.count == 2)
        #expect(points[0] != points[1])
    }
}
