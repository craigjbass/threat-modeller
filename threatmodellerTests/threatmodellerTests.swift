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

    @Test func drawsAZoneAndReducesWhatItCaptures() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let before = try #require(session.threats.first { $0.threatId == "credential-theft" }).riskScore

        let zoneId = session.addZone(x: 0, y: 0, width: 600, height: 500)

        #expect(zoneId != nil)
        #expect(session.canvas.zones.count == 1)
        #expect(session.canvas.components.first?.zoneId == zoneId)
        let after = try #require(session.threats.first { $0.threatId == "credential-theft" }).riskScore
        #expect(after < before)
        #expect(session.errorMessage == nil)
    }

    @Test func refusesAZoneDrawnTooSmall() {
        let session = session()

        #expect(session.addZone(x: 0, y: 0, width: 10, height: 10) == nil)
        #expect(session.canvas.zones.isEmpty)
        #expect(session.errorMessage == "That zone is too small to draw.")
    }

    @Test func movesAZoneToItsNewRectangle() throws {
        let session = session()
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 600, height: 500))

        session.resizeZone(zoneId, x: 40, y: 60, width: 700, height: 550)

        let zone = try #require(session.canvas.zones.first)
        #expect(zone.x == 40)
        #expect(zone.width == 700)
    }

    @Test func setsAZonesPropertiesAndRescores() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 600, height: 500))
        #expect(session.threats.contains { $0.threatId == "lateral-movement" })

        session.setZoneProperties(
            zoneId: zoneId,
            name: "Internet",
            networkZoneId: "public",
            networkTypeId: "generic",
            riskReductionEnabled: true,
            riskReductionPercent: 20
        )

        #expect(session.canvas.zones.first?.name == "Internet")
        #expect(session.canvas.zones.first?.networkZoneId == "public")
        // A public zone raises no zone threats and reduces nothing.
        #expect(session.threats.contains { $0.threatId == "lateral-movement" } == false)
        #expect(try #require(session.threats.first { $0.threatId == "credential-theft" }).riskScore == 8)
    }

    @Test func removesAZoneAndLeavesItsComponents() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 600, height: 500))

        session.removeZone(zoneId)

        #expect(session.canvas.zones.isEmpty)
        #expect(session.canvas.components.count == 1)
        #expect(session.canvas.components.first?.zoneId == nil)
    }

    @Test func showsTheZoneBadgeNameForACapturedComponent() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 600, height: 500))
        session.setZoneProperties(
            zoneId: zoneId,
            name: "Payments",
            networkZoneId: "private",
            networkTypeId: "vpc",
            riskReductionEnabled: true,
            riskReductionPercent: 20
        )

        let captured = try #require(session.canvas.components.first)
        #expect(captured.zoneId == zoneId)
        #expect(session.canvas.zones.first?.name == "Payments")
    }

    @Test func reportsAReductionOutsideTheRange() throws {
        let session = session()
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 600, height: 500))

        session.setZoneProperties(
            zoneId: zoneId,
            name: nil,
            networkZoneId: "private",
            networkTypeId: "generic",
            riskReductionEnabled: true,
            riskReductionPercent: 200
        )

        #expect(session.errorMessage == "Risk reduction must be between 0 and 100 per cent.")
        #expect(session.canvas.zones.first?.riskReductionPercent == 20)
    }

    @Test func summarisesWhatTheSidebarLists() {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)

        #expect(session.summary.totalThreats == session.threats.count)
        #expect(session.summary.byLevel.map(\.levelId) == ["critical", "high", "medium", "low"])
        #expect(session.summary.controlsOffered > 0)
        #expect(session.summary.controlsRecorded == 0)
    }

    @Test func offersEverySeverityTheUserCanOverrideTo() {
        let session = session()

        #expect(session.severityChoices.map(\.id) == ["low", "medium", "high", "critical"])
        #expect(session.severityChoices.map(\.label) == ["Low", "Medium", "High", "Critical"])
    }

    @Test func ticksAndUnticksAControl() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        let control = try #require(
            session.threats.first { $0.threatId == "credential-theft" }?.controls.first
        )

        session.setControl(key: control.key, implemented: true)
        #expect(session.summary.controlsRecorded == 1)
        #expect(session.errorMessage == nil)

        session.setControl(key: control.key, implemented: false)
        #expect(session.summary.controlsRecorded == 0)
    }

    @Test func overridesAndRestoresASeverity() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        let key = try #require(session.threats.first { $0.threatId == "credential-theft" }).overrideKey

        session.overrideSeverity(overrideKey: key, severityId: "low")
        #expect(try #require(session.threats.first { $0.threatId == "credential-theft" }).severityId == "low")

        session.clearOverride(overrideKey: key)
        #expect(try #require(session.threats.first { $0.threatId == "credential-theft" }).severityId == "critical")
        #expect(session.errorMessage == nil)
    }

    @Test func reportsASeverityItDoesNotKnow() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        let key = try #require(session.threats.first { $0.threatId == "credential-theft" }).overrideKey

        session.overrideSeverity(overrideKey: key, severityId: "catastrophic")

        #expect(session.errorMessage == "That severity is not in the catalogue.")
    }

    @Test func listsThePathwayMitigationsOnLaunch() throws {
        let session = session()

        #expect(session.pathwayMitigations.isMasterEnabled == false)
        let waf = try #require(session.pathwayMitigations.mitigations.first)
        #expect(waf.id == "waf-protection")
        #expect(waf.isProvidedOnThisModel == false)
    }

    @Test func saysWhenTheModelProvidesAMitigation() throws {
        let session = session()

        session.add(technologyId: "aws-waf", x: 0, y: 0)

        #expect(try #require(session.pathwayMitigations.mitigations.first).isProvidedOnThisModel)
    }

    @Test func lowersAThreatWhenTheUserSwitchesTheControlOn() throws {
        let session = session()
        session.add(technologyId: "aws-waf", x: 0, y: 0)
        session.add(technologyId: "aws-ec2", x: 300, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])

        let before = try #require(
            session.threats.first { $0.threatId == "credential-theft" }
        ).riskScore

        session.setPathwayMitigation(
            id: "waf-protection",
            isEnabled: true,
            mode: "reduce",
            reductionPercent: 50
        )

        let after = try #require(session.threats.first { $0.threatId == "credential-theft" })
        #expect(after.riskScore < before)
        #expect(after.pathwayMitigationLabels == ["WAF Protection"])
        #expect(session.pathwayMitigations.isMasterEnabled)
        #expect(session.errorMessage == nil)
    }

    @Test func turnsEveryMitigationOffAtOnce() throws {
        let session = session()
        session.add(technologyId: "aws-waf", x: 0, y: 0)
        session.add(technologyId: "aws-ec2", x: 300, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])
        session.setPathwayMitigation(
            id: "waf-protection",
            isEnabled: true,
            mode: "reduce",
            reductionPercent: 50
        )

        session.setPathwayMaster(false)

        #expect(session.pathwayMitigations.isMasterEnabled == false)
        #expect(try #require(session.threats.first { $0.threatId == "credential-theft" })
                .pathwayMitigationLabels.isEmpty)
    }

    @Test func reportsAReductionOutsideTheRangeOnAMitigation() {
        let session = session()

        session.setPathwayMitigation(
            id: "waf-protection",
            isEnabled: true,
            mode: "reduce",
            reductionPercent: 500
        )

        #expect(session.errorMessage == "Risk reduction must be between 0 and 100 per cent.")
    }

    @Test func takesBackTheLastChange() {
        let session = session()
        #expect(session.canUndo == false)

        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        #expect(session.canUndo)
        #expect(session.threats.isEmpty == false)

        session.undo()

        #expect(session.canvas.components.isEmpty)
        #expect(session.threats.isEmpty)
        #expect(session.canRedo)

        session.redo()
        #expect(session.canvas.components.count == 1)
    }

    @Test func saysNothingWhenThereIsNothingToTakeBack() {
        let session = session()

        session.undo()

        #expect(session.errorMessage == nil)
    }

    @Test func copiesAndPastesASelection() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let web = try #require(session.canvas.components.first).id

        session.copySelection(componentIds: [web], zoneIds: [])
        let pasted = session.paste()

        #expect(pasted.componentIds.count == 1)
        #expect(session.canvas.components.count == 2)
        #expect(session.errorMessage == nil)
    }

    @Test func cutRemovesWhatItCopied() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let web = try #require(session.canvas.components.first).id

        session.cutSelection(componentIds: [web], zoneIds: [])
        #expect(session.canvas.components.isEmpty)

        let pasted = session.paste()
        #expect(pasted.componentIds.count == 1)
        #expect(session.canvas.components.count == 1)
    }

    @Test func duplicatesWithoutTouchingTheClipboard() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        session.add(technologyId: "aws-rds", x: 500, y: 100)
        let ids = session.canvas.components.map(\.id)

        session.copySelection(componentIds: [ids[0]], zoneIds: [])
        let duplicated = session.duplicate(componentIds: [ids[1]], zoneIds: [])

        #expect(duplicated.componentIds.count == 1)
        #expect(session.canvas.components.count == 3)

        // The earlier copy is still what pastes.
        _ = session.paste()
        #expect(session.canvas.components.count == 4)
    }

    @Test func saysNothingWhenTheClipboardHoldsSomethingElse() {
        let session = session()
        session.putOnClipboard("a sentence someone copied from a web page")

        let pasted = session.paste()

        #expect(pasted.componentIds.isEmpty)
        #expect(session.errorMessage == "There is no threat model on the clipboard.")
    }

    @Test func selectsEverythingAtOnce() {
        let canvas = CanvasState()

        canvas.select(connectionId: "k1", addingToSelection: false)
        canvas.selectAll(componentIds: ["c1", "c2"], zoneIds: ["z1"])

        #expect(canvas.selectedComponentIds == ["c1", "c2"])
        #expect(canvas.selectedZoneIds == ["z1"])
        #expect(canvas.selectedConnectionIds.isEmpty)
    }

    @Test func deletesEverythingSelectedInOneGo() throws {
        let session = session()
        let canvas = CanvasState()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 500, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 700, height: 600))

        canvas.selectAll(componentIds: [ids[0]], zoneIds: [zoneId])
        CanvasGestures(session: session, canvas: canvas).deleteSelection()

        // The component goes, the link it carried goes with it, and the zone
        // goes too. The other component stays.
        #expect(session.canvas.components.map(\.id) == [ids[1]])
        #expect(session.canvas.connections.isEmpty)
        #expect(session.canvas.zones.isEmpty)
        // Nothing is left selected that the model no longer holds.
        #expect(canvas.selectedComponentIds.isEmpty)
        #expect(canvas.selectedZoneIds.isEmpty)
    }

    @Test func deletesJustTheLinkWhenThatIsWhatIsSelected() throws {
        let session = session()
        let canvas = CanvasState()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 500, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])
        let link = try #require(session.canvas.connections.first).id

        canvas.select(connectionId: link, addingToSelection: false)
        CanvasGestures(session: session, canvas: canvas).deleteSelection()

        #expect(session.canvas.connections.isEmpty)
        #expect(session.canvas.components.count == 2)
    }

    @Test func deletingNothingChangesNothing() {
        let session = session()
        let canvas = CanvasState()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)

        CanvasGestures(session: session, canvas: canvas).deleteSelection()

        #expect(session.canvas.components.count == 1)
        #expect(session.errorMessage == nil)
    }
}
