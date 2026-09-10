import Testing
import ThreatModelKit
import TestSupport

struct RecordControlTests {
    private let models = InMemoryThreatModelGateway()
    private let key = ControlIdentity.componentControl(
        componentId: ComponentId("c1"),
        threatId: ThreatId("credential-theft"),
        description: "Rotate credentials regularly",
        isTechnologySpecific: false
    )
    private let other = ControlIdentity.connectionControl(
        threatId: ThreatId("connection-mitm"),
        description: "Enforce TLS on every hop"
    )

    private func record(_ key: ControlKey) -> RecordControlImplementedResponse {
        RecordControlImplemented(models: models)
            .execute(RecordControlImplementedRequest(controlKey: key.value))
    }

    private func unrecord(_ key: ControlKey) -> RecordControlNotImplementedResponse {
        RecordControlNotImplemented(models: models)
            .execute(RecordControlNotImplementedRequest(controlKey: key.value))
    }

    @Test func recordsAControlAsInPlace() {
        #expect(record(key) == .recorded)

        #expect(models.current().implementedControls == [key])
    }

    @Test func recordingTwiceIsRecordingOnce() {
        _ = record(key)

        #expect(record(key) == .recorded)
        #expect(models.current().implementedControls == [key])
    }

    @Test func takesAControlBackOut() {
        _ = record(key)

        #expect(unrecord(key) == .recorded)
        #expect(models.current().implementedControls.isEmpty)
    }

    @Test func takingOutSomethingNeverRecordedIsNotAnError() {
        #expect(unrecord(key) == .recorded)
        #expect(models.current().implementedControls.isEmpty)
    }

    @Test func touchesNoOtherControl() {
        _ = record(key)
        _ = record(other)

        _ = unrecord(key)

        #expect(models.current().implementedControls == [other])
    }

    /// Recording one of the two controls covers half the credential-theft
    /// threat, so its score drops from 12 to 8. The other threats carry no
    /// control this test answers, so their scores stay at 6 and 3.
    @Test func recordingAControlLowersOnlyItsOwnThreatsScore() {
        let catalogue = CatalogueFixture.catalogue()
        let seeded = InMemoryThreatModelGateway(
            ThreatModel(components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential
                )
            ])
        )
        let assess = AssessThreatModel(models: seeded, catalogue: catalogue)
        let before = assess.execute(AssessThreatModelRequest()).threats.map(\.riskScore)
        #expect(before == [12, 6, 3])

        _ = RecordControlImplemented(models: seeded).execute(
            RecordControlImplementedRequest(
                controlKey: ControlIdentity.componentControl(
                    componentId: ComponentId("c1"),
                    threatId: ThreatId("credential-theft"),
                    description: "Use IAM roles with minimal permissions",
                    isTechnologySpecific: true
                ).value
            )
        )

        #expect(assess.execute(AssessThreatModelRequest()).threats.map(\.riskScore) == [8, 6, 3])
    }
}
