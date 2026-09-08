import Testing
import ThreatModelKit
import TestSupport

struct OverrideThreatSeverityTests {
    private let models = InMemoryThreatModelGateway()
    private let catalogue = CatalogueFixture.catalogue()

    private let key = SeverityOverrideKey.forComponent(
        technologyId: TechnologyId("aws-ec2"),
        threatId: ThreatId("credential-theft")
    )

    private func override(_ keyValue: String, to severityId: String) -> OverrideThreatSeverityResponse {
        OverrideThreatSeverity(models: models, catalogue: catalogue)
            .execute(OverrideThreatSeverityRequest(overrideKey: keyValue, severityId: severityId))
    }

    private func clear(_ keyValue: String) -> ClearSeverityOverrideResponse {
        ClearSeverityOverride(models: models)
            .execute(ClearSeverityOverrideRequest(overrideKey: keyValue))
    }

    @Test func recordsTheOverride() {
        #expect(override(key.value, to: "low") == .overridden)

        #expect(models.current().severityOverrides == [key: "low"])
    }

    @Test func replacesAnOverrideAlreadyThere() {
        _ = override(key.value, to: "low")

        #expect(override(key.value, to: "high") == .overridden)
        #expect(models.current().severityOverrides == [key: "high"])
    }

    @Test func refusesASeverityTheTaxonomyDoesNotHave() {
        #expect(override(key.value, to: "catastrophic") == .unknownSeverity)
        #expect(models.current().severityOverrides.isEmpty)
    }

    @Test func acceptsEverySeverityTheTaxonomyHas() {
        for severity in catalogue.taxonomy().severities {
            #expect(override(key.value, to: severity.id) == .overridden)
        }
    }

    @Test func acceptsAnyKeyShapeTheResponseHandedOut() {
        #expect(override("connection::connection-mitm", to: "high") == .overridden)
        #expect(override("zone::lateral-movement", to: "low") == .overridden)
        #expect(models.current().severityOverrides.count == 2)
    }

    @Test func clearsAnOverride() {
        _ = override(key.value, to: "low")

        #expect(clear(key.value) == .cleared)
        #expect(models.current().severityOverrides.isEmpty)
    }

    @Test func saysSoWhenThereIsNothingToClear() {
        #expect(clear(key.value) == .noOverride)
    }

    @Test func clearsOnlyTheKeyNamed() {
        _ = override(key.value, to: "low")
        _ = override("zone::lateral-movement", to: "high")

        #expect(clear(key.value) == .cleared)
        #expect(models.current().severityOverrides
                == [SeverityOverrideKey("zone::lateral-movement"): "high"])
    }
}
