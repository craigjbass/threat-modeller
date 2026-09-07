import Testing
import ThreatModelKit
import TestSupport

struct AddComponentTests {
    private let models = InMemoryThreatModelGateway()
    private let ids = SequentialIdentityGenerator()

    private func useCase() -> AddComponent {
        AddComponent(models: models, catalogue: CatalogueFixture.catalogue(), ids: ids)
    }

    @Test func addsTheTechnologyToTheModel() {
        let response = useCase().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 120, y: 240, sensitivity: "confidential")
        )

        #expect(response == .added(componentId: "id-1"))
        #expect(models.current().components.count == 1)

        let component = models.current().components[0]
        #expect(component.technologyId == TechnologyId("aws-ec2"))
        #expect(component.position == Point(x: 120, y: 240))
        #expect(component.sensitivity == .confidential)
        #expect(component.customName == nil)
        #expect(component.threatsDisabled == false)
    }

    @Test func keepsEarlierComponents() {
        _ = useCase().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )
        let second = useCase().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 10, y: 10, sensitivity: "restricted")
        )

        #expect(second == .added(componentId: "id-2"))
        #expect(models.current().components.map(\.technologyId.value) == ["aws-ec2", "aws-rds"])
    }

    @Test func rejectsATechnologyTheCatalogueDoesNotHave() {
        let response = useCase().execute(
            AddComponentRequest(technologyId: "aws-nope", x: 0, y: 0, sensitivity: "internal")
        )

        #expect(response == .unknownTechnology)
        #expect(models.current().components.isEmpty)
    }

    @Test func rejectsAnUnknownSensitivity() {
        let response = useCase().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "top-secret")
        )

        #expect(response == .unknownSensitivity)
        #expect(models.current().components.isEmpty)
    }

    @Test func ranksSensitivities() {
        #expect(DataSensitivity.publicData.rank == 1)
        #expect(DataSensitivity.internalData.rank == 2)
        #expect(DataSensitivity.confidential.rank == 3)
        #expect(DataSensitivity.restricted.rank == 4)
        #expect(DataSensitivity.internalData.label == "Internal")
        #expect(DataSensitivity(rawValue: "public") == .publicData)
    }
}
