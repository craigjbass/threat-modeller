import Testing
import ThreatModelKit

@Suite("What shape a component draws as")
struct DiagramShapeTests {
    @Test func drawsAnActorProviderAsAnActor() {
        #expect(DiagramShapeMap.derived(providerId: "actor", categoryId: "person") == .actor)
        #expect(DiagramShapeMap.derived(providerId: "actor", categoryId: "system") == .actor)
    }

    @Test func drawsAStoreCategoryAsAStore() {
        #expect(DiagramShapeMap.derived(providerId: "aws", categoryId: "database") == .store)
        #expect(DiagramShapeMap.derived(providerId: "aws", categoryId: "storage") == .store)
        #expect(DiagramShapeMap.derived(providerId: "aws", categoryId: "secrets") == .store)
    }

    @Test func drawsEverythingElseAsAProcess() {
        #expect(DiagramShapeMap.derived(providerId: "aws", categoryId: "compute") == .process)
        #expect(DiagramShapeMap.derived(providerId: "gcp", categoryId: "messaging") == .process)
    }

    @Test func drawsAnUnknownTechnologyAsAProcess() {
        #expect(DiagramShapeMap.derived(providerId: "", categoryId: "") == .process)
    }

    @Test func takesTheUsersOwnShapeOverTheMap() {
        let component = Component(
            id: ComponentId("c1"),
            technologyId: TechnologyId("aws-rds"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData,
            shape: .process
        )

        #expect(component.resolvedShape(providerId: "aws", categoryId: "database") == .process)
    }

    @Test func fallsBackToTheMapWhenTheUserStatesNoShape() {
        let component = Component(
            id: ComponentId("c1"),
            technologyId: TechnologyId("aws-rds"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )

        #expect(component.shape == nil)
        #expect(component.resolvedShape(providerId: "aws", categoryId: "database") == .store)
    }

    @Test func givesEachShapeItsOwnFootprint() {
        #expect(Component.footprint(for: .actor) == Size(width: 160, height: 72))
        #expect(Component.footprint(for: .process) == Size(width: 104, height: 104))
        #expect(Component.footprint(for: .store) == Size(width: 160, height: 64))
    }

    @Test func keepsTheCentreInTheSamePlaceForEveryShape() {
        let component = Component(
            id: ComponentId("c1"),
            technologyId: TechnologyId("aws-rds"),
            position: Point(x: 200, y: 100),
            sensitivity: .internalData
        )

        #expect(component.centre == Point(x: 280, y: 136))
        #expect(Component.size == Size(width: 160, height: 72))
    }

    @Test func readsEveryShapeFromItsWord() {
        #expect(DiagramShape(rawValue: "actor") == .actor)
        #expect(DiagramShape(rawValue: "process") == .process)
        #expect(DiagramShape(rawValue: "store") == .store)
        #expect(DiagramShape(rawValue: "cylinder") == nil)
        #expect(DiagramShape.allCases.count == 3)
    }
}
