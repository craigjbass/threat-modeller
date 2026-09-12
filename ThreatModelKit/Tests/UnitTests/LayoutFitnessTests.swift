import Testing
import ThreatModelKit

@Suite("Scoring a placed layout")
struct LayoutFitnessTests {
    private func fitness(
        broken: Int = 0,
        overZones: Int = 0,
        waypoints: Int = 0,
        width: Double = 1000,
        height: Double = 1000
    ) -> LayoutFitness {
        LayoutFitness(
            brokenBoundaries: broken,
            flowsOverUnrelatedZones: overZones,
            waypoints: waypoints,
            width: width,
            height: height
        )
    }

    @Test func weighsOneFaultAboveAnyNumberOfDetours() {
        #expect(fitness(overZones: 1).score > fitness(waypoints: 19).score)
    }

    @Test func weighsAFlowOverAZoneAboveAnyNumberOfBrokenBoundaries() {
        #expect(fitness(overZones: 1).score > fitness(broken: 9).score)
    }

    @Test func weighsABrokenBoundaryAboveADetour() {
        #expect(fitness(broken: 1).score > fitness(waypoints: 1).score)
    }

    @Test func weighsOneDetourAboveTwoHundredPointsOfDiagram() {
        #expect(fitness(waypoints: 1).score > fitness(width: 1150).score)
    }

    @Test func weighsASquarePictureAboveALongOne() {
        #expect(fitness(width: 1000, height: 3000).score > fitness(width: 1700, height: 1700).score)
    }

    @Test func decidesTwoFaultlessLayoutsBySize() {
        #expect(fitness(width: 1000).score < fitness(width: 1400).score)
    }

    @Test func neverTakesAWiderLayoutThatFixesNothing() {
        let narrow = fitness(broken: 2, width: 1000, height: 1000)
        let wider = fitness(broken: 2, width: 1600, height: 1600)

        #expect(narrow.score < wider.score)
    }
}
