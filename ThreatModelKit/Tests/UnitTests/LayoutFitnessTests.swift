import Testing
import ThreatModelKit

@Suite("Scoring a placed layout")
struct LayoutFitnessTests {
    private func fitness(
        crossings: Int = 0,
        overZones: Int = 0,
        waypoints: Int = 0,
        width: Double = 1000,
        height: Double = 1000
    ) -> LayoutFitness {
        LayoutFitness(
            unrelatedCrossings: crossings,
            flowsOverUnrelatedZones: overZones,
            waypoints: waypoints,
            width: width,
            height: height
        )
    }

    @Test func weighsOneFaultAboveAnyNumberOfDetours() {
        #expect(fitness(crossings: 1).score > fitness(waypoints: 19).score)
    }

    @Test func weighsAFlowOverAZoneTheSameAsAnUnrelatedCrossing() {
        #expect(fitness(crossings: 1).score == fitness(overZones: 1).score)
    }

    @Test func weighsOneDetourAboveFiveHundredPointsOfDiagram() {
        #expect(fitness(waypoints: 1).score > fitness(width: 1400).score)
    }

    @Test func decidesTwoFaultlessLayoutsBySize() {
        #expect(fitness(width: 1000).score < fitness(width: 1400).score)
    }

    @Test func neverTakesAWiderLayoutThatFixesNothing() {
        let narrow = fitness(crossings: 2, width: 1000, height: 1000)
        let wider = fitness(crossings: 2, width: 1600, height: 1600)

        #expect(narrow.score < wider.score)
    }
}
