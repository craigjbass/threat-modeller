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

    @Test func weighsAFlowOverAZoneAboveThreeBrokenBoundaries() {
        #expect(fitness(overZones: 1).score > fitness(broken: 3).score)
    }

    @Test func weighsABrokenBoundaryAboveTheReadingCosts() {
        #expect(fitness(broken: 1).score > fitness(waypoints: 4).score)
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

@Suite("Scoring how easy a picture is to read")
struct LayoutReadabilityFitnessTests {
    private func fitness(
        overZones: Int = 0,
        broken: Int = 0,
        waypoints: Int = 0,
        sharpness: Double = 0,
        crossings: Int = 0,
        behind: Int = 0,
        width: Double = 1000,
        height: Double = 1000
    ) -> LayoutFitness {
        LayoutFitness(
            brokenBoundaries: broken,
            flowsOverUnrelatedZones: overZones,
            waypoints: waypoints,
            sharpness: sharpness,
            flowCrossings: crossings,
            flowsBehindNodes: behind,
            width: width,
            height: height
        )
    }

    @Test func weighsASharpTurnAboveALineCrossing() {
        #expect(fitness(sharpness: 1).score > fitness(crossings: 3).score)
    }

    @Test func weighsASharpTurnAboveAFlowBehindANode() {
        #expect(fitness(sharpness: 1).score > fitness(behind: 3).score)
    }

    @Test func weighsAFaultAboveEveryReadingCostTogether() {
        #expect(
            fitness(overZones: 1).score
                > fitness(sharpness: 3, crossings: 20, behind: 20).score
        )
    }

    @Test func weighsALineCrossingTheSameAsAFlowBehindANode() {
        #expect(fitness(crossings: 1).score == fitness(behind: 1).score)
    }

    @Test func chargesNothingForAPictureThatReadsCleanly() {
        #expect(fitness().score == fitness(sharpness: 0, crossings: 0, behind: 0).score)
    }
}
