import CoreGraphics
import SwiftUI
import Testing
import ThreatModelKit
@testable import threatmodeller

/// The stretches a boundary draws once the flows it says nothing about are
/// taken out of it.
struct BoundaryRunPathTests {
    private let run = BoundaryCrossings.BoundaryRun(
        zoneId: "z1",
        networkZoneId: "private",
        guards: [],
        openCount: 0,
        connectionIds: ["f1"],
        start: Point(x: 200, y: 0),
        end: Point(x: 200, y: 400),
        control: Point(x: 200, y: 200)
    )

    /// How many separate stretches the path holds.
    private func stretches(_ path: Path) -> Int {
        var count = 0
        path.forEach { element in
            if case .move = element { count += 1 }
        }
        return count
    }

    @Test func drawsOneStretchWhenNothingUnrelatedCrossesIt() {
        #expect(stretches(run.path(avoiding: [])) == 1)
    }

    @Test func drawsOneStretchWhenAnUnrelatedFlowStaysClear() {
        let clear = [Point(x: 400, y: 100), Point(x: 900, y: 100)]

        #expect(stretches(run.path(avoiding: [clear])) == 1)
    }

    @Test func breaksTheCurveWhereAnUnrelatedFlowCrossesIt() {
        let through = [Point(x: 0, y: 200), Point(x: 400, y: 200)]

        #expect(stretches(run.path(avoiding: [through])) == 2)
    }

    @Test func breaksTheCurveOnceForEachUnrelatedFlow() {
        let first = [Point(x: 0, y: 120), Point(x: 400, y: 120)]
        let second = [Point(x: 0, y: 280), Point(x: 400, y: 280)]

        #expect(stretches(run.path(avoiding: [first, second])) == 3)
    }

    @Test func drawsNothingWhenAnUnrelatedFlowCrossesEveryPartOfIt() {
        let everywhere = (0...40).map { step -> [Point] in
            let y = Double(step) * 10
            return [Point(x: 0, y: y), Point(x: 400, y: y)]
        }

        #expect(stretches(run.path(avoiding: everywhere)) == 0)
    }
}
