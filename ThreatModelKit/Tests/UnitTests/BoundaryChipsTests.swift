import Foundation
import Testing
import ThreatModelKit

@Suite("Where the chips naming a boundary's guards sit")
struct BoundaryChipsTests {
    private let run = BoundaryCrossings.BoundaryRun(
        zoneId: "z1",
        networkZoneId: "private",
        guards: [],
        openCount: 0,
        connectionIds: ["f1"],
        start: Point(x: 200, y: 0),
        end: Point(x: 200, y: 400),
        control: Point(x: 180, y: 200)
    )

    @Test func writesNothingWhenThereIsNothingToWrite() {
        #expect(BoundaryChips.rects(of: run, texts: []).isEmpty)
    }

    @Test func stacksTheChipsPastTheEndOfTheCurve() {
        let rects = BoundaryChips.rects(of: run, texts: ["opfilter System Extension", "+1"])

        #expect(rects.count == 2)
        #expect(rects[0].minY > run.end.y - BoundaryChips.height)
        #expect(rects[1].minY > rects[0].minY)
    }

    @Test func widensAChipForALongerName() {
        let rects = BoundaryChips.rects(of: run, texts: ["WAF", "opfilter System Extension"])

        #expect(rects[1].size.width > rects[0].size.width)
    }

    @Test func dropsBelowAZonesNameBand() {
        let band = Rect(x: 0, y: 400, width: 400, height: 40)
        let rects = BoundaryChips.rects(
            of: run,
            texts: ["opfilter System Extension"],
            zoneHeaders: [band]
        )

        #expect(rects[0].minY >= band.maxY)
    }
}
