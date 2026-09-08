import CoreGraphics
import Testing
@testable import threatmodeller

struct MarqueeSelectionTests {
    private let boxes: [(id: String, box: ComponentBox)] = [
        (id: "c1", box: ComponentBox(x: 0, y: 0)),
        (id: "c2", box: ComponentBox(x: 400, y: 0)),
        (id: "c3", box: ComponentBox(x: 0, y: 400))
    ]

    @Test func buildsARectangleFromAnyDragDirection() {
        let downRight = MarqueeSelection.rect(from: CGPoint(x: 10, y: 20), to: CGPoint(x: 110, y: 220))
        let upLeft = MarqueeSelection.rect(from: CGPoint(x: 110, y: 220), to: CGPoint(x: 10, y: 20))

        #expect(downRight == CGRect(x: 10, y: 20, width: 100, height: 200))
        #expect(downRight == upLeft)
    }

    @Test func selectsEveryBoxTheRectangleTouches() {
        let rect = CGRect(x: -10, y: -10, width: 500, height: 100)

        #expect(MarqueeSelection.selected(in: rect, from: boxes) == ["c1", "c2"])
    }

    @Test func selectsABoxTheRectangleOnlyClips() {
        let rect = CGRect(x: -50, y: -50, width: 51, height: 51)

        #expect(MarqueeSelection.selected(in: rect, from: boxes) == ["c1"])
    }

    @Test func selectsNothingWhenTheRectangleMissesEverything() {
        let rect = CGRect(x: 1000, y: 1000, width: 50, height: 50)

        #expect(MarqueeSelection.selected(in: rect, from: boxes).isEmpty)
    }
}
