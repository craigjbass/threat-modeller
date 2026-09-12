import CoreGraphics
import Testing
@testable import threatmodeller

struct AnchorGeometryTests {
    private let box = ComponentBox(x: 0, y: 0)

    @Test func placesTheFourAnchorsOnTheEdges() {
        let width = ComponentBox.slotSize.width
        let height = ComponentBox.slotSize.height

        #expect(AnchorGeometry.point(.top, of: box) == CGPoint(x: width / 2, y: 0))
        #expect(AnchorGeometry.point(.right, of: box) == CGPoint(x: width, y: height / 2))
        #expect(AnchorGeometry.point(.bottom, of: box) == CGPoint(x: width / 2, y: height))
        #expect(AnchorGeometry.point(.left, of: box) == CGPoint(x: 0, y: height / 2))
    }

    @Test func leavesFromTheRightAndArrivesOnTheLeftForABoxToTheRight() {
        let pair = AnchorGeometry.nearestPair(from: box, to: ComponentBox(x: 400, y: 0))

        #expect(pair.source == .right)
        #expect(pair.target == .left)
    }

    @Test func leavesFromTheLeftAndArrivesOnTheRightForABoxToTheLeft() {
        let pair = AnchorGeometry.nearestPair(from: box, to: ComponentBox(x: -400, y: 0))

        #expect(pair.source == .left)
        #expect(pair.target == .right)
    }

    @Test func leavesFromTheBottomAndArrivesOnTheTopForABoxBelow() {
        let pair = AnchorGeometry.nearestPair(from: box, to: ComponentBox(x: 0, y: 400))

        #expect(pair.source == .bottom)
        #expect(pair.target == .top)
    }

    @Test func picksTheSamePairEveryTimeForTheSameLayout() {
        let first = AnchorGeometry.nearestPair(from: box, to: ComponentBox(x: 300, y: 300))
        let second = AnchorGeometry.nearestPair(from: box, to: ComponentBox(x: 300, y: 300))

        #expect(first == second)
    }
}
