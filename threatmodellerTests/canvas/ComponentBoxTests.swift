import CoreGraphics
import Testing
import ThreatModelKit
@testable import threatmodeller

struct ComponentBoxTests {
    @Test func placesItsRectangleAtTheComponentPosition() {
        let box = ComponentBox(x: 100, y: 50)

        #expect(box.rect.origin == CGPoint(x: 100, y: 50))
        #expect(box.rect.size == ComponentBox.slotSize)
    }

    @Test func findsItsOwnCentre() {
        let box = ComponentBox(x: 0, y: 0)

        #expect(box.centre == CGPoint(
            x: ComponentBox.slotSize.width / 2,
            y: ComponentBox.slotSize.height / 2
        ))
    }

    @Test func containsAPointInsideIt() {
        let box = ComponentBox(x: 10, y: 10)

        #expect(box.contains(CGPoint(x: 20, y: 20)))
        #expect(box.contains(CGPoint(x: 9, y: 20)) == false)
        #expect(box.contains(CGPoint(x: 20, y: 10 + ComponentBox.slotSize.height + 1)) == false)
    }

    @Test func keepsTheCentreWhateverShapeItDrawsAs() {
        let centre = CGPoint(x: 80, y: 36)

        #expect(ComponentBox(x: 0, y: 0, shape: .actor).centre == centre)
        #expect(ComponentBox(x: 0, y: 0, shape: .process).centre == centre)
        #expect(ComponentBox(x: 0, y: 0, shape: .store).centre == centre)
    }

    @Test func drawsEachShapeAtItsOwnFootprint() {
        #expect(ComponentBox(x: 0, y: 0, shape: .actor).rect.size == CGSize(width: 160, height: 72))
        #expect(ComponentBox(x: 0, y: 0, shape: .process).rect.size == CGSize(width: 104, height: 104))
        #expect(ComponentBox(x: 0, y: 0, shape: .store).rect.size == CGSize(width: 160, height: 64))
    }

    @Test func centresAProcessCircleOnTheSlot() {
        let box = ComponentBox(x: 0, y: 0, shape: .process)

        #expect(box.rect.origin == CGPoint(x: 28, y: -16))
    }

    @Test func missesTheCornerOfAProcessCircle() {
        let box = ComponentBox(x: 0, y: 0, shape: .process)

        #expect(box.contains(box.centre))
        #expect(box.contains(CGPoint(x: box.rect.minX + 2, y: box.rect.minY + 2)) == false)
    }

    @Test func takesTheWholeRectangleForAnActor() {
        let box = ComponentBox(x: 0, y: 0, shape: .actor)

        #expect(box.contains(CGPoint(x: 1, y: 1)))
    }

    @Test func defaultsToTheSlotRectangleWhenNoShapeIsStated() {
        #expect(ComponentBox(x: 0, y: 0).rect.size == ComponentBox.slotSize)
    }
}
