import CoreGraphics
import Testing
@testable import threatmodeller

struct ComponentBoxTests {
    @Test func placesItsRectangleAtTheComponentPosition() {
        let box = ComponentBox(x: 100, y: 50)

        #expect(box.rect.origin == CGPoint(x: 100, y: 50))
        #expect(box.rect.size == ComponentBox.size)
    }

    @Test func findsItsOwnCentre() {
        let box = ComponentBox(x: 0, y: 0)

        #expect(box.centre == CGPoint(x: ComponentBox.size.width / 2, y: ComponentBox.size.height / 2))
    }

    @Test func containsAPointInsideIt() {
        let box = ComponentBox(x: 10, y: 10)

        #expect(box.contains(CGPoint(x: 20, y: 20)))
        #expect(box.contains(CGPoint(x: 9, y: 20)) == false)
        #expect(box.contains(CGPoint(x: 20, y: 10 + ComponentBox.size.height + 1)) == false)
    }
}
