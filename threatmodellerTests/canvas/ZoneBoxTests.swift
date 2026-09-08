import CoreGraphics
import Testing
import ThreatModelKit
@testable import threatmodeller

struct ZoneBoxTests {
    private let box = ZoneBox(x: 100, y: 200, width: 600, height: 400)

    @Test func takesItsHeaderBandFromTheCore() {
        // The canvas and the core must agree, or a component would look
        // captured while scoring as though it were outside.
        // Compared as Double on both sides: `#expect` keeps the captured
        // operands' own types, so a CGFloat against a Double reads as unequal
        // even when both print the same number.
        #expect(Double(ZoneBox.headerHeight) == ZoneContainment.headerHeight)
        #expect(Double(ZoneBox.minimumSize.width) == Zone.minimumSize.width)
        #expect(Double(ZoneBox.minimumSize.height) == Zone.minimumSize.height)
    }

    @Test func splitsItselfIntoAHeaderAndAContentArea() {
        #expect(box.headerRect == CGRect(x: 100, y: 200, width: 600, height: ZoneBox.headerHeight))
        #expect(box.contentRect == CGRect(
            x: 100,
            y: 200 + ZoneBox.headerHeight,
            width: 600,
            height: 400 - ZoneBox.headerHeight
        ))
    }

    @Test func neverSplitsPastItsOwnBottom() {
        let squashed = ZoneBox(x: 0, y: 0, width: 600, height: 20)

        #expect(squashed.headerRect.height == 20)
        #expect(squashed.contentRect.height == 0)
    }

    @Test func knowsWhenAPointIsOnItsHeader() {
        #expect(box.containsHeader(CGPoint(x: 300, y: 210)))
        #expect(box.containsHeader(CGPoint(x: 300, y: 300)) == false)
        #expect(box.containsHeader(CGPoint(x: 50, y: 210)) == false)
    }

    @Test func putsAHandleOnEveryCornerAndEveryEdge() {
        #expect(ZoneHandle.allCases.count == 8)

        for handle in ZoneHandle.allCases {
            let rect = box.handleRect(handle)
            #expect(rect.width == ZoneBox.handleSize)
            #expect(rect.height == ZoneBox.handleSize)
            #expect(box.handle(at: CGPoint(x: rect.midX, y: rect.midY)) == handle)
        }
    }

    @Test func findsNoHandleAwayFromTheEdges() {
        #expect(box.handle(at: CGPoint(x: 400, y: 400)) == nil)
    }

    @Test func growsFromTheHandleTheUserDragged() {
        #expect(box.resized(by: CGSize(width: 50, height: 30), from: .bottomRight)
                == CGRect(x: 100, y: 200, width: 650, height: 430))

        #expect(box.resized(by: CGSize(width: -50, height: -30), from: .topLeft)
                == CGRect(x: 50, y: 170, width: 650, height: 430))
    }

    @Test func movesOnlyTheEdgeAnEdgeHandleOwns() {
        #expect(box.resized(by: CGSize(width: 40, height: 999), from: .right)
                == CGRect(x: 100, y: 200, width: 640, height: 400))

        #expect(box.resized(by: CGSize(width: 999, height: 40), from: .bottom)
                == CGRect(x: 100, y: 200, width: 600, height: 440))
    }

    @Test func stopsAtTheMinimumRatherThanTurningInsideOut() {
        let shrunk = box.resized(by: CGSize(width: -5000, height: -5000), from: .bottomRight)

        #expect(shrunk.width == ZoneBox.minimumSize.width)
        #expect(shrunk.height == ZoneBox.minimumSize.height)
        // The dragged corner stops; the opposite corner does not move.
        #expect(shrunk.minX == 100)
        #expect(shrunk.minY == 200)
    }

    @Test func stopsTheDraggedEdgeWhenTheTopLeftShrinksTooFar() {
        let shrunk = box.resized(by: CGSize(width: 5000, height: 5000), from: .topLeft)

        #expect(shrunk.width == ZoneBox.minimumSize.width)
        #expect(shrunk.height == ZoneBox.minimumSize.height)
        // The bottom-right corner is the one that stays put.
        #expect(shrunk.maxX == 700)
        #expect(shrunk.maxY == 600)
    }

    @Test func buildsItselfFromWhatTheCanvasWasGiven() {
        let viewed = ViewedZone(
            id: "z1",
            name: "Payments",
            customName: "Payments",
            networkZoneId: "private",
            networkTypeId: "vpc",
            riskReductionEnabled: true,
            riskReductionPercent: 20,
            x: 10,
            y: 20,
            width: 300,
            height: 200
        )

        #expect(ZoneBox(zone: viewed).rect == CGRect(x: 10, y: 20, width: 300, height: 200))
    }
}
