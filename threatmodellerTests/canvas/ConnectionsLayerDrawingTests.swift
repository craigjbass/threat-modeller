import AppKit
import CoreGraphics
import SwiftUI
import Testing
import ThreatModelKit
@testable import threatmodeller

/// The band every zone's name sits in, and the stroke each flow draws,
/// stated as values a test reads without a rendered picture.
@MainActor
struct ConnectionsLayerDrawingTests {
    // MARK: building a model

    private func zone(
        _ id: String,
        x: Double,
        y: Double,
        width: Double,
        height: Double
    ) -> ViewedZone {
        ViewedZone(
            id: id,
            name: id,
            customName: nil,
            networkZoneId: "private",
            networkTypeId: "generic",
            riskReductionEnabled: false,
            riskReductionPercent: 0,
            x: x,
            y: y,
            width: width,
            height: height
        )
    }

    private func component(
        _ id: String,
        x: Double,
        y: Double,
        zoneId: String? = nil
    ) -> ViewedComponent {
        ViewedComponent(
            id: id,
            technologyId: "aws-ec2",
            name: "EC2",
            customName: nil,
            providerId: "aws",
            categoryId: "compute",
            x: x,
            y: y,
            sensitivityId: "internal",
            threatsDisabled: false,
            isUnknownTechnology: false,
            zoneId: zoneId
        )
    }

    private func link(
        _ id: String,
        _ source: String,
        _ target: String,
        described: String? = nil,
        isUse: Bool = false
    ) -> ViewedConnection {
        ViewedConnection(
            id: id,
            sourceComponentId: source,
            targetComponentId: target,
            description: described,
            isUse: isUse
        )
    }

    private func aLayer(
        connections: [ViewedConnection] = [],
        components: [ViewedComponent] = [],
        zones: [ViewedZone] = [],
        risks: [String: ElementRisk] = [:],
        guards: [String: [EdgeGuard]] = [:],
        outOfScopeComponentIds: Set<String> = []
    ) -> ConnectionsLayer {
        ConnectionsLayer(
            origin: .zero,
            connections: connections,
            boxes: CanvasHitTest.boxes(for: components, selected: [], dragTranslation: .zero),
            componentsById: Dictionary(uniqueKeysWithValues: components.map { ($0.id, $0) }),
            zones: zones,
            risks: risks,
            guards: guards,
            outOfScopeComponentIds: outOfScopeComponentIds,
            selectedConnectionIds: [],
            preview: nil
        )
    }

    // MARK: bandRects

    @Test func bandRectsGivesOneRectanglePerZoneAtTheZonesOriginWidthAndHeaderHeight() {
        let layer = aLayer(zones: [
            zone("z1", x: 10, y: 20, width: 300, height: 200),
            zone("z2", x: 500, y: 5, width: 150, height: 90)
        ])

        #expect(layer.bandRects == [
            Rect(x: 10, y: 20, width: 300, height: Double(ZoneBox.headerHeight)),
            Rect(x: 500, y: 5, width: 150, height: Double(ZoneBox.headerHeight))
        ])
    }

    // MARK: no callout and no guard chip overlaps a zone band

    private func overlaps(_ first: Rect, _ second: Rect) -> Bool {
        first.minX < second.maxX && second.minX < first.maxX
            && first.minY < second.maxY && second.minY < first.maxY
    }

    /// A source well above a zone and a target well inside it, so the flow's
    /// curve runs down through the zone's name band on its way to the
    /// target.
    @Test func noCalloutAndNoGuardChipOverlapsAZoneBandOnAModelWhoseFlowsCrossAZoneHeader() {
        let boundedZone = zone("z1", x: 0, y: 150, width: 400, height: 300)
        let components = [
            component("source", x: 100, y: 0),
            component("target", x: 100, y: 300, zoneId: "z1")
        ]
        let connections = [link("k1", "source", "target")]
        let layer = aLayer(
            connections: connections,
            components: components,
            zones: [boundedZone],
            guards: ["connection:k1": [EdgeGuard(label: "WAF", isAssumed: false)]]
        )
        let geometry = FlowGeometry.of(
            connections: connections,
            boxes: CanvasHitTest.boxes(for: components, selected: [], dragTranslation: .zero),
            componentsById: Dictionary(uniqueKeysWithValues: components.map { ($0.id, $0) }),
            zones: [boundedZone],
            guards: ["connection:k1": [EdgeGuard(label: "WAF", isAssumed: false)]],
            risks: [:],
            outOfScopeComponentIds: []
        )

        #expect(geometry.runs.isEmpty == false, "the flow crossed no boundary to test against")
        #expect(geometry.chipRects.isEmpty == false, "the boundary wrote no guard chip to test")
        #expect(geometry.callouts.isEmpty == false, "the flow wrote no callout to test")

        for chip in geometry.chipRects {
            #expect(
                layer.bandRects.contains { overlaps($0, chip) } == false,
                "a guard chip overlapped a zone band"
            )
        }
        for callout in geometry.callouts {
            #expect(
                layer.bandRects.contains { overlaps($0, callout.rect) } == false,
                "a callout overlapped a zone band"
            )
        }
    }

    // MARK: the stroke each flow takes

    @Test func aUseLinkAFlowOutOfScopeAndAFlowInScopeEachTakeTheirOwnStroke() {
        let layer = aLayer(outOfScopeComponentIds: ["out"])

        #expect(layer.strokeKind(of: link("u1", "a", "b", isUse: true)) == .dotted)
        #expect(layer.strokeKind(of: link("f1", "out", "b")) == .dashed)
        #expect(layer.strokeKind(of: link("f2", "a", "b")) == .plain)
    }

    @Test func aUseLinkCarriesNoRiskColour() {
        let use = link("u1", "a", "b", isUse: true)
        let layer = aLayer(
            connections: [use],
            risks: [
                "connection:u1": ElementRisk(
                    sourceId: "connection:u1",
                    openCount: 3,
                    totalCount: 3,
                    highestLevelId: "critical"
                )
            ]
        )

        #expect(layer.colourForTesting(use) == .secondary)
    }

    // MARK: painting order

    /// The image a view draws at a stated size, or nil.
    private func drawn(_ view: some View, width: Double, height: Double) -> NSBitmapImageRep? {
        let renderer = ImageRenderer(content: view.frame(width: width, height: height))
        renderer.scale = 1
        guard let image = renderer.cgImage else { return nil }
        return NSBitmapImageRep(cgImage: image)
    }

    /// True when every pixel of the two images matches within `tolerance` on
    /// every channel. A size mismatch, or a missing bitmap, is never a
    /// match.
    private func pixelsMatch(
        _ first: NSBitmapImageRep,
        _ second: NSBitmapImageRep,
        tolerance: Int = 4
    ) -> Bool {
        guard first.pixelsWide == second.pixelsWide,
            first.pixelsHigh == second.pixelsHigh,
            first.bytesPerRow == second.bytesPerRow,
            let bytesA = first.bitmapData,
            let bytesB = second.bitmapData
        else { return false }

        let count = first.bytesPerRow * first.pixelsHigh
        for offset in 0 ..< count {
            if abs(Int(bytesA[offset]) - Int(bytesB[offset])) > tolerance { return false }
        }
        return true
    }

    /// Three flows, each crossing its own zone's boundary with a guard chip
    /// and a label, spaced apart so none reaches another's chip or label.
    private func threeCrossingFlows(order: [String]) -> ConnectionsLayer {
        let zones = [
            zone("z1", x: 0, y: 150, width: 250, height: 300),
            zone("z2", x: 400, y: 150, width: 250, height: 300),
            zone("z3", x: 800, y: 150, width: 250, height: 300)
        ]
        let components = [
            component("a1", x: 40, y: 0), component("a2", x: 40, y: 300, zoneId: "z1"),
            component("b1", x: 440, y: 0), component("b2", x: 440, y: 300, zoneId: "z2"),
            component("c1", x: 840, y: 0), component("c2", x: 840, y: 300, zoneId: "z3")
        ]
        let byId: [String: ViewedConnection] = [
            "k1": link("k1", "a1", "a2", described: "Alpha flow"),
            "k2": link("k2", "b1", "b2", described: "Bravo flow"),
            "k3": link("k3", "c1", "c2", described: "Charlie flow")
        ]
        let connections = order.compactMap { byId[$0] }
        let guards: [String: [EdgeGuard]] = [
            "connection:k1": [EdgeGuard(label: "WAF-A", isAssumed: false)],
            "connection:k2": [EdgeGuard(label: "WAF-B", isAssumed: false)],
            "connection:k3": [EdgeGuard(label: "WAF-C", isAssumed: false)]
        ]

        return aLayer(connections: connections, components: components, zones: zones, guards: guards)
    }

    @Test func chipsAndLabelsDrawTheSamePixelsWhicheverOrderThreeCrossingFlowsSitIn() throws {
        let forward = try #require(
            drawn(threeCrossingFlows(order: ["k1", "k2", "k3"]), width: 1100, height: 600)
        )
        let reversed = try #require(
            drawn(threeCrossingFlows(order: ["k3", "k2", "k1"]), width: 1100, height: 600)
        )
        let rotated = try #require(
            drawn(threeCrossingFlows(order: ["k2", "k3", "k1"]), width: 1100, height: 600)
        )

        #expect(pixelsMatch(forward, reversed), "the reversed order drew different pixels")
        #expect(pixelsMatch(forward, rotated), "the rotated order drew different pixels")
    }
}
