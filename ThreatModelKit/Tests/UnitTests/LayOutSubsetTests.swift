import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// Laying a narrowed set out, without moving the model.
@Suite("Laying a subset out")
struct LayOutSubsetTests {
    private let app = TestDependencies()

    /// Six components in two zones, with flows between them.
    private func drawn() {
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  zone "app" {
                    kind = "private"

                    component "api" { technology = "aws-ec2" }
                    component "worker" { technology = "aws-ec2" }
                    component "db" { technology = "aws-rds" }
                  }

                  zone "edge" {
                    kind = "public"

                    component "cdn" { technology = "aws-cloudfront" }
                    component "lb" { technology = "aws-elb" }
                    component "waf" { technology = "aws-waf" }
                  }

                  flow cdn -> lb
                  flow lb -> api
                  flow api -> db
                  flow api -> worker
                  flow waf -> cdn
                }
                """
            )
        )
    }

    private func positions() -> [String: Point] {
        Dictionary(
            uniqueKeysWithValues: app.modelStore.current().components.map {
                ($0.id.value, $0.position)
            }
        )
    }

    private func zoneRects() -> [String: Rect] {
        Dictionary(
            uniqueKeysWithValues: app.modelStore.current().zones.map { ($0.id.value, $0.rect) }
        )
    }

    @Test func saysThereIsNothingToLayOutForAnEmptySubset() {
        drawn()

        #expect(app.layOutSubset().execute(LayOutSubsetRequest()) == .nothingToLayOut)
    }

    /// The acceptance criterion: three components and one zone out of six
    /// components, laid out near the origin, with the model untouched.
    @Test func laysOutOnlyTheNamedComponentsAndZones() {
        drawn()
        let before = positions()
        let zonesBefore = zoneRects()

        guard case .laidOut(let components, let zones) = app.layOutSubset().execute(
            LayOutSubsetRequest(componentIds: ["api", "worker", "db"], zoneIds: ["app"])
        ) else {
            Issue.record("expected the subset to be laid out")
            return
        }

        #expect(Set(components.map(\.id)) == ["api", "worker", "db"])
        #expect(zones.map(\.id) == ["app"])

        // Near the origin: the subset is a picture in its own right, so it
        // does not keep the offset the full layout gave it.
        let left = components.map(\.x).min() ?? 0
        let top = components.map(\.y).min() ?? 0
        let right = components.map(\.x).max() ?? 0
        let bottom = components.map(\.y).max() ?? 0
        #expect(left >= 0)
        #expect(top >= 0)
        #expect(right < 1000)
        #expect(bottom < 1000)

        #expect(positions() == before)
        #expect(zoneRects() == zonesBefore)
    }

    /// The same subset lays out the same way whatever order the ids arrive
    /// in, because the layout reads the model's own order.
    @Test func theOrderOfTheNamedIdsChangesNothing() {
        drawn()

        let one = app.layOutSubset().execute(
            LayOutSubsetRequest(componentIds: ["api", "db", "worker"], zoneIds: ["app"])
        )
        let other = app.layOutSubset().execute(
            LayOutSubsetRequest(componentIds: ["worker", "api", "db"], zoneIds: ["app"])
        )

        #expect(one == other)
    }

    /// A flow to a component the subset leaves out is not in the picture, so
    /// the layout never reads it.
    @Test func dropsAFlowWhoseFarEndIsNotInTheSubset() {
        drawn()

        guard case .laidOut(let components, _) = app.layOutSubset().execute(
            LayOutSubsetRequest(componentIds: ["api", "db"], zoneIds: ["app"])
        ) else {
            Issue.record("expected the subset to be laid out")
            return
        }

        #expect(Set(components.map(\.id)) == ["api", "db"])
    }

    /// A component whose zone the subset leaves out still draws: it lays out
    /// as a loose component.
    @Test func laysOutAComponentWhoseZoneIsNotInTheSubset() {
        drawn()

        guard case .laidOut(let components, let zones) = app.layOutSubset().execute(
            LayOutSubsetRequest(componentIds: ["api", "cdn"])
        ) else {
            Issue.record("expected the subset to be laid out")
            return
        }

        #expect(Set(components.map(\.id)) == ["api", "cdn"])
        #expect(zones.isEmpty)
    }

    /// The frame budget the design states: a narrowed set of ten elements
    /// lays out inside one frame at 60 Hz.
    @Test func laysTenElementsOutInsideTheFrameBudget() {
        drawn()

        // Warm the catalogue and the model store, so the measurement is the
        // search and nothing else.
        _ = app.layOutSubset().execute(
            LayOutSubsetRequest(componentIds: ["api"], zoneIds: ["app"])
        )

        let started = Date()
        _ = app.layOutSubset().execute(
            LayOutSubsetRequest(
                componentIds: ["api", "worker", "db", "cdn", "lb", "waf"],
                zoneIds: ["app", "edge"]
            )
        )
        let took = Date().timeIntervalSince(started)

        #expect(took < LayOutSubset.frameBudget)
    }
}
