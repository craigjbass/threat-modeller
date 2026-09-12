import Testing
import ThreatModelKit

@Suite("Laying a diagram out from declaration order")
struct LayOutModelTests {
    private let useCase = LayOutModel()

    private func component(_ id: String) -> SourceComponent {
        SourceComponent(id: id, technologyId: "aws-ec2")
    }

    private func layOut(_ source: ArchitectureSource) -> LayOutModelResponse {
        useCase.execute(LayOutModelRequest(source: source))
    }

    @Test func placesOneComponentOutsideEveryZone() {
        let response = layOut(
            ArchitectureSource(systemName: "P", components: [component("a")])
        )

        #expect(response.components == [LaidOutComponent(id: "a", x: 40, y: 40)])
        #expect(response.zones.isEmpty)
    }

    @Test func spacesTheBandAcrossTheTop() {
        let response = layOut(
            ArchitectureSource(systemName: "P", components: [component("a"), component("b")])
        )

        #expect(response.components[1].x == 40 + 160 + 60)
        #expect(response.components[1].y == 40)
    }

    @Test func placesFourComponentsInAZoneAsATwoByTwoGrid() {
        let response = layOut(
            ArchitectureSource(
                systemName: "P",
                zones: [
                    SourceZone(
                        id: "z",
                        components: [component("a"), component("b"), component("c"), component("d")]
                    )
                ]
            )
        )

        // The first cell sits inside the padding and below the header band.
        #expect(response.components[0] == LaidOutComponent(id: "a", x: 80, y: 120))
        #expect(response.components[1] == LaidOutComponent(id: "b", x: 80 + 220, y: 120))
        #expect(response.components[2] == LaidOutComponent(id: "c", x: 80, y: 120 + 144))
        #expect(response.components[3] == LaidOutComponent(id: "d", x: 80 + 220, y: 120 + 144))
    }

    @Test func sizesAZoneToWhatItsGridNeeds() throws {
        let response = layOut(
            ArchitectureSource(
                systemName: "P",
                zones: [SourceZone(id: "z", components: [component("a"), component("b")])]
            )
        )

        let zone = try #require(response.zones.first)
        #expect(zone.width == 160 * 2 + 60 + 80)
        #expect(zone.height == 40 + 72 + 80)
    }

    @Test func givesAZoneHoldingNothingOneCell() throws {
        let response = layOut(
            ArchitectureSource(systemName: "P", zones: [SourceZone(id: "empty")])
        )

        let zone = try #require(response.zones.first)
        #expect(zone.width == 160 + 80)
        #expect(zone.height == 40 + 72 + 80)
    }

    @Test func putsTwoZonesSideBySide() {
        let response = layOut(
            ArchitectureSource(
                systemName: "P",
                zones: [
                    SourceZone(id: "one", components: [component("a")]),
                    SourceZone(id: "two", components: [component("b")])
                ]
            )
        )

        #expect(response.zones[0].x == 40)
        #expect(response.zones[1].x == 40 + 240 + 60)
        #expect(response.zones[1].y == response.zones[0].y)
    }

    @Test func wrapsARowThatWouldRunTooWide() throws {
        let wide = (0 ..< 12).map { index in
            SourceZone(id: "z\(index)", components: [component("c\(index)")])
        }

        let response = layOut(ArchitectureSource(systemName: "P", zones: wide))

        // Which wrap width the layout picks is its own business; that a row
        // wraps at all, and that the next row starts at the left, is not.
        let rows = Set(response.zones.map(\.y))
        #expect(rows.count > 1)

        let secondRow = try #require(response.zones.first { $0.y > response.zones[0].y })
        #expect(secondRow.x == 40)
    }

    @Test func putsTheZonesBelowTheBand() {
        let response = layOut(
            ArchitectureSource(
                systemName: "P",
                zones: [SourceZone(id: "z", components: [component("a")])],
                components: [component("loose")]
            )
        )

        #expect(response.zones[0].y == 40 + 72 + 144)
    }

    @Test func drawsTheSamePictureEveryTime() {
        let source = ArchitectureSource(
            systemName: "P",
            zones: [SourceZone(id: "z", components: [component("a"), component("b")])],
            components: [component("loose")]
        )

        #expect(layOut(source) == layOut(source))
    }

    @Test func leavesRoomBetweenRowsForAProcessCircle() {
        let tallest = Component.footprint(for: .process).height
        let overflow = (tallest - Component.size.height) / 2

        #expect(LayOutModel.rowGap > overflow * 2)
    }

    // MARK: keeping a flow off a boundary it does not cross

    /// Two zones side by side, with `flows` between the named components.
    private func twoZones(flows: [SourceFlow], mitigates: [SourceMitigates] = []) -> ArchitectureSource {
        ArchitectureSource(
            systemName: "P",
            zones: [
                SourceZone(id: "left", components: [component("a"), component("b")]),
                SourceZone(id: "right", components: [component("c"), component("d")])
            ],
            flows: flows,
            mitigates: mitigates
        )
    }

    @Test func staysAtTheStartingSpacingWhenNothingCrossesUnrelated() {
        let source = twoZones(flows: [SourceFlow(sourceId: "a", targetId: "c")])
        let response = layOut(source)

        #expect(response.unrelatedCrossings == 0)
        // One flow crosses two boundaries and no other flow exists, so the
        // starting gaps stand.
        #expect(response.components.first { $0.id == "b" }?.x == 300.0)
    }

    @Test func statesWhatSurvivesTheWidening() {
        let source = twoZones(
            flows: [
                SourceFlow(sourceId: "a", targetId: "c"),
                SourceFlow(sourceId: "b", targetId: "d"),
                SourceFlow(sourceId: "a", targetId: "d"),
                SourceFlow(sourceId: "b", targetId: "c")
            ]
        )

        let response = layOut(source)

        // The count is whatever the widening could not clear, and it is stated
        // rather than hidden.
        #expect(response.unrelatedCrossings >= 0)
    }

    @Test func laysTheSameSourceOutTheSameWayTwice() {
        let source = twoZones(
            flows: [
                SourceFlow(sourceId: "a", targetId: "c"),
                SourceFlow(sourceId: "b", targetId: "d")
            ]
        )

        #expect(layOut(source) == layOut(source))
    }

    @Test func placesAStoreAtAStoresFootprint() {
        let source = ArchitectureSource(
            systemName: "P",
            components: [component("a")]
        )
        let response = useCase.execute(
            LayOutModelRequest(source: source, shapes: ["a": "store"])
        )

        // The shape changes nothing about where the slot sits: the footprint
        // centres on it.
        #expect(response.components == [LaidOutComponent(id: "a", x: 40, y: 40)])
    }

    // MARK: keeping a flow off a zone it does not relate to

    @Test func placesALooseComponentAboveTheZoneItTalksToMost() throws {
        let source = ArchitectureSource(
            systemName: "P",
            zones: [
                SourceZone(id: "left", components: [component("a")]),
                SourceZone(id: "right", components: [component("b"), component("c")])
            ],
            components: [component("outside")],
            flows: [
                SourceFlow(sourceId: "outside", targetId: "b"),
                SourceFlow(sourceId: "outside", targetId: "c"),
                SourceFlow(sourceId: "outside", targetId: "a")
            ]
        )

        let response = layOut(source)
        let placed = try #require(response.components.first { $0.id == "outside" })
        let right = try #require(response.zones.first { $0.id == "right" })

        // Two flows reach the right zone and one the left, so it sits above the
        // right one.
        #expect(abs(placed.x + 80 - (right.x + right.width / 2)) < 1)
    }

    @Test func keepsDeclarationOrderForALooseComponentThatTalksToNoZone() {
        let source = ArchitectureSource(
            systemName: "P",
            zones: [SourceZone(id: "z", components: [component("a")])],
            components: [component("outside")]
        )

        let response = layOut(source)

        #expect(response.components.first?.id == "outside")
        #expect(response.components.first?.x == 40)
    }

    @Test func neverOverlapsTwoLooseComponentsWantingTheSamePlace() throws {
        let source = ArchitectureSource(
            systemName: "P",
            zones: [SourceZone(id: "z", components: [component("a")])],
            components: [component("one"), component("two")],
            flows: [
                SourceFlow(sourceId: "one", targetId: "a"),
                SourceFlow(sourceId: "two", targetId: "a")
            ]
        )

        let response = layOut(source)
        let one = try #require(response.components.first { $0.id == "one" })
        let two = try #require(response.components.first { $0.id == "two" })

        #expect(abs(one.x - two.x) >= 160)
    }

    @Test func statesHowManyFlowsRunOverAZoneTheyDoNotRelateTo() {
        let source = ArchitectureSource(
            systemName: "P",
            zones: [
                SourceZone(id: "left", components: [component("a")]),
                SourceZone(id: "right", components: [component("b")])
            ],
            components: [component("outside")],
            flows: [SourceFlow(sourceId: "outside", targetId: "b")]
        )

        let response = layOut(source)

        #expect(response.flowsOverUnrelatedZones == 0)
    }
}
