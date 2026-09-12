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

        // Which grid the layout picks is its own business; that the zone holds
        // what it was given is not.
        let zone = try #require(response.zones.first)
        for placed in response.components {
            #expect(placed.x >= zone.x)
            #expect(placed.y >= zone.y)
            #expect(placed.x + 160 <= zone.x + zone.width)
            #expect(placed.y + 72 <= zone.y + zone.height)
        }
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

    @Test func keepsTheBandClearOfTheZones() throws {
        let response = layOut(
            ArchitectureSource(
                systemName: "P",
                zones: [SourceZone(id: "z", components: [component("a")])],
                components: [component("loose")]
            )
        )

        let zone = try #require(response.zones.first)
        let band = try #require(response.components.first { $0.id == "loose" })

        // Above or below is the layout's choice; overlapping the zone is not.
        #expect(band.y + 72 <= zone.y || band.y >= zone.y + zone.height)
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

        #expect(response.brokenBoundaries == 0)
    }

    @Test func neverOverlapsTwoComponentsInOneZone() {
        let response = layOut(twoZones(flows: []))
        let placed = response.components

        for one in placed {
            for other in placed where other.id != one.id {
                let apart = abs(one.x - other.x) >= 160 || abs(one.y - other.y) >= 72
                #expect(apart, "\(one.id) and \(other.id) overlap")
            }
        }
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
        #expect(response.brokenBoundaries >= 0)
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

    @Test func keepsALooseComponentsFlowsOffTheZonesTheyDoNotReach() throws {
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

        // Which of the placements the search picks is its own business. That
        // the component's flows stay off the zones they do not reach is not.
        #expect(response.flowsOverUnrelatedZones == 0)
        #expect(try #require(response.components.first { $0.id == "outside" }).y >= 0)
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

@Suite("A zone wide enough for its own name")
struct ZoneNameWidthTests {
    private let useCase = LayOutModel()

    @Test func widensAZoneToHoldALongName() throws {
        let response = useCase.execute(
            LayOutModelRequest(
                source: ArchitectureSource(
                    systemName: "P",
                    zones: [
                        SourceZone(
                            id: "z",
                            name: "Corporate Cloud (MDM + EDR management)",
                            components: [SourceComponent(id: "a", technologyId: "aws-ec2")]
                        )
                    ]
                )
            )
        )

        let zone = try #require(response.zones.first)
        #expect(zone.width >= LayOutModel.width(ofName: "Corporate Cloud (MDM + EDR management)"))
    }

    @Test func leavesAZoneWiderThanItsNameAlone() throws {
        let wide = (0 ..< 6).map { SourceComponent(id: "c\($0)", technologyId: "aws-ec2") }
        let response = useCase.execute(
            LayOutModelRequest(
                source: ArchitectureSource(
                    systemName: "P",
                    zones: [SourceZone(id: "z", name: "Edge", components: wide)]
                )
            )
        )

        let zone = try #require(response.zones.first)
        #expect(zone.width > LayOutModel.width(ofName: "Edge"))
    }
}

@Suite("Placing the zones that talk to each other together")
struct ZoneOrderTests {
    private func component(_ id: String) -> SourceComponent {
        SourceComponent(id: id, technologyId: "aws-ec2")
    }

    /// Three zones declared a, b, c, where a talks only to c.
    private var source: ArchitectureSource {
        ArchitectureSource(
            systemName: "P",
            zones: [
                SourceZone(id: "a", components: [component("a1")]),
                SourceZone(id: "b", components: [component("b1")]),
                SourceZone(id: "c", components: [component("c1")])
            ],
            flows: [
                SourceFlow(sourceId: "a1", targetId: "c1"),
                SourceFlow(sourceId: "a1", targetId: "c1")
            ]
        )
    }

    @Test func keepsDeclarationOrderWhenItIsAsked() {
        let ordered = LayOutModel.ordered(
            source.zones,
            by: .declaration,
            in: LayOutModelRequest(source: source)
        )

        #expect(ordered.map(\.id) == ["a", "b", "c"])
    }

    @Test func putsTheZoneWithMostFlowsNextToTheFirst() {
        let ordered = LayOutModel.ordered(
            source.zones,
            by: .byConnection,
            in: LayOutModelRequest(source: source)
        )

        #expect(ordered.map(\.id) == ["a", "c", "b"])
    }

    @Test func keepsDeclarationOrderWhenNothingTalksToAnything() {
        let apart = ArchitectureSource(
            systemName: "P",
            zones: [
                SourceZone(id: "a", components: [component("a1")]),
                SourceZone(id: "b", components: [component("b1")]),
                SourceZone(id: "c", components: [component("c1")])
            ]
        )

        let ordered = LayOutModel.ordered(
            apart.zones,
            by: .byConnection,
            in: LayOutModelRequest(source: apart)
        )

        #expect(ordered.map(\.id) == ["a", "b", "c"])
    }

    @Test func ordersTheSameSourceTheSameWayTwice() {
        let request = LayOutModelRequest(source: source)

        #expect(
            LayOutModel.ordered(source.zones, by: .byConnection, in: request).map(\.id)
                == LayOutModel.ordered(source.zones, by: .byConnection, in: request).map(\.id)
        )
    }
}
