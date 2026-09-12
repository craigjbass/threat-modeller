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

    @Test func wrapsARowThatWouldRunTooWide() {
        let wide = (0 ..< 12).map { index in
            SourceZone(id: "z\(index)", components: [component("c\(index)")])
        }

        let response = layOut(ArchitectureSource(systemName: "P", zones: wide))

        // Each zone is 240 wide with a 60 gap, so four fit before the wrap.
        #expect(response.zones[3].y == response.zones[0].y)
        #expect(response.zones[4].y > response.zones[0].y)
        #expect(response.zones[4].x == 40)
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
}
