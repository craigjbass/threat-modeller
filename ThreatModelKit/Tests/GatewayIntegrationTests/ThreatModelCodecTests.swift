import Foundation
import Testing
import ThreatModelKit
import FileGateways

struct ThreatModelCodecTests {
    private let codec = ThreatModelCodec()

    private func fullModel() -> ThreatModel {
        ThreatModel(
            name: "Payments",
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 100, y: 200),
                    sensitivity: .confidential,
                    customName: "Web tier",
                    threatsDisabled: true
                ),
                Component(
                    id: ComponentId("c2"),
                    technologyId: TechnologyId("aws-rds"),
                    position: Point(x: 500, y: 200),
                    sensitivity: .restricted
                )
            ],
            connections: [
                Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c2"))
            ],
            zones: [
                Zone(
                    id: ZoneId("z1"),
                    rect: Rect(x: 0, y: 0, width: 600, height: 500),
                    name: "Payments VPC",
                    networkZone: .privateZone,
                    networkType: .vpc,
                    riskReductionEnabled: true,
                    riskReductionPercent: 35
                )
            ],
            severityOverrides: [
                SeverityOverrideKey("aws-ec2::credential-theft"): "low"
            ],
            implementedControls: [ControlKey("node:c1:credential-theft::0002b606")],
            pathwayMitigations: PathwayMitigationSettings(
                isMasterEnabled: true,
                configs: [
                    PathwayMitigationId("waf-protection"):
                        PathwayMitigationConfig(isEnabled: false, mode: .remove, reductionPercent: 80)
                ]
            ),
            createdAt: Date(timeIntervalSince1970: 1_000_000),
            updatedAt: Date(timeIntervalSince1970: 2_000_000),
            catalogueVersion: CatalogueVersion(repository: "jib1337/threat-model-library", tag: "v1.0.1")
        )
    }

    @Test func carriesEverythingThroughARoundTrip() throws {
        let original = fullModel()

        let read = try codec.decode(try codec.encode(original))

        #expect(read == original)
    }

    @Test func carriesAnEmptyModelThrough() throws {
        let empty = ThreatModel()

        #expect(try codec.decode(try codec.encode(empty)) == empty)
    }

    @Test func writesTheFormatVersionAndTheCatalogueStamp() throws {
        let data = try codec.encode(fullModel())
        let json = try #require(
            try JSONSerialization.jsonObject(with: data) as? [String: Any]
        )

        #expect(json["formatVersion"] as? Int == ThreatModelCodec.formatVersion)
        #expect(ThreatModelCodec.formatVersion == 1)
        let catalogue = try #require(json["catalogue"] as? [String: Any])
        #expect(catalogue["tag"] as? String == "v1.0.1")
        #expect(json["customTechnologies"] as? [Any] != nil)
    }

    @Test func writesSomethingAPersonCanRead() throws {
        let text = try #require(String(data: try codec.encode(fullModel()), encoding: .utf8))

        // A threat model is a document a team reviews in a pull request, so the
        // file is pretty-printed with stable key order.
        #expect(text.contains("\n"))
        #expect(text.contains("\"name\" : \"Payments\""))
    }

    @Test func refusesAFormatVersionItDoesNotKnow() throws {
        var json = try #require(
            try JSONSerialization.jsonObject(with: try codec.encode(ThreatModel())) as? [String: Any]
        )
        json["formatVersion"] = 99
        let data = try JSONSerialization.data(withJSONObject: json)

        #expect(throws: ThreatModelFileError.unsupportedFormatVersion(found: 99, supported: 1)) {
            try codec.decode(data)
        }
    }

    @Test func refusesBytesThatAreNotAThreatModel() {
        #expect(throws: (any Error).self) {
            try codec.decode(Data("not a threat model".utf8))
        }
    }

    @Test func refusesAValueTheVocabularyDoesNotHold() throws {
        var json = try #require(
            try JSONSerialization.jsonObject(with: try codec.encode(fullModel())) as? [String: Any]
        )
        var zones = try #require(json["zones"] as? [[String: Any]])
        zones[0]["networkType"] = "mainframe"
        json["zones"] = zones

        #expect(throws: ThreatModelFileError.unknownValue(field: "networkType", value: "mainframe")) {
            try codec.decode(try JSONSerialization.data(withJSONObject: json))
        }
    }

    private func snippet() -> SelectionSnippet {
        SelectionSnippet(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 10, y: 20),
                    sensitivity: .restricted,
                    customName: "Web tier",
                    threatsDisabled: true
                )
            ],
            connections: [
                Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c1"))
            ],
            zones: [
                Zone(id: ZoneId("z1"), rect: Rect(x: 0, y: 0, width: 400, height: 300), name: "Edge")
            ]
        )
    }

    @Test func carriesASelectionThroughARoundTrip() throws {
        let original = snippet()

        #expect(try codec.decodeSelection(try codec.encodeSelection(original)) == original)
    }

    @Test func carriesAnEmptySelectionThrough() throws {
        let empty = SelectionSnippet(components: [], connections: [], zones: [])

        #expect(try codec.decodeSelection(try codec.encodeSelection(empty)) == empty)
        #expect(empty.isEmpty)
    }

    @Test func putsASelectionOnTheClipboardAsSomethingAPersonCanRead() throws {
        let text = try codec.encodeSelection(snippet())

        #expect(text.contains("\"formatVersion\""))
        #expect(text.contains("\"aws-ec2\""))
    }

    @Test func refusesASnippetFromAVersionItDoesNotKnow() throws {
        let text = try codec.encodeSelection(snippet())
            .replacingOccurrences(of: "\"formatVersion\" : 1", with: "\"formatVersion\" : 99")

        #expect(throws: ThreatModelFileError.unsupportedFormatVersion(found: 99, supported: 1)) {
            try codec.decodeSelection(text)
        }
    }

    @Test func refusesClipboardTextThatIsNotASelection() {
        #expect(throws: (any Error).self) {
            try codec.decodeSelection("just some words someone copied")
        }
    }
}
