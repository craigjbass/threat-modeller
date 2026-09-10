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
        #expect(ThreatModelCodec.formatVersion == 5)
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

    @Test func carriesTheTechnologiesTheModelDefinesForItself() throws {
        let model = ThreatModel(
            customTechnologies: [
                CustomTechnology(
                    id: TechnologyId("custom-1"),
                    name: "Our Ledger",
                    category: CategoryId("database"),
                    description: "Keeps the balances",
                    threatIds: [ThreatId("t-sql-injection")],
                    enforcesEncryption: true
                )
            ]
        )

        #expect(try codec.decode(try codec.encode(model)) == model)
    }

    /// A version 1 file wrote `customTechnologies` as an empty list, so it
    /// still reads. A user's saved work does not stop opening.
    @Test func readsAFileFromTheVersionBefore() throws {
        var json = try #require(
            try JSONSerialization.jsonObject(with: try codec.encode(fullModel())) as? [String: Any]
        )
        json["formatVersion"] = 1
        json["customTechnologies"] = []
        let data = try JSONSerialization.data(withJSONObject: json)

        #expect(try codec.decode(data).name == "Payments")
    }

    @Test func carriesTheAnswersAndWhatCompensatesAThreat() throws {
        let key = ControlKey("component:c1:t:x")
        let model = ThreatModel(
            controlStatuses: [key: .accepted],
            compensatingControls: [
                ThreatKey("t@component:c1"): [
                    CompensatingControl(
                        label: "Watched by the SIEM",
                        reducesRiskBy: 40,
                        rationale: "It alerts on use."
                    )
                ]
            ]
        )

        let read = try codec.decode(try codec.encode(model))

        #expect(read.controlStatuses == model.controlStatuses)
        #expect(read.compensatingControls == model.compensatingControls)
        #expect(read.implementedControls.isEmpty)
    }

    /// A version 2 file has no statuses. Its recorded controls become
    /// `implemented`, so a user's saved work does not stop opening.
    @Test func readsAVersionTwoFileAsImplementedStatuses() throws {
        var json = try #require(
            try JSONSerialization.jsonObject(with: try codec.encode(fullModel())) as? [String: Any]
        )
        json["formatVersion"] = 2
        json["controlStatuses"] = nil
        json["compensatingControls"] = nil
        json.removeValue(forKey: "controlStatuses")
        json.removeValue(forKey: "compensatingControls")
        json["implementedControls"] = ["component:c1:t:x"]
        let data = try JSONSerialization.data(withJSONObject: json)

        let read = try codec.decode(data)

        #expect(read.implementedControls == [ControlKey("component:c1:t:x")])
        #expect(read.controlStatuses == [ControlKey("component:c1:t:x"): .implemented])
        #expect(read.compensatingControls.isEmpty)
    }

    @Test func refusesAFormatVersionItDoesNotKnow() throws {
        var json = try #require(
            try JSONSerialization.jsonObject(with: try codec.encode(ThreatModel())) as? [String: Any]
        )
        json["formatVersion"] = 99
        let data = try JSONSerialization.data(withJSONObject: json)

        #expect(throws: ThreatModelFileError.unsupportedFormatVersion(found: 99, supported: 5)) {
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

    @Test func refusesARunsAsValueTheVocabularyDoesNotHold() throws {
        var json = try #require(
            try JSONSerialization.jsonObject(with: try codec.encode(fullModel())) as? [String: Any]
        )
        var components = try #require(json["components"] as? [[String: Any]])
        components[0]["runsAs"] = "hypervisor"
        json["components"] = components

        #expect(throws: ThreatModelFileError.unknownValue(field: "runsAs", value: "hypervisor")) {
            try codec.decode(try JSONSerialization.data(withJSONObject: json))
        }
    }

    @Test func refusesAKindValueTheVocabularyDoesNotHold() throws {
        var json = try #require(
            try JSONSerialization.jsonObject(with: try codec.encode(fullModel())) as? [String: Any]
        )
        var connections = try #require(json["connections"] as? [[String: Any]])
        connections[0]["kind"] = "carrier-pigeon"
        json["connections"] = connections

        #expect(throws: ThreatModelFileError.unknownValue(field: "kind", value: "carrier-pigeon")) {
            try codec.decode(try JSONSerialization.data(withJSONObject: json))
        }
    }

    @Test func refusesABoundaryValueTheVocabularyDoesNotHold() throws {
        var json = try #require(
            try JSONSerialization.jsonObject(with: try codec.encode(fullModel())) as? [String: Any]
        )
        var zones = try #require(json["zones"] as? [[String: Any]])
        zones[0]["boundary"] = "orbit"
        json["zones"] = zones

        #expect(throws: ThreatModelFileError.unknownValue(field: "boundary", value: "orbit")) {
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
            .replacingOccurrences(of: "\"formatVersion\" : 5", with: "\"formatVersion\" : 99")

        #expect(throws: ThreatModelFileError.unsupportedFormatVersion(found: 99, supported: 5)) {
            try codec.decodeSelection(text)
        }
    }

    @Test func refusesClipboardTextThatIsNotASelection() {
        #expect(throws: (any Error).self) {
            try codec.decodeSelection("just some words someone copied")
        }
    }
}
