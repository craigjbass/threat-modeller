import Testing
import Foundation
import ThreatModelKit
import FileGateways
import TestSupport

struct DocumentFormatVersionFourTests {
    private func model() -> ThreatModel {
        ThreatModel(
            name: "S",
            components: [
                Component(
                    id: ComponentId("guard"),
                    technologyId: TechnologyId("aws-waf"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .internalData,
                    runsAs: .root,
                    assets: [Asset(name: "ssh-keys", sensitivity: .restricted)]
                ),
                Component(
                    id: ComponentId("store"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 200, y: 0),
                    sensitivity: .confidential
                )
            ],
            connections: [
                Connection(
                    id: ConnectionId("guard->store"),
                    source: ComponentId("guard"),
                    target: ComponentId("store"),
                    kind: .ipc,
                    description: "XPC call"
                )
            ],
            zones: [
                Zone(
                    id: ZoneId("root"),
                    rect: Rect(x: 0, y: 0, width: 400, height: 300),
                    boundary: .privilege,
                    description: "uid 0"
                )
            ],
            mitigatesEdges: [
                MitigatesEdge(
                    source: ComponentId("guard"),
                    target: ComponentId("store"),
                    threatIds: [ThreatId("credential-theft")],
                    reducesRiskBy: 80
                )
            ],
            recommendations: [
                ThreatKey(threatId: "credential-theft", sourceId: "component:store"):
                    [Recommendation(text: "Deny reads of /dev/rdisk**", note: "An endpoint rule.")]
            ]
        )
    }

    @Test func aRoundTripKeepsEveryNewValue() throws {
        let data = try ThreatModelCodec().encode(model())
        let read = try ThreatModelCodec().decode(data)

        #expect(read.connections.first?.kind == .ipc)
        #expect(read.connections.first?.description == "XPC call")
        #expect(read.components.first?.runsAs == .root)
        #expect(read.components.first?.assets == [Asset(name: "ssh-keys", sensitivity: .restricted)])
        #expect(read.zones.first?.boundary == .privilege)
        #expect(read.zones.first?.description == "uid 0")
        #expect(read.mitigatesEdges.first?.reducesRiskBy == 80)
        #expect(read.recommendations.values.first?.first?.text == "Deny reads of /dev/rdisk**")
    }

    @Test func theFormatVersionIsFour() throws {
        let data = try ThreatModelCodec().encode(model())
        let text = try #require(String(data: data, encoding: .utf8))
        #expect(text.contains("\"formatVersion\" : 4"))
    }

    @Test func aVersionThreeDocumentStillReads() throws {
        let text = """
        {
          "formatVersion" : 3,
          "name" : "S",
          "createdAt" : "1970-01-01T00:00:00Z",
          "updatedAt" : "1970-01-01T00:00:00Z",
          "components" : [],
          "connections" : [],
          "zones" : [],
          "customTechnologies" : [],
          "severityOverrides" : {},
          "implementedControls" : [],
          "pathwayMitigations" : { "isMasterEnabled" : false, "configs" : {} }
        }
        """
        let read = try ThreatModelCodec().decode(Data(text.utf8))
        #expect(read.name == "S")
        #expect(read.mitigatesEdges.isEmpty)
    }
}
