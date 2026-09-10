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
            compensatingControls: [
                ThreatKey(threatId: "credential-theft", sourceId: "component:store"):
                    [
                        CompensatingControl(
                            label: "hardware-bound key",
                            reducesRiskBy: 40,
                            rationale: "the key never leaves the Secure Enclave",
                            sources: ["https://example.internal/adr/17"]
                        )
                    ]
            ],
            mitigatesEdges: [
                MitigatesEdge(
                    source: ComponentId("guard"),
                    target: ComponentId("store"),
                    threatIds: [ThreatId("credential-theft")],
                    reducesRiskBy: 80,
                    status: .assumed
                )
            ],
            recommendations: [
                ThreatKey(threatId: "credential-theft", sourceId: "component:store"):
                    [
                        Recommendation(
                            text: "Deny reads of /dev/rdisk**",
                            note: "An endpoint rule.",
                            sources: ["https://attack.mitre.org/techniques/T1218/"]
                        )
                    ]
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

    /// D1: an edge's `status`, a compensating control's `sources` and a
    /// recommendation's `sources` are carried whole through a round trip. A
    /// codec that dropped `status` would turn an assumed edge into an
    /// adopted one, and lower the model's residual score on the next open.
    @Test func aRoundTripKeepsTheEdgeStatusAndEverySourcesList() throws {
        let data = try ThreatModelCodec().encode(model())
        let read = try ThreatModelCodec().decode(data)

        #expect(read.mitigatesEdges.first?.status == .assumed)
        #expect(
            read.compensatingControls.values.first?.first?.sources
                == ["https://example.internal/adr/17"]
        )
        #expect(
            read.recommendations.values.first?.first?.sources
                == ["https://attack.mitre.org/techniques/T1218/"]
        )
    }

    /// An edge with no stated status carries no status, and reads back with
    /// none: a file written before `status` existed keeps its numbers,
    /// unchanged, on the next save, and still scores as an adopted edge.
    @Test func anEdgeWithNoStatusWritesNoStatusKey() throws {
        let noStatus = ThreatModel(
            name: "S",
            mitigatesEdges: [
                MitigatesEdge(
                    source: ComponentId("guard"),
                    target: ComponentId("store"),
                    threatIds: [ThreatId("credential-theft")],
                    reducesRiskBy: 80
                )
            ]
        )

        let data = try ThreatModelCodec().encode(noStatus)
        let text = try #require(String(data: data, encoding: .utf8))
        #expect(text.contains("\"status\"") == false)

        let read = try ThreatModelCodec().decode(data)
        #expect(read.mitigatesEdges.first?.status == nil)
        #expect(read.mitigatesEdges.first?.effectiveStatus == .adopted)
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

    /// A version 3 document holds one component, one connection and one zone,
    /// none carrying any of the version 4 keys. Every version 4 value defaults,
    /// and every value the version 3 document did carry comes back unchanged.
    @Test func aVersionThreeDocumentWithItemsStillReadsThemAtTheirDefaults() throws {
        let text = """
        {
          "formatVersion" : 3,
          "name" : "S",
          "createdAt" : "1970-01-01T00:00:00Z",
          "updatedAt" : "1970-01-01T00:00:00Z",
          "components" : [
            {
              "id" : "guard",
              "technologyId" : "aws-waf",
              "x" : 10,
              "y" : 20,
              "sensitivity" : "confidential",
              "customName" : "Edge guard",
              "threatsDisabled" : false
            }
          ],
          "connections" : [
            { "id" : "guard->store", "source" : "guard", "target" : "store" }
          ],
          "zones" : [
            {
              "id" : "root",
              "x" : 0,
              "y" : 0,
              "width" : 400,
              "height" : 300,
              "name" : "Root zone",
              "networkZone" : "private",
              "networkType" : "vpc",
              "riskReductionEnabled" : true,
              "riskReductionPercent" : 35
            }
          ],
          "customTechnologies" : [],
          "severityOverrides" : {},
          "implementedControls" : [],
          "pathwayMitigations" : { "isMasterEnabled" : false, "configs" : {} }
        }
        """
        let read = try ThreatModelCodec().decode(Data(text.utf8))

        let component = try #require(read.components.first)
        #expect(component.runsAs == .user)
        #expect(component.assets.isEmpty)
        #expect(component.position == Point(x: 10, y: 20))
        #expect(component.sensitivity == .confidential)
        #expect(component.customName == "Edge guard")

        let connection = try #require(read.connections.first)
        #expect(connection.kind == .network)
        #expect(connection.description == nil)

        let zone = try #require(read.zones.first)
        #expect(zone.boundary == .network)
        #expect(zone.description == nil)
        #expect(zone.rect == Rect(x: 0, y: 0, width: 400, height: 300))
        #expect(zone.networkZone == .privateZone)
        #expect(zone.networkType == .vpc)
        #expect(zone.riskReductionEnabled == true)
        #expect(zone.riskReductionPercent == 35)

        #expect(read.mitigatesEdges.isEmpty)
        #expect(read.recommendations.isEmpty)
    }
}
