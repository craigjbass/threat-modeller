import Testing
import Foundation
import ThreatModelKit
import FileGateways
import TestSupport

/// Version 6 adds the action an assumed edge carries. A version 5 file has
/// none, and its edges keep their numbers.
struct DocumentFormatVersionSixTests {
    private func model() -> ThreatModel {
        var model = ThreatModel(name: "Payments")
        model.mitigatesEdges = [
            MitigatesEdge(
                source: ComponentId("guard"),
                target: ComponentId("store"),
                threatIds: [ThreatId("credential-theft")],
                status: .proposed,
                action: EdgeAction(
                    label: "adopt-the-guard",
                    text: "Adopt the guard",
                    note: "It is bought and not deployed.",
                    blockedBy: "guard-not-deployed",
                    sources: ["https://example.com/ticket/1"]
                )
            ),
            MitigatesEdge(
                source: ComponentId("guard"),
                target: ComponentId("queue"),
                threatIds: [ThreatId("credential-theft")],
                status: .proposed
            )
        ]
        return model
    }

    /// The version moves with the format. Version 7 adds the zone a
    /// component sits in, and the fields this suite covers are unchanged.
    @Test func writesTheCurrentVersion() throws {
        let data = try ThreatModelCodec().encode(model())

        let read = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(read["formatVersion"] as? Int == ThreatModelCodec.formatVersion)
    }

    @Test func readsBackEveryEdgeWithAndWithoutAnAction() throws {
        let written = try ThreatModelCodec().encode(model())

        let back = try ThreatModelCodec().decode(written)

        #expect(back.mitigatesEdges[0].action?.label == "adopt-the-guard")
        #expect(back.mitigatesEdges[0].action?.text == "Adopt the guard")
        #expect(back.mitigatesEdges[0].action?.note == "It is bought and not deployed.")
        #expect(back.mitigatesEdges[0].action?.blockedBy == "guard-not-deployed")
        #expect(back.mitigatesEdges[0].action?.sources == ["https://example.com/ticket/1"])
        #expect(back.mitigatesEdges[1].action == nil)
    }

    @Test func readsBackAnActionWithNoSources() throws {
        var model = ThreatModel(name: "Payments")
        model.mitigatesEdges = [
            MitigatesEdge(
                source: ComponentId("guard"),
                target: ComponentId("store"),
                threatIds: [ThreatId("credential-theft")],
                status: .proposed,
                action: EdgeAction(label: "adopt-the-guard", text: "Adopt the guard")
            )
        ]

        let written = try ThreatModelCodec().encode(model)
        let back = try ThreatModelCodec().decode(written)

        #expect(back.mitigatesEdges[0].action?.sources == [])
    }

    /// A file written at version 5 has no `action` key on any edge. It still
    /// opens, and each edge's action reads back nil.
    @Test func aVersionFiveDocumentStillReadsWithNoAction() throws {
        let text = """
        {
          "formatVersion" : 5,
          "name" : "S",
          "createdAt" : "1970-01-01T00:00:00Z",
          "updatedAt" : "1970-01-01T00:00:00Z",
          "components" : [],
          "connections" : [],
          "zones" : [],
          "customTechnologies" : [],
          "severityOverrides" : {},
          "implementedControls" : [],
          "pathwayMitigations" : { "isMasterEnabled" : false, "configs" : {} },
          "mitigatesEdges" : [
            {
              "source" : "guard",
              "target" : "store",
              "threatIds" : [ "credential-theft" ],
              "status" : "assumed"
            }
          ]
        }
        """
        let read = try ThreatModelCodec().decode(Data(text.utf8))
        #expect(read.mitigatesEdges.count == 1)
        #expect(read.mitigatesEdges[0].action == nil)
    }
}
