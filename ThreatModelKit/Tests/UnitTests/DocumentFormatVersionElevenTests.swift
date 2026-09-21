import Testing
import Foundation
import ThreatModelKit
import FileGateways
import TestSupport

/// Version 11 adds what a person wrote about a control, beside its evidence.
/// A version 10 file states none and reads back with none.
struct DocumentFormatVersionElevenTests {
    private func model() throws -> ThreatModel {
        var model = ThreatModel(name: "Payments")
        model.controlNotes = [
            ControlKey("node:c1:credential-theft::00000000"): "Okta, enforced group-wide"
        ]
        return model
    }

    @Test func writesTheCurrentVersion() throws {
        let data = try ThreatModelCodec().encode(try model())

        let read = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(read["formatVersion"] as? Int == ThreatModelCodec.formatVersion)
        #expect(ThreatModelCodec.formatVersion == 13)
    }

    @Test func readsBackWhatWasWrittenAboutEachControl() throws {
        let written = try ThreatModelCodec().encode(try model())

        let back = try ThreatModelCodec().decode(written)

        let note = try #require(back.controlNotes[ControlKey("node:c1:credential-theft::00000000")])
        #expect(note == "Okta, enforced group-wide")
    }

    @Test func readsAVersionTenFileWithNoNotes() throws {
        let ten = """
        {
          "formatVersion": 10,
          "name": "Payments",
          "createdAt": "2026-01-01T00:00:00Z",
          "updatedAt": "2026-01-01T00:00:00Z",
          "components": [],
          "connections": [],
          "zones": [],
          "customTechnologies": [],
          "severityOverrides": {},
          "implementedControls": [],
          "pathwayMitigations": { "isMasterEnabled": false, "configs": {} }
        }
        """

        let back = try ThreatModelCodec().decode(Data(ten.utf8))

        #expect(back.controlNotes.isEmpty)
    }
}
