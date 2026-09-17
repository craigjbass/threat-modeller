import Testing
import Foundation
import ThreatModelKit
import FileGateways
import TestSupport

/// Version 10 adds what proves a control: the tier, the reference and the
/// verified-on date, on a control and on a compensating control. A version 9
/// file states none and reads back with none.
struct DocumentFormatVersionTenTests {
    private func model() throws -> ThreatModel {
        var model = ThreatModel(name: "Payments")
        let verified = try #require(try? GovernanceDate.read("2026-09-01").get())
        model.controlProofs = [
            ControlKey("node:c1:credential-theft::00000000"): ControlProof(
                evidence: .tested,
                reference: "ci/imdsv2-test",
                verifiedOn: verified
            )
        ]
        model.compensatingControls = [
            ThreatKey("credential-theft@component:c1"): [
                CompensatingControl(
                    label: "Watched by the SIEM",
                    reducesRiskBy: 50,
                    rationale: "The account alerts on use.",
                    proof: ControlProof(evidence: .configured)
                )
            ]
        ]
        return model
    }

    @Test func writesTheCurrentVersion() throws {
        let data = try ThreatModelCodec().encode(try model())

        let read = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(read["formatVersion"] as? Int == ThreatModelCodec.formatVersion)
    }

    @Test func readsBackWhatProvesEachControl() throws {
        let written = try ThreatModelCodec().encode(try model())

        let back = try ThreatModelCodec().decode(written)

        let proof = try #require(
            back.controlProofs[ControlKey("node:c1:credential-theft::00000000")]
        )
        #expect(proof.evidence == .tested)
        #expect(proof.reference == "ci/imdsv2-test")
        #expect(proof.verifiedOn?.description == "2026-09-01")

        let compensating = try #require(
            back.compensatingControls[ThreatKey("credential-theft@component:c1")]?.first
        )
        #expect(compensating.proof.evidence == .configured)
        #expect(compensating.proof.reference.isEmpty)
        #expect(compensating.proof.verifiedOn == nil)
    }

    @Test func readsAVersionNineFileWithNoProofs() throws {
        let nine = """
        {
          "formatVersion": 9,
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

        let back = try ThreatModelCodec().decode(Data(nine.utf8))

        #expect(back.controlProofs.isEmpty)
        #expect(back.compensatingControls.isEmpty)
    }
}
