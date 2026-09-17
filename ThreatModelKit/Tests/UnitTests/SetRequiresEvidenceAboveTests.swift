import Testing
import ThreatModelKit
import TestSupport

/// Writing the risk level at and above which an implemented control must
/// state evidence.
@Suite("Setting the tier that requires evidence")
struct SetRequiresEvidenceAboveTests {
    @Test func writesTheLevelToTheModel() {
        let app = TestDependencies()

        let response = app.setRequiresEvidenceAbove()
            .execute(SetRequiresEvidenceAboveRequest(level: "high"))

        #expect(response == .recorded)
        #expect(app.modelStore.current().requiresEvidenceAbove == .high)
    }

    @Test func refusesALevelTheLadderDoesNotHold() {
        let app = TestDependencies()

        let response = app.setRequiresEvidenceAbove()
            .execute(SetRequiresEvidenceAboveRequest(level: "extreme"))

        #expect(response == .unknownLevel("extreme"))
        #expect(app.modelStore.current().requiresEvidenceAbove == nil)
    }

    @Test func anEmptyLevelClearsIt() {
        let app = TestDependencies()
        _ = app.setRequiresEvidenceAbove().execute(SetRequiresEvidenceAboveRequest(level: "high"))

        let response = app.setRequiresEvidenceAbove().execute(SetRequiresEvidenceAboveRequest(level: ""))

        #expect(response == .recorded)
        #expect(app.modelStore.current().requiresEvidenceAbove == nil)
    }

    @Test func writesRequiresEvidenceAboveIntoTheArchitectureFileWithEveryOtherBlockUnchanged() {
        let app = TestDependencies()
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )
        let before = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        let response = app.setRequiresEvidenceAbove()
            .execute(SetRequiresEvidenceAboveRequest(level: "high"))

        #expect(response == .recorded)
        let after = app.exportArchitecture().execute(ExportArchitectureRequest()).text
        #expect(after.contains("requires_evidence_above = \"high\""))

        let beforeLines = Set(before.split(separator: "\n"))
        let afterLines = Set(after.split(separator: "\n"))
        #expect(afterLines.subtracting(beforeLines) == ["  requires_evidence_above = \"high\""])
    }
}
