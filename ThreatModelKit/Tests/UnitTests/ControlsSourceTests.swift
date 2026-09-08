import Testing
import ThreatModelKit

@Suite("What a control answer is")
struct ControlsSourceTests {
    @Test func namesAThreatOnASource() {
        #expect(ThreatKey(threatId: "credential-theft", sourceId: "component:api").value
            == "credential-theft@component:api")
        #expect(ThreatKey("a@b").value == "a@b")
    }

    @Test func saysWhichStatusesCountAsAnAnswer() {
        #expect(ControlStatus.notImplemented.isAnswered == false)
        #expect(ControlStatus.implemented.isAnswered)
        #expect(ControlStatus.notApplicable.isAnswered)
        #expect(ControlStatus.accepted.isAnswered)
    }

    @Test func recordsOnlyWhatIsImplemented() {
        #expect(ControlStatus.implemented.isRecorded)
        for status in ControlStatus.allCases where status != .implemented {
            #expect(status.isRecorded == false, "\(status) should not record a control")
        }
    }

    @Test func mintsTheKeyTheResolverMints() {
        let answer = SourceThreatAnswer(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api"
        )

        #expect(answer.key.value == "credential-theft@component:api")
    }

    @Test func knowsAnAnsweredThreatFromAnUnansweredOne() {
        let unanswered = SourceThreatAnswer(
            threatId: "t", sourceKind: "component", sourceId: "a",
            controls: [SourceControlAnswer(description: "c", status: .notImplemented)]
        )
        let answered = SourceThreatAnswer(
            threatId: "t", sourceKind: "component", sourceId: "a",
            controls: [SourceControlAnswer(description: "c", status: .accepted)]
        )
        let compensated = SourceThreatAnswer(
            threatId: "t", sourceKind: "component", sourceId: "a",
            controls: [SourceControlAnswer(description: "c", status: .notImplemented)],
            compensating: [
                CompensatingControl(label: "watched", reducesRiskBy: 40, rationale: "it alerts")
            ]
        )

        #expect(unanswered.isAnswered == false)
        #expect(answered.isAnswered)
        #expect(compensated.isAnswered)
    }

    @Test func findsAnAnswerByItsKey() throws {
        let source = ControlsSource(
            systemName: "P",
            answers: [
                SourceThreatAnswer(threatId: "t", sourceKind: "zone", sourceId: "app")
            ]
        )

        let found = source.answer(for: ThreatKey(threatId: "t", sourceId: "zone:app"))

        #expect(try #require(found).sourceId == "app")
        #expect(source.answer(for: ThreatKey("nothing@here")) == nil)
    }
}
