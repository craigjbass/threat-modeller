import Testing
import ThreatModelKit
@testable import ArchitectureDSL

@Suite("Writing the controls language")
struct ControlsWriterTests {
    private func answer(
        threatId: String = "t1",
        sourceKind: String,
        sourceId: String,
        isStale: Bool = false
    ) -> SourceThreatAnswer {
        SourceThreatAnswer(
            threatId: threatId,
            sourceKind: sourceKind,
            sourceId: sourceId,
            isStale: isStale
        )
    }

    private func tree(
        id: String,
        goalKey: String = "",
        chain: Int = 0,
        raisesRiskBy: Int = 0,
        score: Int = 0,
        scoreBefore: Int = 0,
        isStale: Bool = false
    ) -> SourceTreeAnswer {
        SourceTreeAnswer(
            treeId: id,
            goalKey: goalKey,
            chain: chain,
            raisesRiskBy: raisesRiskBy,
            score: score,
            scoreBefore: scoreBefore,
            isStale: isStale
        )
    }

    @Test func putsAComponentAnswerBeforeAFlowAnswerAndAFlowAnswerBeforeAZoneAnswer() {
        let answers = [
            answer(sourceKind: "zone", sourceId: "z1"),
            answer(sourceKind: "flow", sourceId: "f1"),
            answer(sourceKind: "component", sourceId: "c1")
        ]

        let ordered = ControlsWriter.ordered(answers)

        #expect(ordered.map(\.sourceKind) == ["component", "flow", "zone"])
    }

    @Test func sortsAnUnknownSourceKindAfterComponentFlowAndZone() {
        let answers = [
            answer(sourceKind: "unknown", sourceId: "u1"),
            answer(sourceKind: "zone", sourceId: "z1"),
            answer(sourceKind: "flow", sourceId: "f1"),
            answer(sourceKind: "component", sourceId: "c1")
        ]

        let ordered = ControlsWriter.ordered(answers)

        #expect(ordered.map(\.sourceKind) == ["component", "flow", "zone", "unknown"])
    }

    @Test func putsAStaleAnswerAfterEveryLiveAnswerWhateverItsSourceKind() {
        let answers = [
            answer(sourceKind: "component", sourceId: "c1", isStale: true),
            answer(sourceKind: "zone", sourceId: "z1", isStale: false)
        ]

        let ordered = ControlsWriter.ordered(answers)

        #expect(ordered.map(\.sourceKind) == ["zone", "component"])
        #expect(ordered.map(\.isStale) == [false, true])
    }

    @Test func sortsTwoAnswersOfOneSourceKindBySourceId() {
        let answers = [
            answer(sourceKind: "component", sourceId: "c2"),
            answer(sourceKind: "component", sourceId: "c1")
        ]

        let ordered = ControlsWriter.ordered(answers)

        #expect(ordered.map(\.sourceId) == ["c1", "c2"])
    }

    @Test func sortsTwoAnswersOfOneSourceByThreatId() {
        let answers = [
            answer(threatId: "t2", sourceKind: "component", sourceId: "c1"),
            answer(threatId: "t1", sourceKind: "component", sourceId: "c1")
        ]

        let ordered = ControlsWriter.ordered(answers)

        #expect(ordered.map(\.threatId) == ["t1", "t2"])
    }

    @Test func putsALiveTreeBeforeAStaleTree() {
        let trees = [tree(id: "t1", isStale: true), tree(id: "t2", isStale: false)]

        let ordered = trees.sorted(by: ControlsWriter.treeOrder)

        #expect(ordered.map(\.treeId) == ["t2", "t1"])
    }

    @Test func sortsTwoTreesOfOneStateById() {
        let trees = [tree(id: "b", isStale: false), tree(id: "a", isStale: false)]

        let ordered = trees.sorted(by: ControlsWriter.treeOrder)

        #expect(ordered.map(\.treeId) == ["a", "b"])
    }

    @Test func writesNoNumbersForAStaleTree() {
        let source = ControlsSource(
            systemName: "acme",
            trees: [
                tree(
                    id: "t1",
                    goalKey: "threat@component:c1",
                    chain: 50,
                    raisesRiskBy: 10,
                    score: 40,
                    scoreBefore: 30,
                    isStale: true
                )
            ]
        )

        let text = ControlsWriter().write(source)

        #expect(text.contains("goal") == false)
        #expect(text.contains("chain") == false)
        #expect(text.contains("raises_risk_by") == false)
        #expect(text.contains("score") == false)
        #expect(text.contains("score_before") == false)
    }

    @Test func writesAllFiveNumbersForALiveTree() {
        let source = ControlsSource(
            systemName: "acme",
            trees: [
                tree(
                    id: "t1",
                    goalKey: "threat@component:c1",
                    chain: 50,
                    raisesRiskBy: 10,
                    score: 40,
                    scoreBefore: 30,
                    isStale: false
                )
            ]
        )

        let text = ControlsWriter().write(source)

        #expect(text.contains("goal"))
        #expect(text.contains("chain"))
        #expect(text.contains("raises_risk_by"))
        #expect(text.contains("score"))
        #expect(text.contains("score_before"))
    }
}
