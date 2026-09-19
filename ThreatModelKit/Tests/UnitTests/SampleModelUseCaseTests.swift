import Foundation
import Testing
import ThreatModelKit
import TestSupport
import FileGateways

@Suite("Starting from an example")
struct SampleModelUseCaseTests {
    private let app = TestDependencies()

    @Test func listsWhatCanBeOpened() throws {
        let listed = app.listSampleModels().execute(ListSampleModelsRequest())

        let sample = try #require(listed.samples.first)
        #expect(sample.id == FakeSampleModels.sampleId)
        #expect(sample.name == "One Component")
        #expect(sample.description.isEmpty == false)
    }

    @Test func putsTheExampleInFrontOfTheUser() {
        let response = app.loadSampleModel().execute(
            LoadSampleModelRequest(sampleId: FakeSampleModels.sampleId)
        )

        #expect(response == .loaded(name: "One Component"))
        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.name == "One Component")
        #expect(view.components.count == 1)
    }

    @Test func replacesWhateverWasThereBefore() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 0, y: 0, sensitivity: "internal")
        )

        _ = app.loadSampleModel().execute(
            LoadSampleModelRequest(sampleId: FakeSampleModels.sampleId)
        )

        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.map(\.technologyId) == ["aws-ec2"])
    }

    @Test func costsOneUndo() {
        _ = app.loadSampleModel().execute(
            LoadSampleModelRequest(sampleId: FakeSampleModels.sampleId)
        )

        _ = app.undoLastChange().execute(UndoLastChangeRequest())

        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()).components.isEmpty)
    }

    @Test func refusesAnExampleItDoesNotHold() {
        let response = app.loadSampleModel().execute(
            LoadSampleModelRequest(sampleId: "no-such-sample")
        )

        #expect(response == .unknownSample)
    }

    @Test func scoresTheExampleTheSameWayAsAnythingElse() {
        _ = app.loadSampleModel().execute(
            LoadSampleModelRequest(sampleId: FakeSampleModels.sampleId)
        )

        let assessment = app.assessThreatModel().execute(AssessThreatModelRequest())

        #expect(assessment.threats.isEmpty == false)
    }

    @Test func drawsTheSamplesOwnPictureWithoutOpeningIt() {
        let response = app.previewSampleModel().execute(
            PreviewSampleModelRequest(sampleId: FakeSampleModels.sampleId)
        )

        guard case .drawn(let drawn) = response else {
            Issue.record("Expected the sample to be drawn")
            return
        }
        #expect(drawn.components.map(\.technologyId) == ["aws-ec2"])
        #expect(drawn.connections.isEmpty)
        #expect(drawn.zones.isEmpty)
    }

    @Test func leavesTheOpenModelAndItsRevisionAsTheyWere() {
        let modelBefore = app.modelStore.current()
        let revisionBefore = app.modelStore.revision

        _ = app.previewSampleModel().execute(
            PreviewSampleModelRequest(sampleId: FakeSampleModels.sampleId)
        )

        #expect(app.modelStore.current() == modelBefore)
        #expect(app.modelStore.revision == revisionBefore)
    }

    @Test func leavesNothingToTakeBack() {
        _ = app.previewSampleModel().execute(
            PreviewSampleModelRequest(sampleId: FakeSampleModels.sampleId)
        )

        #expect(app.modelStore.undo() == nil)
    }

    @Test func anUnknownSampleAnswersUnknownSampleAndWritesNothing() {
        let modelBefore = app.modelStore.current()
        let revisionBefore = app.modelStore.revision

        let response = app.previewSampleModel().execute(
            PreviewSampleModelRequest(sampleId: "no-such-sample")
        )

        #expect(response == .unknownSample)
        #expect(app.modelStore.current() == modelBefore)
        #expect(app.modelStore.revision == revisionBefore)
    }

    @Test func anUnreadableDocumentAnswersUnreadableAndWritesNothing() {
        let modelBefore = app.modelStore.current()
        let revisionBefore = app.modelStore.revision
        let useCase = PreviewSampleModel(
            samples: UnreadableSample(),
            files: ThreatModelCodec(),
            catalogue: app.catalogueInUse
        )

        let response = useCase.execute(PreviewSampleModelRequest(sampleId: "anything"))

        guard case .unreadable = response else {
            Issue.record("Expected the document to be unreadable")
            return
        }
        #expect(app.modelStore.current() == modelBefore)
        #expect(app.modelStore.revision == revisionBefore)
    }
}

private struct UnreadableSample: SampleModelGateway {
    func all() -> [SampleModel] { [] }
    func document(id: String) throws -> Data { Data("not a threat model".utf8) }
}
