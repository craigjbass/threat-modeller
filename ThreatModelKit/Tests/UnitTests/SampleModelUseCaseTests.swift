import Testing
import ThreatModelKit
import TestSupport

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
}
