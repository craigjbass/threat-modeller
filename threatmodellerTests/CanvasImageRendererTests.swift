import AppKit
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

@MainActor
struct CanvasImageRendererTests {
    @Test func drawsThePngAtTwiceTheSizeItWasAskedFor() throws {
        let app = TestDependencies()
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 100, y: 100, sensitivity: "internal")
        )
        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        let area = app.exportModelAsImage().execute(ExportModelAsImageRequest())

        let risks = ElementRiskRollup.byElement(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats,
            levelOrder: []
        )
        let data = try CanvasImageRenderer().png(of: canvas, risks: risks, guards: [:], area: area)

        let image = try #require(NSBitmapImageRep(data: data))
        #expect(image.pixelsWide == Int(area.width * CanvasImageRenderer.scale))
        #expect(image.pixelsHigh == Int(area.height * CanvasImageRenderer.scale))
    }

    @Test func drawsAPictureOfAnEmptyModel() throws {
        let app = TestDependencies()
        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        let area = app.exportModelAsImage().execute(ExportModelAsImageRequest())

        let data = try CanvasImageRenderer().png(of: canvas, risks: [:], guards: [:], area: area)

        #expect(NSBitmapImageRep(data: data) != nil)
    }
}
