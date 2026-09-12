import Testing
import Foundation
import ThreatModelKit
import FileGateways

@Suite("Saving and reloading the shape a component draws as")
struct DocumentShapeTests {
    private func model(shape: DiagramShape?) -> ThreatModel {
        ThreatModel(
            name: "Shapes",
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-rds"),
                    position: Point(x: 10, y: 20),
                    sensitivity: .internalData,
                    shape: shape
                )
            ]
        )
    }

    @Test func keepsTheShapeAcrossASaveAndAReload() throws {
        let data = try ThreatModelCodec().encode(model(shape: .store))
        let read = try ThreatModelCodec().decode(data)

        #expect(read.components.first?.shape == .store)
    }

    @Test func writesNoShapeKeyWhenTheUserStatesNone() throws {
        let data = try ThreatModelCodec().encode(model(shape: nil))
        let text = String(decoding: data, as: UTF8.self)

        #expect(text.contains("\"shape\"") == false)
    }

    @Test func readsAFileThatStatesNoShape() throws {
        let data = try ThreatModelCodec().encode(model(shape: nil))
        let read = try ThreatModelCodec().decode(data)

        #expect(read.components.first?.shape == nil)
    }

    @Test func refusesAShapeWordThisApplicationDoesNotHold() throws {
        let data = try ThreatModelCodec().encode(model(shape: .store))
        let broken = String(decoding: data, as: UTF8.self)
            .replacingOccurrences(of: "\"store\"", with: "\"cylinder\"")

        #expect(throws: ThreatModelFileError.unknownValue(field: "shape", value: "cylinder")) {
            try ThreatModelCodec().decode(Data(broken.utf8))
        }
    }
}
