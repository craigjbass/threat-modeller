import Foundation
import FileGateways
import ThreatModelKit

/// Stands in for the bundled samples. It holds one example, built here rather
/// than read from a file, so a unit test never touches a bundle.
public struct FakeSampleModels: SampleModelGateway {
    public static let sampleId = "one-component"

    private let document: Data

    public init() {
        let model = ThreatModel(
            name: "One Component",
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 100, y: 100),
                    sensitivity: .confidential
                )
            ]
        )
        document = (try? ThreatModelCodec().encode(model)) ?? Data()
    }

    public func all() -> [SampleModel] {
        [
            SampleModel(
                id: Self.sampleId,
                name: "One Component",
                description: "One server, so a test can name what it expects."
            )
        ]
    }

    public func document(id: String) throws -> Data {
        guard id == Self.sampleId else { throw SampleModelError.unknownSample(id: id) }
        return document
    }
}
