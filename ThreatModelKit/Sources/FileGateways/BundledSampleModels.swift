import Foundation
import ThreatModelKit

/// Reads the examples this application ships from its own bundle.
public struct BundledSampleModels: SampleModelGateway {
    private struct IndexJSON: Codable {
        let samples: [EntryJSON]
    }

    private struct EntryJSON: Codable {
        let id: String
        let name: String
        let description: String
        let file: String
    }

    private let entries: [EntryJSON]

    public init() {
        guard let url = Bundle.module.url(forResource: "Samples/samples", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let index = try? JSONDecoder().decode(IndexJSON.self, from: data) else {
            // A missing index means no samples, not a broken application. The
            // browser says there is nothing to open.
            entries = []
            return
        }
        entries = index.samples
    }

    public func all() -> [SampleModel] {
        entries.map { SampleModel(id: $0.id, name: $0.name, description: $0.description) }
    }

    public func document(id: String) throws -> Data {
        guard let entry = entries.first(where: { $0.id == id }) else {
            throw SampleModelError.unknownSample(id: id)
        }
        guard let url = Bundle.module.url(forResource: "Samples/\(entry.file)", withExtension: nil) else {
            throw SampleModelError.unreadable(reason: "\(entry.file) is not in the bundle")
        }
        do {
            return try Data(contentsOf: url)
        } catch {
            throw SampleModelError.unreadable(reason: String(describing: error))
        }
    }
}
