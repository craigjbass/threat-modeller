import ArchitectureDSL
import CatalogueGateways
import FileGateways
import Foundation
import Testing
import ThreatModelKit

/// The bundled examples must survive the whole path: a document in the bundle,
/// decoded, written as an architecture file, and read back.
struct InitialiseProjectFromBundledSamplesTests {
    @Test func writesEveryBundledExampleAsSomethingTheLanguageReads() throws {
        let samples = BundledSampleModels()
        let architecture = HclArchitectureSource()
        let projects = FileSystemProject()

        for sample in samples.all() {
            let root = FileManager.default.temporaryDirectory
                .appendingPathComponent("threat-modeller-init-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }

            let response = InitialiseProject(
                projects: projects,
                samples: samples,
                files: ThreatModelCodec(),
                sources: architecture
            )
            .execute(InitialiseProjectRequest(root: root.path, sampleId: sample.id))

            guard case .created(_, let path) = response else {
                Issue.record("\(sample.id) was not written: \(response)")
                continue
            }

            let read = architecture.read(try projects.read(path: path))
            #expect(read.hasErrors == false, "\(sample.id): \(read.diagnostics)")
            let source = try #require(read.source)
            #expect(source.everyComponent.isEmpty == false, "\(sample.id) wrote no components")
            #expect(source.systemName == sample.name)
        }
    }

    @Test func scoresWhatItWroteAgainstTheRealCatalogue() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("threat-modeller-init-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let projects = FileSystemProject()
        let architecture = HclArchitectureSource()
        _ = InitialiseProject(
            projects: projects,
            samples: BundledSampleModels(),
            files: ThreatModelCodec(),
            sources: architecture
        )
        .execute(InitialiseProjectRequest(root: root.path))

        let catalogue = try BundledTechnologyCatalogue()
        let models = InMemoryThreatModelGateway()
        let layout = try projects.discover(root: root.path)
        let system = try #require(layout.systems.first)

        let imported = ImportArchitecture(
            models: models,
            catalogue: catalogue,
            sources: architecture,
            layout: LayOutModel()
        )
        .execute(ImportArchitectureRequest(text: try projects.read(path: system.architecturePath)))

        guard case .imported(_, let warnings) = imported else {
            Issue.record("the written example did not import: \(imported)")
            return
        }
        // Every technology an example names is one the catalogue holds.
        #expect(warnings.isEmpty, "\(warnings)")
        #expect(ThreatResolver(model: models.current(), catalogue: catalogue).resolve().isEmpty == false)
    }
}
