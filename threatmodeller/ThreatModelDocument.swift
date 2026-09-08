import Foundation
import SwiftUI
import UniformTypeIdentifiers
import ThreatModelKit
import FileGateways

nonisolated extension UTType {
    /// Spec section 8. Declared in `Info.plist` as an exported type.
    static let threatModel = UTType(exportedAs: "io.threatmodeller.model")
}

enum DocumentStoreError: Error, LocalizedError {
    case catalogueUnavailable(String)
    case notWritable(String)
    case unreadable(String)

    var errorDescription: String? {
        switch self {
        case .catalogueUnavailable(let reason): "The catalogue could not be loaded. \(reason)"
        case .notWritable(let reason): "The model could not be written. \(reason)"
        case .unreadable(let reason): "The file could not be read. \(reason)"
        }
    }
}

/// One open document's dependency graph. Spec section 3.5: one graph per open
/// document, each owning its own model gateway.
///
/// Declared `nonisolated` on purpose. SwiftUI asks a `FileDocument` for its
/// bytes wherever it likes, and every gateway underneath is safe to call from
/// anywhere.
nonisolated final class DocumentStore: @unchecked Sendable {
    /// Nil when the catalogue could not be loaded. The window says so rather
    /// than showing an empty diagram.
    let useCases: UseCaseFactory?
    let startupError: String?

    init() {
        do {
            useCases = try Dependencies()
            startupError = nil
        } catch {
            useCases = nil
            startupError = String(describing: error)
        }
    }

    func create(named name: String) {
        _ = useCases?.createThreatModel().execute(CreateThreatModelRequest(name: name))
    }

    func open(_ data: Data) throws -> ThreatModelDrift {
        guard let useCases else {
            throw DocumentStoreError.catalogueUnavailable(startupError ?? "")
        }
        switch useCases.openThreatModel().execute(OpenThreatModelRequest(data: data)) {
        case .opened(_, let drift):
            return drift
        case .unreadable(let reason):
            throw DocumentStoreError.unreadable(reason)
        }
    }

    func data() throws -> Data {
        guard let useCases else {
            throw DocumentStoreError.catalogueUnavailable(startupError ?? "")
        }
        switch useCases.saveThreatModel().execute(SaveThreatModelRequest()) {
        case .saved(let data):
            return data
        case .notWritable(let reason):
            throw DocumentStoreError.notWritable(reason)
        }
    }
}

/// The document SwiftUI opens, saves and closes.
///
/// The struct holds a reference to the store, so SwiftUI copying it never
/// copies the model. The bytes are the only thing that crosses the boundary.
struct ThreatModelDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.threatModel] }

    let store: DocumentStore
    /// What had moved under this file since it was last saved, or nil for a
    /// new document.
    let drift: ThreatModelDrift?

    init() {
        store = DocumentStore()
        store.create(named: "Untitled")
        drift = nil
    }

    init(configuration: ReadConfiguration) throws {
        store = DocumentStore()
        guard let data = configuration.file.regularFileContents else {
            throw CocoaError(.fileReadCorruptFile)
        }
        drift = try store.open(data)
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: try store.data())
    }
}
