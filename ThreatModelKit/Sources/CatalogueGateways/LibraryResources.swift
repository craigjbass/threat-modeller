import Foundation

public enum LibraryResourceError: Error, Equatable {
    case notFound(String)
}

/// Reads the catalogue files vendored into this target's resource bundle.
public enum LibraryResources {
    public static func data(named name: String) throws -> Data {
        guard let url = Bundle.module.url(forResource: "Library/\(name)", withExtension: nil) else {
            throw LibraryResourceError.notFound(name)
        }
        return try Data(contentsOf: url)
    }
}
