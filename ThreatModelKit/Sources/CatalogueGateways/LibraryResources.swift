import Foundation

public enum LibraryResourceError: Error, Equatable {
    case notFound(String)
}

/// Reads the catalogue files vendored into this target's resource bundle.
public enum LibraryResources {
    public static func data(named name: String) throws -> Data {
        try read("Library/\(name)")
    }

    /// Application-owned data, outside the vendored library. No checksum, no
    /// lock entry: it is ours, and `scripts/update-catalogue.sh` never touches
    /// the directory it lives in.
    public static func appOwnedData(named name: String) throws -> Data {
        try read("Actors/\(name)")
    }

    /// The named directory when one is set, else this target's bundle.
    private static func read(_ path: String) throws -> Data {
        if let directory = CatalogueLocation.directory {
            let url = URL(fileURLWithPath: directory).appendingPathComponent(path)
            guard let data = try? Data(contentsOf: url) else {
                throw LibraryResourceError.notFound(url.path)
            }
            return data
        }
        guard let url = Bundle.module.url(forResource: path, withExtension: nil) else {
            throw LibraryResourceError.notFound(path)
        }
        return try Data(contentsOf: url)
    }
}
