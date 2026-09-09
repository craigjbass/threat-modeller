import CatalogueGateways
import Foundation
import Testing

/// Where the executable's own catalogue is.
///
/// A tarball and the application's helper both put `Library/` and `Actors/`
/// beside the binary, so the binary finds them without a flag. These tests set
/// the executable this rule reads, so they run in one order.
@Suite("Finding the catalogue beside the executable", .serialized)
struct CatalogueLocationTests {
    /// A directory holding a file that stands for the executable, and the
    /// catalogue directories beside it.
    private func aTarball(withCatalogue: Bool) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("catalogue-location-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try "binary".write(
            to: directory.appendingPathComponent("threatmodeller"),
            atomically: true,
            encoding: .utf8
        )
        if withCatalogue {
            for name in ["Library", "Actors"] {
                try FileManager.default.createDirectory(
                    at: directory.appendingPathComponent(name),
                    withIntermediateDirectories: true
                )
            }
        }
        return directory
    }

    private func withExecutable(_ url: URL?, _ body: () throws -> Void) rethrows {
        let before = CatalogueLocation.executableURL
        CatalogueLocation.executableURL = url
        defer { CatalogueLocation.executableURL = before }
        try body()
    }

    @Test func readsTheDirectoryTheExecutableSitsIn() throws {
        let tarball = try aTarball(withCatalogue: true)
        defer { try? FileManager.default.removeItem(at: tarball) }

        try withExecutable(tarball.appendingPathComponent("threatmodeller")) {
            #expect(
                CatalogueLocation.directory
                    == tarball.resolvingSymlinksInPath().path
            )
        }
    }

    @Test func readsThroughASymbolicLink() throws {
        let tarball = try aTarball(withCatalogue: true)
        let elsewhere = FileManager.default.temporaryDirectory
            .appendingPathComponent("catalogue-link-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: elsewhere, withIntermediateDirectories: true)
        let link = elsewhere.appendingPathComponent("threatmodeller")
        try FileManager.default.createSymbolicLink(
            at: link,
            withDestinationURL: tarball.appendingPathComponent("threatmodeller")
        )
        defer {
            try? FileManager.default.removeItem(at: tarball)
            try? FileManager.default.removeItem(at: elsewhere)
        }

        // A link on the user's PATH must find the catalogue the binary sits
        // beside, not the directory the link sits in.
        try withExecutable(link) {
            #expect(
                CatalogueLocation.directory
                    == tarball.resolvingSymlinksInPath().path
            )
        }
    }

    @Test func readsNothingWhenTheCatalogueIsNotBesideIt() throws {
        let plain = try aTarball(withCatalogue: false)
        defer { try? FileManager.default.removeItem(at: plain) }

        try withExecutable(plain.appendingPathComponent("threatmodeller")) {
            #expect(CatalogueLocation.directory == nil)
        }
    }

    @Test func readsNothingWhenOnlyOneDirectoryIsBesideIt() throws {
        let half = try aTarball(withCatalogue: false)
        try FileManager.default.createDirectory(
            at: half.appendingPathComponent("Library"),
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: half) }

        try withExecutable(half.appendingPathComponent("threatmodeller")) {
            #expect(CatalogueLocation.directory == nil)
        }
    }

    @Test func prefersTheDirectoryTheUserNamed() throws {
        let tarball = try aTarball(withCatalogue: true)
        defer { try? FileManager.default.removeItem(at: tarball) }

        try withExecutable(tarball.appendingPathComponent("threatmodeller")) {
            CatalogueLocation.directory = "/somewhere/else"
            defer { CatalogueLocation.directory = nil }

            #expect(CatalogueLocation.directory == "/somewhere/else")
        }
    }
}
