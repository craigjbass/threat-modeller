import CatalogueGateways
import Foundation
import Testing

/// Where the executable's own catalogue is.
///
/// A tarball and the application's helper both put `Library/` and `Actors/`
/// beside the binary, so the binary finds them without a flag. These tests
/// name the executable they mean, so nothing the whole process shares changes
/// and a test that reads the catalogue at the same time is unaffected.
@Suite("Finding the catalogue beside the executable")
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

    @Test func readsTheDirectoryTheExecutableSitsIn() throws {
        let tarball = try aTarball(withCatalogue: true)
        defer { try? FileManager.default.removeItem(at: tarball) }

        #expect(
            CatalogueLocation.directoryBeside(tarball.appendingPathComponent("threatmodeller"))
                == tarball.resolvingSymlinksInPath().path
        )
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
        #expect(
            CatalogueLocation.directoryBeside(link)
                == tarball.resolvingSymlinksInPath().path
        )
    }

    @Test func readsNothingWhenTheCatalogueIsNotBesideIt() throws {
        let plain = try aTarball(withCatalogue: false)
        defer { try? FileManager.default.removeItem(at: plain) }

        #expect(
            CatalogueLocation.directoryBeside(plain.appendingPathComponent("threatmodeller")) == nil
        )
    }

    @Test func readsNothingWhenOnlyOneDirectoryIsBesideIt() throws {
        let half = try aTarball(withCatalogue: false)
        try FileManager.default.createDirectory(
            at: half.appendingPathComponent("Library"),
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: half) }

        #expect(
            CatalogueLocation.directoryBeside(half.appendingPathComponent("threatmodeller")) == nil
        )
    }

    @Test func readsNothingWhenThereIsNoExecutable() {
        #expect(CatalogueLocation.directoryBeside(nil) == nil)
    }

    @Test func prefersTheDirectoryTheUserNamed() throws {
        let tarball = try aTarball(withCatalogue: true)
        defer { try? FileManager.default.removeItem(at: tarball) }

        #expect(
            CatalogueLocation.resolve(
                chosen: "/somewhere/else",
                environment: ["THREATMODELLER_CATALOGUE": "/from/the/environment"],
                executable: tarball.appendingPathComponent("threatmodeller")
            ) == "/somewhere/else"
        )
    }

    @Test func prefersTheEnvironmentOverTheExecutable() throws {
        let tarball = try aTarball(withCatalogue: true)
        defer { try? FileManager.default.removeItem(at: tarball) }

        #expect(
            CatalogueLocation.resolve(
                chosen: nil,
                environment: ["THREATMODELLER_CATALOGUE": "/from/the/environment"],
                executable: tarball.appendingPathComponent("threatmodeller")
            ) == "/from/the/environment"
        )
    }

    @Test func readsTheExecutableWhenNothingElseNamesADirectory() throws {
        let tarball = try aTarball(withCatalogue: true)
        defer { try? FileManager.default.removeItem(at: tarball) }

        #expect(
            CatalogueLocation.resolve(
                chosen: nil,
                environment: [:],
                executable: tarball.appendingPathComponent("threatmodeller")
            ) == tarball.resolvingSymlinksInPath().path
        )
    }

    @Test func readsTheBundleWhenNothingNamesADirectory() {
        #expect(
            CatalogueLocation.resolve(chosen: nil, environment: [:], executable: nil) == nil
        )
    }
}
