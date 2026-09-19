import Foundation
import Testing
@testable import CatalogueGateways

struct LibraryResourcesTests {
    @Test func loadsTheVendoredTaxonomy() throws {
        let data = try LibraryResources.data(named: "taxonomy.json")
        let text = String(decoding: data, as: UTF8.self)
        #expect(text.contains("\"spoofing\""))
    }

    @Test func loadsAVendoredProviderFile() throws {
        let data = try LibraryResources.data(named: "technologies/aws.json")
        let text = String(decoding: data, as: UTF8.self)
        #expect(text.contains("\"aws-ec2\""))
    }

    @Test func reportsAMissingResource() {
        #expect(throws: LibraryResourceError.self) {
            try LibraryResources.data(named: "does-not-exist.json")
        }
    }

    @Test func dataReadsFromLibraryAndAppOwnedDataReadsFromActors() throws {
        _ = try LibraryResources.data(named: "taxonomy.json")
        _ = try LibraryResources.appOwnedData(named: "threat-actors.json")

        #expect(throws: LibraryResourceError.self) {
            try LibraryResources.appOwnedData(named: "taxonomy.json")
        }
        #expect(throws: LibraryResourceError.self) {
            try LibraryResources.data(named: "threat-actors.json")
        }
    }

    @Test func lockFileNamesNoFileUnderActors() throws {
        struct LockFileFilesJSON: Decodable {
            let files: [String: String]
        }
        let lockData = try LibraryResources.data(named: "library.lock.json")
        let lock = try JSONDecoder().decode(LockFileFilesJSON.self, from: lockData)
        #expect(lock.files.keys.allSatisfy { !$0.hasPrefix("Actors/") })
    }
}
