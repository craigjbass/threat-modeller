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
}
