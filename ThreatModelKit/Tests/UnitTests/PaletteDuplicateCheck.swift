import CatalogueGateways
import Testing
import ThreatModelKit
import TestSupport

@Suite("What the palette list holds")
struct PaletteDuplicateCheckTests {
    @Test func everyIdInTheVendoredPaletteIsItsOwn() throws {
        let app = TestDependencies()
        let catalogue = try BundledTechnologyCatalogue()
        let listed = ListTechnologies(models: app.modelStore, catalogue: catalogue)
            .execute(ListTechnologiesRequest()).providers

        var providerIds: Set<String> = []
        for provider in listed {
            #expect(providerIds.insert(provider.id).inserted, Comment(rawValue: "two providers are \(provider.id)"))
            var categoryIds: Set<String> = []
            for category in provider.categories {
                #expect(
                    categoryIds.insert(category.id).inserted,
                    Comment(rawValue: "\(provider.id) holds two \(category.id) categories")
                )
                var technologyIds: Set<String> = []
                for technology in category.technologies {
                    #expect(
                        technologyIds.insert(technology.id).inserted,
                        Comment(rawValue: "\(category.id) holds two \(technology.id)")
                    )
                }
            }
        }

        // The list keys a row by the technology alone, so an id repeated in
        // two categories is two rows with one key.
        var everyTechnology: [String: Int] = [:]
        for provider in listed {
            for category in provider.categories {
                for technology in category.technologies {
                    everyTechnology[technology.id, default: 0] += 1
                }
            }
        }
        let repeated = everyTechnology.filter { $0.value > 1 }.keys.sorted()
        #expect(repeated.isEmpty, Comment(rawValue: "these ids are drawn twice: \(repeated)"))
    }
}
