import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// A catalogue that counts how many times a resolution reads it, so a test
/// counts the runs of the resolver without reaching inside it.
final class CountingCatalogue: TechnologyCatalogue, @unchecked Sendable {
    private let real: TechnologyCatalogue
    private let lock = NSLock()
    private var reads = 0

    /// How many times something asked this catalogue for the threats of a
    /// technology. One resolution asks once per component.
    var threatReads: Int {
        lock.lock()
        defer { lock.unlock() }
        return reads
    }

    init(_ real: TechnologyCatalogue) {
        self.real = real
    }

    func threatsFor(technologyId: TechnologyId) -> [Threat] {
        lock.lock()
        reads += 1
        lock.unlock()
        return real.threatsFor(technologyId: technologyId)
    }

    func findById(_ id: TechnologyId) -> Technology? { real.findById(id) }
    func all() -> [Technology] { real.all() }
    func providers() -> [Provider] { real.providers() }
    func connectionThreats() -> [Threat] { real.connectionThreats() }
    func zoneThreats() -> [Threat] { real.zoneThreats() }
    func taxonomy() -> Taxonomy { real.taxonomy() }
    func version() -> CatalogueVersion { real.version() }
    func pathwayMitigations() -> [PathwayMitigationDefinition] { real.pathwayMitigations() }
    func threatActors() -> [ThreatActor] { real.threatActors() }
    func findActor(_ id: ThreatActorId) -> ThreatActor? { real.findActor(id) }
    func faults() -> [CatalogueFault] { real.faults() }
}

@Suite("Resolving once per change")
struct ThreatResolutionCacheTests {
    private func drawn() -> (InMemoryThreatModelGateway, CountingCatalogue) {
        let catalogue = CountingCatalogue(CatalogueFixture.catalogue())
        let models = InMemoryThreatModelGateway(
            ThreatModel(
                components: [
                    Component(
                        id: ComponentId("api"),
                        technologyId: TechnologyId("aws-ec2"),
                        position: Point(x: 0, y: 0),
                        sensitivity: .confidential
                    )
                ]
            )
        )
        return (models, catalogue)
    }

    @Test func theListAndTheSummaryRunTheResolverOnce() {
        let (models, catalogue) = drawn()
        let cache = ThreatResolutionCache()

        _ = AssessThreatModel(models: models, catalogue: catalogue, cache: cache)
            .execute(AssessThreatModelRequest())
        let afterTheList = catalogue.threatReads
        _ = SummariseRisk(models: models, catalogue: catalogue, cache: cache)
            .execute(SummariseRiskRequest())

        #expect(catalogue.threatReads == afterTheList)
    }

    @Test func withNoCacheEachOneRunsItsOwn() {
        let (models, catalogue) = drawn()

        _ = AssessThreatModel(models: models, catalogue: catalogue)
            .execute(AssessThreatModelRequest())
        let afterTheList = catalogue.threatReads
        _ = SummariseRisk(models: models, catalogue: catalogue)
            .execute(SummariseRiskRequest())

        #expect(catalogue.threatReads > afterTheList)
    }

    @Test func aChangeToTheModelResolvesAgain() {
        let (models, catalogue) = drawn()
        let cache = ThreatResolutionCache()
        _ = AssessThreatModel(models: models, catalogue: catalogue, cache: cache)
            .execute(AssessThreatModelRequest())
        let afterTheFirst = catalogue.threatReads

        _ = models.mutate { model in
            model.components[0].sensitivity = .restricted
        }
        _ = AssessThreatModel(models: models, catalogue: catalogue, cache: cache)
            .execute(AssessThreatModelRequest())

        #expect(catalogue.threatReads > afterTheFirst)
    }

    @Test func anUndoResolvesAgain() {
        let (models, catalogue) = drawn()
        let cache = ThreatResolutionCache()
        _ = models.mutate { model in model.components[0].sensitivity = .restricted }
        _ = AssessThreatModel(models: models, catalogue: catalogue, cache: cache)
            .execute(AssessThreatModelRequest())
        let afterTheChange = catalogue.threatReads

        _ = models.undo()
        _ = AssessThreatModel(models: models, catalogue: catalogue, cache: cache)
            .execute(AssessThreatModelRequest())

        #expect(catalogue.threatReads > afterTheChange)
    }

    @Test func forgettingMakesTheNextReadResolveAgain() {
        let (models, catalogue) = drawn()
        let cache = ThreatResolutionCache()
        _ = AssessThreatModel(models: models, catalogue: catalogue, cache: cache)
            .execute(AssessThreatModelRequest())
        let afterTheFirst = catalogue.threatReads

        cache.forget()
        _ = AssessThreatModel(models: models, catalogue: catalogue, cache: cache)
            .execute(AssessThreatModelRequest())

        #expect(catalogue.threatReads > afterTheFirst)
    }

    @Test func theCachedAnswerIsTheSameAnswer() {
        let (models, catalogue) = drawn()
        let cache = ThreatResolutionCache()

        let first = AssessThreatModel(models: models, catalogue: catalogue, cache: cache)
            .execute(AssessThreatModelRequest())
        let again = AssessThreatModel(models: models, catalogue: catalogue, cache: cache)
            .execute(AssessThreatModelRequest())

        #expect(first.threats == again.threats)
    }
}
