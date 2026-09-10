import Testing
import ThreatModelKit

@Suite("What a likelihood does to a score")
struct LikelihoodTests {
    @Test func namesThreeTiers() throws {
        #expect(Likelihood.commodity.factor == 1.0)
        #expect(Likelihood.targeted.factor == 0.6)
        #expect(Likelihood.research.factor == 0.25)
        #expect(Likelihood.commodity.label == "Commodity")
    }

    @Test func readsATierByItsIdentifier() throws {
        #expect(Likelihood(rawValue: "research") == .research)
        #expect(Likelihood(rawValue: "folklore") == nil)
    }

    @Test func readsAPriorAsAPercentage() throws {
        let prior = try #require(Likelihood(prior: 25))
        #expect(prior.factor == 0.25)
        #expect(prior.id == "25")
        #expect(prior.label == "25%")
        #expect(Likelihood(prior: 101) == nil)
        #expect(Likelihood(prior: -1) == nil)
    }

    @Test func multipliesTheScoreAndNeverGoesBelowOne() throws {
        #expect(Likelihood.apply(to: 10, likelihood: .commodity) == 10)
        #expect(Likelihood.apply(to: 10, likelihood: .targeted) == 6)
        #expect(Likelihood.apply(to: 10, likelihood: .research) == 3)
        #expect(Likelihood.apply(to: 1, likelihood: .research) == 1)
    }
}
