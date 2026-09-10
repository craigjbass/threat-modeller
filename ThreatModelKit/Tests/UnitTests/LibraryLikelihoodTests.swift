import ArchitectureDSL
import Testing
import TestSupport
import ThreatModelKit

@Suite("A library threat's likelihood")
struct LibraryLikelihoodTests {
    private let gateway = HclLibrarySource()

    private func library(_ likelihoodLine: String) -> String {
        """
        library "endpoint" {
          threat "sip-bypass" {
            name       = "SIP Bypass"
            severity   = "critical"
        \(likelihoodLine)
          }
        }
        """
    }

    @Test func readsATier() throws {
        let source = try #require(gateway.read(library("    likelihood = \"research\"")).source)
        #expect(source.threats.first?.likelihood == "research")
    }

    @Test func readsANumericPrior() throws {
        let source = try #require(gateway.read(library("    likelihood = 25")).source)
        #expect(source.threats.first?.likelihood == "25")
    }

    @Test func aThreatThatStatesNoneReadsAsNil() throws {
        let source = try #require(gateway.read(library("")).source)
        #expect(source.threats.first?.likelihood == nil)
    }

    @Test func refusesAWordTheApplicationDoesNotHold() throws {
        let read = gateway.read(library("    likelihood = \"folklore\""))
        let errors = read.diagnostics.filter { $0.severity == .error }
        #expect(errors.count == 1)
        #expect(errors.first?.message.contains("folklore") == true)
    }

    @Test func refusesANumberAboveOneHundred() throws {
        let read = gateway.read(library("    likelihood = 150"))
        let errors = read.diagnostics.filter { $0.severity == .error }
        #expect(errors.count == 1)
        #expect(errors.first?.message.contains("150") == true)
    }

    @Test func refusesANegativeNumber() throws {
        let read = gateway.read(library("    likelihood = -1"))
        let errors = read.diagnostics.filter { $0.severity == .error }
        #expect(errors.count == 1)
        #expect(errors.first?.message.contains("-1") == true)
    }

    @Test func buildsIntoTheThreatAndDefaultsToCommodity() throws {
        let stated = try #require(gateway.read(library("    likelihood = \"targeted\"")).source)
        let silent = try #require(gateway.read(library("")).source)

        let built = Library.build(from: stated, taxonomy: CatalogueFixture.taxonomy())
        let plain = Library.build(from: silent, taxonomy: CatalogueFixture.taxonomy())

        #expect(built.library?.threats.first?.likelihood == .targeted)
        #expect(plain.library?.threats.first?.likelihood == .commodity)
    }

    @Test func writesTheAttributeBackOnlyWhenTheThreatStatesOne() throws {
        let stated = try #require(gateway.read(library("    likelihood = \"research\"")).source)
        #expect(gateway.write(stated).contains("likelihood = \"research\""))

        let silent = try #require(gateway.read(library("")).source)
        #expect(gateway.write(silent).contains("likelihood") == false)
    }
}
