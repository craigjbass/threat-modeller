import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("Stating the diagram shape in an architecture file")
struct ArchitectureShapeTests {
    private let gateway = HclArchitectureSource()

    private func file(_ attribute: String) -> String {
        """
        system "Payments" {
          component "customer_db" {
            technology = "aws-rds"
            data       = "restricted"
        \(attribute)
          }
        }
        """
    }

    @Test func readsTheShapeFromAComponentBlock() throws {
        let read = gateway.read(file("    shape      = \"store\""))

        #expect(read.diagnostics.filter { $0.severity == .error }.isEmpty)
        #expect(try #require(read.source).components.first?.shape == "store")
    }

    @Test func statesNoShapeWhenTheBlockNamesNone() throws {
        let read = gateway.read(file(""))

        #expect(try #require(read.source).components.first?.shape == nil)
    }

    @Test func refusesAShapeWordTheApplicationDoesNotHold() {
        let read = gateway.read(file("    shape      = \"cylinder\""))

        #expect(read.diagnostics.filter { $0.severity == .error }.isEmpty == false)
    }

    @Test func writesTheShapeBackOnlyWhenTheSourceStatesOne() throws {
        let source = try #require(gateway.read(file("    shape      = \"store\"")).source)
        let written = gateway.write(source)

        #expect(written.contains("shape      = \"store\""))
        #expect(try #require(gateway.read(written).source) == source)
    }

    @Test func writesNoShapeForAComponentThatStatesNone() throws {
        let source = try #require(gateway.read(file("")).source)

        #expect(gateway.write(source).contains("shape") == false)
    }
}
