import ArchitectureDSL
import Foundation
import Testing
import ThreatModelKit

@Suite("Writing the architecture language back")
struct ArchitectureWriterTests {
    private let gateway = HclArchitectureSource()

    /// The canonical file, written out here rather than read from disk: a unit
    /// test that reads a file is a test of the file system as well.
    private let golden = """
    system "Payments" {
      catalogue = "v1.0.1"

      technology "our-ledger" {
        name     = "Our Ledger"
        category = "database"
        threats  = ["t-sql-injection"]
        encrypts = true
      }

      zone "edge" {
        kind    = "public"
        network = "dmz"
        name    = "Edge"

        component "cdn" {
          technology = "aws-cloudfront"
          data       = "public"
        }
      }

      zone "app" {
        kind            = "private"
        network         = "vpc"
        reduces_risk_by = 30

        component "api" {
          technology = "aws-ec2"
          name       = "Application Server"
          data       = "confidential"
        }

        component "ledger" {
          technology = "our-ledger"
          data       = "restricted"
          threats    = false
        }
      }

      component "attacker" {
        technology = "actor-attacker"
        data       = "public"
      }

      flow cdn -> api
      flow api -> ledger
    }

    """

    @Test func writesWhatItRead() throws {
        let once = try #require(gateway.read(golden).source)
        let twice = try #require(gateway.read(gateway.write(once)).source)

        #expect(once == twice)
    }

    @Test func reproducesACanonicalFileCharacterForCharacter() throws {
        let source = try #require(gateway.read(golden).source)

        #expect(gateway.write(source) == golden)
    }

    @Test func linesUpTheEqualsSignsInOneBlock() {
        let text = gateway.write(
            ArchitectureSource(
                systemName: "P",
                zones: [
                    SourceZone(
                        id: "z",
                        reducesRiskBy: 30,
                        components: [SourceComponent(id: "c", technologyId: "aws-ec2")]
                    )
                ]
            )
        )

        #expect(text.contains("    kind            = \"private\""))
        #expect(text.contains("    reduces_risk_by = 30"))
    }

    @Test func writesAFileWithNothingInIt() throws {
        let text = gateway.write(ArchitectureSource(systemName: "Empty"))

        #expect(text == "system \"Empty\" {\n}\n")
        #expect(gateway.read(text).source?.systemName == "Empty")
    }

    @Test func putsTheEscapesBack() throws {
        let source = ArchitectureSource(
            systemName: "The \"one\" that matters",
            components: [SourceComponent(id: "c", technologyId: "aws-ec2")]
        )

        let read = try #require(gateway.read(gateway.write(source)).source)

        #expect(read.systemName == "The \"one\" that matters")
    }
}
