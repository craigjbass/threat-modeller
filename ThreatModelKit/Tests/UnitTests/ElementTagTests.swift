import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// The `tags` list a component, a zone and a flow state, read from a file,
/// written back to a file, and shown to the window.
@Suite("The tags an element holds")
struct ElementTagTests {
    private let app = TestDependencies()
    private let architecture = HclArchitectureSource()

    private let tagged = """
    system "Payments" {
      zone "app" {
        kind    = "private"
        network = "vpc"
        tags    = ["payments"]

        component "api" {
          technology = "aws-ec2"
          tags       = ["payments", "pci"]
        }
      }

      component "attacker" {
        technology = "actor-attacker"
      }

      flow attacker -> api {
        kind = "network"
        tags = ["payments"]
      }
    }

    """

    private let untagged = """
    system "Payments" {
      zone "app" {
        kind    = "private"
        network = "vpc"

        component "api" {
          technology = "aws-ec2"
        }
      }

      component "attacker" {
        technology = "actor-attacker"
      }

      flow attacker -> api
    }

    """

    // MARK: the language

    @Test func theParserReadsTheTagsOnAComponentAZoneAndAFlow() throws {
        let source = try #require(architecture.read(tagged).source)

        #expect(source.zones[0].tags == ["payments"])
        #expect(source.zones[0].components[0].tags == ["payments", "pci"])
        #expect(source.flows[0].tags == ["payments"])
    }

    @Test func anElementThatStatesNoTagsHoldsNone() throws {
        let source = try #require(architecture.read(untagged).source)

        #expect(source.zones[0].tags.isEmpty)
        #expect(source.zones[0].components[0].tags.isEmpty)
        #expect(source.flows[0].tags.isEmpty)
    }

    @Test func aTaggedFileRoundTripsByteForByte() throws {
        let source = try #require(architecture.read(tagged).source)

        #expect(architecture.write(source) == tagged)
    }

    @Test func aFileWithNoTagsRoundTripsByteForByte() throws {
        let source = try #require(architecture.read(untagged).source)

        #expect(architecture.write(source) == untagged)
    }

    // MARK: the model and the window

    @Test func theModelKeepsTheTagsTheFileStates() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: tagged))

        let view = app.viewThreatModel().execute(ViewThreatModelRequest())

        #expect(view.components.first { $0.id == "api" }?.tags == ["payments", "pci"])
        #expect(view.zones.first { $0.id == "app" }?.tags == ["payments"])
        #expect(view.connections.first { $0.id == "attacker->api" }?.tags == ["payments"])
    }

    @Test func aWrittenFileHoldsTheTagsTheModelKeeps() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: tagged))

        let written = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        #expect(written.contains("tags       = [\"payments\", \"pci\"]"))
        #expect(written.contains("tags            = [\"payments\"]"))
        #expect(written.contains("tags = [\"payments\"]"))
    }

    @Test func settingThePropertiesOfAComponentWritesItsTags() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: tagged))

        let answer = app.setComponentProperties().execute(
            SetComponentPropertiesRequest(
                componentId: "api",
                name: nil,
                sensitivity: "internal",
                threatsDisabled: false,
                runsAs: "user",
                tags: ["operations"]
            )
        )

        #expect(answer == .updated)
        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.first { $0.id == "api" }?.tags == ["operations"])
    }

    @Test func settingThePropertiesWithNoTagsLeavesTheTagsAlone() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: tagged))

        _ = app.setComponentProperties().execute(
            SetComponentPropertiesRequest(
                componentId: "api",
                name: nil,
                sensitivity: "internal",
                threatsDisabled: false,
                runsAs: "user"
            )
        )

        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.first { $0.id == "api" }?.tags == ["payments", "pci"])
    }
}
