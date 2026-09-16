import ArchitectureDSL
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// A component that sits in a zone another part file declares, by stating
/// `zone = "<id>"` on its block.
@Suite("A zone declared in another part file")
struct ZoneAcrossPartFilesTests {
    private let header = """
    system "Payments" {
      catalogue = "v1.0.0"
    }
    """

    private let edge = """
    zone "edge" {
      kind = "public"

      component "waf" { technology = "aws-waf" }
    }
    """

    private let ledger = """
    component "api" {
      technology = "aws-ec2"
      zone       = "edge"
    }

    flow waf -> api
    """

    private func merged(_ parts: [SourcePart]) -> MergedArchitecture.Merged {
        HclArchitectureSource().read(parts, named: "payments")
    }

    private func parts() -> [SourcePart] {
        [
            SourcePart(file: "arch/edge.arch", text: edge),
            SourcePart(file: "arch/ledger.arch", text: ledger),
            SourcePart(file: "arch/payments.arch", text: header)
        ]
    }

    // MARK: the attribute

    @Test func theParserReadsTheZoneAComponentStates() throws {
        let read = HclArchitectureSource().readPart(ledger)

        let component = try #require(read.source?.components.first)
        #expect(component.zoneId == "edge")
    }

    @Test func aComponentSitsInAZoneAnotherFileDeclares() throws {
        let read = merged(parts())

        #expect(read.hasErrors == false)
        let source = try #require(read.source)
        let zone = try #require(source.zones.first { $0.id == "edge" })
        #expect(zone.components.map(\.id) == ["waf", "api"])
        #expect(source.components.isEmpty)
    }

    @Test func theComponentKeepsTheFileItsBlockIsIn() {
        let read = merged(parts())

        #expect(read.origins[.component("api")] == "arch/ledger.arch")
        #expect(read.origins[.zone("edge")] == "arch/edge.arch")
    }

    @Test func theModelPlacesTheComponentInTheZone() throws {
        let app = TestDependencies()
        app.project.put(header, at: "/work/threatmodel/payments/arch/payments.arch")
        app.project.put(edge, at: "/work/threatmodel/payments/arch/edge.arch")
        app.project.put(ledger, at: "/work/threatmodel/payments/arch/ledger.arch")

        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        let api = try #require(app.modelStore.current().component(ComponentId("api")))
        #expect(api.zoneId == ZoneId("edge"))
    }

    // MARK: what is refused

    @Test func refusesAComponentThatNestsAndStatesAnotherZone() {
        let nested = """
        zone "edge" {
          kind = "public"

          component "waf" {
            technology = "aws-waf"
            zone       = "core"
          }
        }

        zone "core" { kind = "private" }
        """
        let read = merged([
            SourcePart(file: "arch/payments.arch", text: header),
            SourcePart(file: "arch/edge.arch", text: nested)
        ])

        #expect(read.source == nil)
        #expect(
            read.diagnostics.contains {
                $0.message == "the component \"waf\" sits in the zone \"edge\" and states zone \"core\""
                    && $0.file == "arch/edge.arch"
            }
        )
    }

    @Test func aNestedComponentMayStateTheZoneItSitsIn() throws {
        let nested = """
        zone "edge" {
          kind = "public"

          component "waf" {
            technology = "aws-waf"
            zone       = "edge"
          }
        }
        """
        let read = merged([
            SourcePart(file: "arch/payments.arch", text: header),
            SourcePart(file: "arch/edge.arch", text: nested)
        ])

        #expect(read.hasErrors == false)
        #expect(read.source?.zones.first?.components.map(\.id) == ["waf"])
    }

    @Test func refusesAZoneNoFileDeclares() {
        let read = merged([
            SourcePart(file: "arch/payments.arch", text: header),
            SourcePart(
                file: "arch/ledger.arch",
                text: "component \"api\" {\n  technology = \"aws-ec2\"\n  zone       = \"ghost\"\n}"
            )
        ])

        #expect(read.source == nil)
        #expect(
            read.diagnostics.contains {
                $0.message == "the component \"api\" states zone \"ghost\", which this system does not declare"
            }
        )
    }

    @Test func aFlatFileRefusesAZoneItDoesNotDeclare() {
        let read = HclArchitectureSource().read("""
        system "Payments" {
          component "api" {
            technology = "aws-ec2"
            zone       = "ghost"
          }
        }
        """)

        #expect(read.source == nil)
        #expect(
            read.diagnostics.contains {
                $0.message == "the component \"api\" states zone \"ghost\", which this file does not declare"
            }
        )
    }

    @Test func aFlatFilePlacesTheComponentInTheZoneItStates() throws {
        let read = HclArchitectureSource().read([
            SourcePart(
                file: "",
                text: """
                system "Payments" {
                  zone "edge" { kind = "public" }

                  component "api" {
                    technology = "aws-ec2"
                    zone       = "edge"
                  }
                }
                """
            )
        ])

        let source = try #require(read.source)
        #expect(source.zones.first?.components.map(\.id) == ["api"])
        #expect(source.components.isEmpty)
    }

    // MARK: what the writer chooses

    private static let goldens = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Goldens")
        .appendingPathComponent("split-payments")
        .appendingPathComponent("arch")

    private static let goldenFiles = ["payments.arch", "edge.arch", "ledger.arch"]

    private func aGoldenProject() throws -> TestDependencies {
        let app = TestDependencies()
        for name in Self.goldenFiles {
            let text = try String(contentsOf: Self.goldens.appendingPathComponent(name), encoding: .utf8)
            app.project.put(text, at: "/work/threatmodel/payments/arch/\(name)")
        }
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
        return app
    }

    /// The golden split system nests `waf` in the zone its file declares and
    /// states `zone = "edge"` on `api`, whose zone another file declares. A
    /// save writes every byte back as it was.
    @Test func aSaveOfTheGoldenSplitSystemWritesTheSameBytes() throws {
        let app = try aGoldenProject()

        let response = app.saveSystem().execute(
            SaveSystemRequest(root: "/work", systemName: "payments")
        )

        #expect(response == .saved(architecturePath: "/work/threatmodel/payments/arch/payments.arch"))
        for name in Self.goldenFiles {
            let golden = try String(contentsOf: Self.goldens.appendingPathComponent(name), encoding: .utf8)
            #expect(app.project.text(at: "/work/threatmodel/payments/arch/\(name)") == golden, "\(name)")
        }
    }

    @Test func theGoldenSplitSystemOpensWithTheComponentInTheZone() throws {
        let app = try aGoldenProject()

        let api = try #require(app.modelStore.current().component(ComponentId("api")))
        let waf = try #require(app.modelStore.current().component(ComponentId("waf")))
        #expect(api.zoneId == ZoneId("edge"))
        #expect(waf.zoneId == ZoneId("edge"))
    }

    @Test func aFlatSystemNestsTheComponentWhenItIsSaved() throws {
        let app = TestDependencies()
        app.project.put(
            """
            system "Payments" {
              zone "edge" { kind = "public" }

              component "api" {
                technology = "aws-ec2"
                zone       = "edge"
              }
            }
            """,
            at: "/work/threatmodel/payments.arch"
        )
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))

        let written = try #require(app.project.text(at: "/work/threatmodel/payments.arch"))
        #expect(written.contains("    component \"api\" {"))
        #expect(written.contains("zone       = \"edge\"") == false)
    }

    /// A component the application adds and drops into a zone another file
    /// declares goes into the header file with the attribute.
    @Test func aNewComponentDroppedIntoAZoneWritesTheAttributeIntoTheHeaderFile() throws {
        let app = TestDependencies()
        app.project.put(header, at: "/work/threatmodel/payments/arch/payments.arch")
        app.project.put(edge, at: "/work/threatmodel/payments/arch/edge.arch")
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
        let zone = try #require(app.modelStore.current().zones.first)
        _ = app.addComponent().execute(
            AddComponentRequest(
                technologyId: "aws-rds",
                x: zone.rect.origin.x + zone.rect.size.width / 2 - Component.size.width / 2,
                y: zone.rect.origin.y + zone.rect.size.height / 2 - Component.size.height / 2,
                sensitivity: "internal"
            )
        )
        let added = try #require(
            app.modelStore.current().components.first { $0.technologyId.value == "aws-rds" }
        )
        #expect(added.zoneId == zone.id)

        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))

        let headerFile = try #require(
            app.project.text(at: "/work/threatmodel/payments/arch/payments.arch")
        )
        #expect(headerFile.contains("zone       = \"edge\""))
        let edgeFile = try #require(app.project.text(at: "/work/threatmodel/payments/arch/edge.arch"))
        #expect(edgeFile.contains("aws-rds") == false)
    }
}
