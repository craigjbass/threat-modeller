import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("Parsing the architecture language")
struct ArchitectureParserTests {
    private let gateway = HclArchitectureSource()

    private func read(_ text: String) -> ArchitectureRead {
        gateway.read(text)
    }

    private func errors(_ text: String) -> [Diagnostic] {
        read(text).diagnostics.filter { $0.severity == .error }
    }

    @Test func readsASystemWithOneZoneAndOneComponent() throws {
        let read = read("""
        system "Payments" {
          catalogue = "v1.0.1"

          zone "app" {
            kind = "private"
            network = "vpc"
            component "api" { technology = "aws-ec2" }
          }
        }
        """)

        let source = try #require(read.source)
        #expect(source.systemName == "Payments")
        #expect(source.catalogueTag == "v1.0.1")
        let zone = try #require(source.zones.first)
        #expect(zone.id == "app")
        #expect(zone.network == "vpc")
        #expect(zone.components.map(\.id) == ["api"])
    }

    @Test func appliesTheDefaultsWhenAnAttributeIsAbsent() throws {
        let read = read("""
        system "P" {
          zone "z" { component "c" { technology = "aws-ec2" } }
        }
        """)

        let zone = try #require(read.source?.zones.first)
        #expect(zone.kind == "private")
        #expect(zone.network == "generic")
        #expect(zone.reducesRisk)
        #expect(zone.reducesRiskBy == nil)
        let component = try #require(zone.components.first)
        #expect(component.data == "internal")
        #expect(component.raisesThreats)
        #expect(component.name == nil)
    }

    @Test func readsAComponentOutsideEveryZone() throws {
        let read = read("""
        system "P" {
          component "attacker" {
            technology = "actor-attacker"
            data       = "public"
          }
        }
        """)

        #expect(read.source?.components.map(\.id) == ["attacker"])
        #expect(read.source?.zones.isEmpty == true)
    }

    @Test func readsATechnologyBlock() throws {
        let read = read("""
        system "P" {
          technology "our-ledger" {
            name     = "Our Ledger"
            category = "database"
            threats  = ["t-a", "t-b"]
            encrypts = true
          }
          component "l" { technology = "our-ledger" }
        }
        """)

        let technology = try #require(read.source?.technologies.first)
        #expect(technology.name == "Our Ledger")
        #expect(technology.threatIds == ["t-a", "t-b"])
        #expect(technology.encrypts)
    }

    @Test func readsAFlow() throws {
        let read = read("""
        system "P" {
          component "a" { technology = "aws-ec2" }
          component "b" { technology = "aws-rds" }
          flow a -> b
        }
        """)

        #expect(read.source?.flows.map(\.id) == ["a->b"])
    }

    @Test func readsThreatsOff() throws {
        let read = read("""
        system "P" {
          component "a" { technology = "aws-ec2"
            threats = false
          }
        }
        """)

        #expect(read.source?.components.first?.raisesThreats == false)
    }

    @Test func refusesADuplicateComponent() {
        let faults = errors("""
        system "P" {
          component "a" { technology = "aws-ec2" }
          component "a" { technology = "aws-rds" }
        }
        """)

        #expect(faults.count == 1)
        #expect(faults[0].message.contains("declared twice"))
    }

    @Test func refusesAFlowNamingAComponentTheFileDoesNotDeclare() {
        let faults = errors("""
        system "P" {
          component "a" { technology = "aws-ec2" }
          flow a -> ghost
        }
        """)

        #expect(faults.count == 1)
        #expect(faults[0].message.contains("ghost"))
    }

    @Test func refusesAFlowToItself() {
        let faults = errors("""
        system "P" {
          component "a" { technology = "aws-ec2" }
          flow a -> a
        }
        """)

        #expect(faults.contains { $0.message.contains("same component") })
    }

    @Test func refusesTheSameFlowTwice() {
        let faults = errors("""
        system "P" {
          component "a" { technology = "aws-ec2" }
          component "b" { technology = "aws-rds" }
          flow a -> b
          flow a -> b
        }
        """)

        #expect(faults.contains { $0.message.contains("declared twice") })
    }

    @Test func refusesAValueOutsideAVocabulary() throws {
        let faults = errors("""
        system "P" {
          zone "z" {
            kind = "secret"
            component "c" { technology = "aws-ec2" }
          }
        }
        """)

        let fault = try #require(faults.first)
        #expect(fault.message.contains("kind is \"secret\""))
        #expect(fault.line == 3)
        #expect(fault.column == 5)
    }

    @Test func refusesARiskReductionOutsideTheRange() {
        let faults = errors("""
        system "P" {
          zone "z" {
            reduces_risk_by = 140
            component "c" { technology = "aws-ec2" }
          }
        }
        """)

        #expect(faults.contains { $0.message.contains("runs from 0 to 100") })
    }

    @Test func refusesAComponentWithNoTechnology() {
        let faults = errors("""
        system "P" {
          component "a" { data = "public" }
        }
        """)

        #expect(faults.contains { $0.message.contains("names no technology") })
    }

    @Test func refusesAnAttributeTheGrammarDoesNotHold() {
        let faults = errors("""
        system "P" {
          component "a" {
            technology = "aws-ec2"
            colour     = "blue"
          }
        }
        """)

        #expect(faults.contains { $0.message.contains("colour") })
    }

    @Test func refusesAFileThatDoesNotStartWithASystem() {
        let faults = errors("zone \"z\" { }")

        #expect(faults.first?.message.contains("starts with system") == true)
    }

    @Test func warnsAboutAZoneHoldingNothing() throws {
        let read = read("""
        system "P" {
          zone "empty" { }
        }
        """)

        #expect(read.hasErrors == false)
        #expect(read.warnings.count == 1)
        #expect(read.source != nil)
    }

    @Test func reportsEveryFaultRatherThanTheFirst() {
        let faults = errors("""
        system "P" {
          zone "z" {
            kind = "secret"
            network = "outer"
            component "c" { technology = "aws-ec2" }
          }
        }
        """)

        #expect(faults.count == 2)
    }
}
