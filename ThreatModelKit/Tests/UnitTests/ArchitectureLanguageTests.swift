import Testing
import ThreatModelKit
import ArchitectureDSL

struct ArchitectureLanguageTests {
    private func read(_ text: String) -> ArchitectureRead {
        HclArchitectureSource().read(text)
    }

    @Test func aFlowWithNoBodyIsANetworkFlow() throws {
        let source = try #require(read("""
        system "S" {
          component "a" { technology = "t" }
          component "b" { technology = "t" }
          flow a -> b
        }
        """).source)
        #expect(source.flows.first?.kind == "network")
        #expect(source.flows.first?.description == nil)
    }

    @Test func aFlowStatesItsKindAndItsDescription() throws {
        let source = try #require(read("""
        system "S" {
          component "a" { technology = "t" }
          component "b" { technology = "t" }
          flow a -> b {
            kind        = "ipc"
            description = "XPC call"
          }
        }
        """).source)
        #expect(source.flows.first?.kind == "ipc")
        #expect(source.flows.first?.description == "XPC call")
    }

    @Test func aFlowKindOutsideTheVocabularyIsAnError() {
        let read = read("""
        system "S" {
          component "a" { technology = "t" }
          component "b" { technology = "t" }
          flow a -> b { kind = "carrier-pigeon" }
        }
        """)
        #expect(read.hasErrors)
        #expect(read.diagnostics.contains { $0.message.contains("kind is \"carrier-pigeon\"") })
    }

    @Test func aZoneStatesItsBoundary() throws {
        let source = try #require(read("""
        system "S" {
          zone "root" {
            boundary    = "privilege"
            description = "uid 0"
            component "a" { technology = "t" }
          }
        }
        """).source)
        #expect(source.zones.first?.boundary == "privilege")
        #expect(source.zones.first?.description == "uid 0")
    }

    @Test func aComponentStatesThePrivilegeItRunsAt() throws {
        let source = try #require(read("""
        system "S" {
          component "a" {
            technology = "t"
            runs_as    = "root"
          }
        }
        """).source)
        #expect(source.components.first?.runsAs == "root")
    }

    @Test func aComponentHoldsAssets() throws {
        let source = try #require(read("""
        system "S" {
          component "a" {
            technology = "t"
            asset "ssh-keys" { data = "restricted" }
            asset "notes" { }
          }
        }
        """).source)
        #expect(source.components.first?.assets.map(\.name) == ["ssh-keys", "notes"])
        #expect(source.components.first?.assets.map(\.data) == ["restricted", "internal"])
    }

    @Test func aMitigatesEdgeNamesItsThreatsAndItsReduction() throws {
        let source = try #require(read("""
        system "S" {
          component "guard" { technology = "t" }
          component "store" { technology = "t" }
          mitigates guard -> store {
            threats         = ["credential-theft"]
            reduces_risk_by = 80
          }
        }
        """).source)
        #expect(source.mitigates.first?.id == "guard->store")
        #expect(source.mitigates.first?.threatIds == ["credential-theft"])
        #expect(source.mitigates.first?.reducesRiskBy == 80)
    }

    @Test func aMitigatesEdgeWithNoThreatsIsAnError() {
        let read = read("""
        system "S" {
          component "guard" { technology = "t" }
          component "store" { technology = "t" }
          mitigates guard -> store { reduces_risk_by = 80 }
        }
        """)
        #expect(read.hasErrors)
        #expect(read.diagnostics.contains { $0.message.contains("names no threats") })
    }

    @Test func aMitigatesEdgeToAnUndeclaredComponentIsAnError() {
        let read = read("""
        system "S" {
          component "guard" { technology = "t" }
          mitigates guard -> store {
            threats         = ["credential-theft"]
            reduces_risk_by = 80
          }
        }
        """)
        #expect(read.hasErrors)
        #expect(read.diagnostics.contains { $0.message.contains("which this file does not declare") })
    }

    @Test func aRewriteOfWhatItReadProducesTheSameText() throws {
        let text = """
        system "S" {
          component "guard" {
            technology = "t"
            data       = "internal"
            runs_as    = "root"

            asset "ssh-keys" {
              data = "restricted"
            }
          }

          component "store" {
            technology = "t"
            data       = "internal"
          }

          flow guard -> store {
            kind        = "ipc"
            description = "XPC call"
          }

          mitigates guard -> store {
            threats         = ["credential-theft"]
            reduces_risk_by = 80
          }
        }

        """
        let source = try #require(read(text).source)
        #expect(HclArchitectureSource().write(source) == text)
    }
}
