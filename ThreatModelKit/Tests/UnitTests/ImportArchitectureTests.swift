import Testing
import ThreatModelKit
import TestSupport

@Suite("Drawing what an architecture file describes")
struct ImportArchitectureTests {
    private let app = TestDependencies()

    private let payments = """
    system "Payments" {
      catalogue = "v1.0.1"

      zone "app" {
        kind            = "private"
        network         = "vpc"
        name            = "Application VPC"
        reduces_risk_by = 30

        component "api" {
          technology = "aws-ec2"
          name       = "Application Server"
          data       = "confidential"
        }

        component "db" {
          technology = "aws-rds"
          data       = "restricted"
        }
      }

      component "user" {
        technology = "actor-user"
        data       = "public"
      }

      flow user -> api
      flow api -> db
    }

    """

    private func importIt(_ text: String) -> ImportArchitectureResponse {
        app.importArchitecture().execute(ImportArchitectureRequest(text: text))
    }

    private func view() -> ViewThreatModelResponse {
        app.viewThreatModel().execute(ViewThreatModelRequest())
    }

    @Test func placesEveryComponentTheFileDeclares() throws {
        let response = importIt(payments)

        #expect(response == .imported(name: "Payments", warnings: []))
        let view = view()
        #expect(view.name == "Payments")
        #expect(view.components.map(\.id).sorted() == ["api", "db", "user"])
        #expect(view.connections.map(\.id).sorted() == ["api->db", "user->api"])
        #expect(view.zones.map(\.id) == ["app"])
    }

    @Test func carriesWhatEachComponentSaysAboutItself() throws {
        _ = importIt(payments)

        let api = try #require(view().components.first { $0.id == "api" })
        #expect(api.name == "Application Server")
        #expect(api.sensitivityId == "confidential")
        #expect(api.threatsDisabled == false)
        #expect(api.zoneId == "app")
    }

    @Test func carriesWhatEachZoneSaysAboutItself() throws {
        _ = importIt(payments)

        let zone = try #require(view().zones.first)
        #expect(zone.customName == "Application VPC")
        #expect(zone.networkZoneId == "private")
        #expect(zone.networkTypeId == "vpc")
        #expect(zone.riskReductionPercent == 30)
    }

    @Test func scoresWhatItDrew() {
        _ = importIt(payments)

        let assessment = app.assessThreatModel().execute(AssessThreatModelRequest())

        #expect(assessment.threats.isEmpty == false)
        #expect(assessment.threats.contains { $0.source.displayName == "Application Server" })
    }

    @Test func readsATechnologyTheFileDeclaresForItself() throws {
        _ = importIt("""
        system "P" {
          technology "our-ledger" {
            name     = "Our Ledger"
            category = "database"
            threats  = ["credential-theft"]
          }
          component "l" { technology = "our-ledger" }
        }
        """)

        let component = try #require(view().components.first)
        #expect(component.name == "Our Ledger")
        #expect(component.isUnknownTechnology == false)
        #expect(
            app.assessThreatModel().execute(AssessThreatModelRequest())
                .threats.contains { $0.threatId == "credential-theft" }
        )
    }

    @Test func warnsAboutATechnologyNothingHolds() throws {
        let response = importIt("""
        system "P" {
          component "ghost" { technology = "aws-ec3" }
        }
        """)

        guard case .imported(_, let warnings) = response else {
            Issue.record("expected the import to go through, got \(response)")
            return
        }
        #expect(warnings.count == 1)
        #expect(warnings[0].message.contains("aws-ec3"))
        // The node is still drawn: the diagram shows what the file says.
        #expect(view().components.map(\.id) == ["ghost"])
    }

    @Test func changesNothingWhenTheFileHasAFault() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 0, y: 0, sensitivity: "internal")
        )

        let response = importIt("system \"P\" { component \"a\" { data = \"public\" } }")

        guard case .refused(let diagnostics) = response else {
            Issue.record("expected the import to be refused, got \(response)")
            return
        }
        #expect(diagnostics.isEmpty == false)
        #expect(view().components.map(\.technologyId) == ["aws-rds"])
    }

    @Test func costsOneUndo() {
        _ = importIt(payments)

        _ = app.undoLastChange().execute(UndoLastChangeRequest())

        #expect(view().components.isEmpty)
    }

    @Test func carriesAnAssumedEdgeAsAssumedAndAPlainEdgeAsAdopted() throws {
        _ = importIt("""
        system "P" {
          component "shield" { technology = "aws-ec2" }
          component "host" { technology = "aws-ec2" }

          mitigates shield -> host {
            threats         = ["persistence"]
            reduces_risk_by = 60
            status          = "assumed"
          }
        }
        """)

        let model = app.modelStore.current()
        let edge = try #require(model.mitigatesEdges.first)
        #expect(edge.status == .assumed)
    }

    @Test func anEdgeWithNoStatusArrivesAdopted() throws {
        _ = importIt("""
        system "P" {
          component "shield" { technology = "aws-ec2" }
          component "host" { technology = "aws-ec2" }

          mitigates shield -> host {
            threats         = ["persistence"]
            reduces_risk_by = 60
          }
        }
        """)

        let model = app.modelStore.current()
        let edge = try #require(model.mitigatesEdges.first)
        #expect(edge.status == .adopted)
    }

    @Test func carriesTheRiskToleranceTheFileStates() {
        _ = importIt("""
        system "P" {
          risk_tolerance = "medium"
          component "a" { technology = "aws-ec2" }
        }
        """)

        #expect(app.modelStore.current().riskTolerance == .medium)
    }

    @Test func aSystemThatStatesNoToleranceIsLow() {
        _ = importIt("""
        system "P" {
          component "a" { technology = "aws-ec2" }
        }
        """)

        #expect(app.modelStore.current().riskTolerance == .low)
    }

    @Test func carriesAnAssumptionWithItsLabelTextAndOwner() throws {
        _ = importIt("""
        system "P" {
          assumption "mdm-push" {
            text  = "the hardening baseline is written, and MDM has not pushed it yet"
            owner = "platform team"
          }
          component "a" { technology = "aws-ec2" }
        }
        """)

        let assumption = try #require(app.modelStore.current().assumptions.first)
        #expect(assumption.label == "mdm-push")
        #expect(assumption.text == "the hardening baseline is written, and MDM has not pushed it yet")
        #expect(assumption.owner == "platform team")
    }

    @Test func anAssumptionWithNoOwnerArrivesWithANilOwner() throws {
        _ = importIt("""
        system "P" {
          assumption "mdm-push" {
            text = "the hardening baseline is written, and MDM has not pushed it yet"
          }
          component "a" { technology = "aws-ec2" }
        }
        """)

        let assumption = try #require(app.modelStore.current().assumptions.first)
        #expect(assumption.owner == nil)
    }
}
