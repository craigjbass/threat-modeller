import Testing
import ThreatModelKit
import ArchitectureDSL
import TestSupport

/// A macOS endpoint, and the security product that protects it.
///
/// This is the model that showed every fault the spec lists. It is here so a
/// change that brings one back fails a test somebody reads.
struct ModellingAnEndpointTests {
    private let architecture = """
    system "Endpoint" {
      zone "user" {
        boundary = "privilege"
        name     = "uid 501"

        component "devtools" {
          technology = "aws-ec2"
          name       = "devtools"
          data       = "internal"
          runs_as    = "user"
        }
      }

      zone "root" {
        boundary = "privilege"
        name     = "uid 0"

        component "guard" {
          technology = "aws-waf"
          runs_as    = "root"
        }

        component "secrets" {
          technology = "aws-ec2"
          name       = "secrets"
          data       = "confidential"
          runs_as    = "root"

          asset "ssh-keys" { data = "restricted" }
        }
      }

      flow devtools -> secrets {
        kind        = "ipc"
        description = "XPC call to read a secret"
      }

      mitigates guard -> secrets {
        threats         = ["credential-theft"]
        reduces_risk_by = 80
      }
    }
    """

    private func model() throws -> ThreatModel {
        let models = InMemoryThreatModelGateway()
        let response = ImportArchitecture(
            models: models,
            catalogue: CatalogueFixture.catalogue(),
            sources: HclArchitectureSource(),
            layout: LayOutModel()
        ).execute(ImportArchitectureRequest(text: architecture))
        guard case .imported = response else {
            Issue.record("the import refused the file: \(response)")
            throw ImportFault.refused
        }
        return models.current()
    }

    private enum ImportFault: Error { case refused }

    @Test func theLocalFlowRaisesNoThreatAboutTls() throws {
        let resolved = ThreatResolver(model: try model(), catalogue: CatalogueFixture.catalogue()).resolve()
        #expect(resolved.contains { $0.threat.id == ThreatId("connection-mitm") } == false)
    }

    @Test func theSecretStoreScoresAtItsHighestAsset() throws {
        let resolved = ThreatResolver(model: try model(), catalogue: CatalogueFixture.catalogue()).resolve()
        let threat = try #require(
            resolved.first { $0.source.id == "component:secrets" && $0.threat.id == ThreatId("misconfiguration") }
        )
        #expect(threat.sensitivity == .restricted)
    }

    @Test func theProtectorLowersTheThreatItAnswers() throws {
        let resolved = ThreatResolver(model: try model(), catalogue: CatalogueFixture.catalogue()).resolve()
        let threat = try #require(
            resolved.first { $0.source.id == "component:secrets" && $0.threat.id == ThreatId("credential-theft") }
        )
        #expect(threat.mitigatedByComponents.first?.protectorName == "WAF")
        #expect(threat.score.value < threat.scoreBeforeControls)
    }

    @Test func theReportNamesTheProtectionDependencyAndTheAttackPath() throws {
        let models = InMemoryThreatModelGateway(try model())
        let report = BuildThreatModelReport(models: models, catalogue: CatalogueFixture.catalogue())
            .execute(BuildThreatModelReportRequest()).report

        #expect(report.protectionDependencies.contains { $0.protectorName == "WAF" })
        #expect(report.attackPaths.contains { $0.endName == "secrets" })
        #expect(report.rollups.topResidual.isEmpty == false)
    }

    @Test func aCompileAnswersEveryThreatItRaisesAndKeepsARecommendation() throws {
        let controls = """
        controls for "Endpoint" {
          threat "credential-theft" on component "secrets" {
            recommendation "Protect the managed preferences plist" { }
          }
        }
        """
        let response = CompileControls(
            catalogue: CatalogueFixture.catalogue(),
            architectureSources: HclArchitectureSource(),
            controlsSources: HclControlsSource(),
            layout: LayOutModel()
        ).execute(
            CompileControlsRequest(architectureText: architecture, controlsText: controls)
        )

        guard case .compiled(let text, _, _, let stale, _) = response else {
            Issue.record("the compile refused the files: \(response)")
            return
        }
        #expect(stale == 0)
        #expect(text.contains("recommendation \"Protect the managed preferences plist\""))
        #expect(text.contains("on flow \"devtools->secrets\""))
    }
}
