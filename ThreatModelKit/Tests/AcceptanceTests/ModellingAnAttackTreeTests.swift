import Testing
import ThreatModelKit
import TestSupport

/// Given a system and the routes a person wrote through it
/// When I assess, compile, check and report
/// Then the goal of an open route scores higher and a broken route fails the build
struct ModellingAnAttackTreeTests {
    private let app = TestDependencies()

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    @Test func assessesAModelThatStatesNoTree() throws {
        app.project.put(payments, at: "/work/threatmodel/payments.arch")
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        let assessed = app.assessThreatModel().execute(AssessThreatModelRequest())

        #expect(assessed.attackTrees.isEmpty)
        #expect(assessed.threats.isEmpty == false)
    }
}
