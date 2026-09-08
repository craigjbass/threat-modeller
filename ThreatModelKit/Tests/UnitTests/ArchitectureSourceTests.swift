import Testing
import ThreatModelKit

@Suite("What an architecture source is")
struct ArchitectureSourceTests {
    @Test func namesTheFileTheLineAndTheColumn() {
        let diagnostic = Diagnostic(severity: .error, line: 12, column: 5, message: "no such thing")

        #expect(diagnostic.described(in: "payments.arch")
            == "payments.arch:12:5: error: no such thing")
    }

    @Test func knowsAWarningFromAnError() {
        let read = ArchitectureRead(
            source: ArchitectureSource(systemName: "Payments"),
            diagnostics: [
                Diagnostic(severity: .warning, line: 1, column: 1, message: "an empty zone")
            ]
        )

        #expect(read.hasErrors == false)
        #expect(read.warnings.count == 1)
    }

    @Test func namesEveryComponentWhereverItWasDeclared() {
        let source = ArchitectureSource(
            systemName: "Payments",
            zones: [
                SourceZone(id: "app", components: [SourceComponent(id: "api", technologyId: "aws-ec2")])
            ],
            components: [SourceComponent(id: "attacker", technologyId: "actor-attacker")]
        )

        #expect(source.everyComponent.map(\.id) == ["attacker", "api"])
    }

    @Test func namesAFlowAfterItsEnds() {
        #expect(SourceFlow(sourceId: "api", targetId: "ledger").id == "api->ledger")
    }
}
