import Testing
import ThreatModelKit

/// What every controls gateway owes its callers.
public func verifyControlsSourceGatewayContract(_ make: () -> ControlsSourceGateway) {
    let gateway = make()

    let source = ControlsSource(
        systemName: "Payments",
        catalogueTag: "v1.0.1",
        answers: [
            SourceThreatAnswer(
                threatId: "credential-theft",
                sourceKind: "component",
                sourceId: "api",
                controls: [
                    SourceControlAnswer(description: "Enforce MFA", status: .implemented, note: "Okta")
                ],
                compensating: [
                    CompensatingControl(
                        label: "Break-glass account",
                        reducesRiskBy: 40,
                        rationale: "It alerts on use."
                    )
                ]
            ),
            SourceThreatAnswer(
                threatId: "sql-injection",
                sourceKind: "component",
                sourceId: "cache",
                controls: [
                    SourceControlAnswer(description: "Parameterise", status: .accepted)
                ],
                isStale: true
            )
        ]
    )

    // Writing then reading gives back what was written, stale answers included:
    // nothing deletes a person's work.
    let read = gateway.read(gateway.write(source))
    #expect(read.hasErrors == false, "a gateway refused what it wrote: \(read.diagnostics)")
    #expect(read.source?.answers.count == source.answers.count)
    #expect(read.source?.answer(for: ThreatKey("sql-injection@component:cache"))?.isStale == true)
    #expect(
        read.source?.answer(for: ThreatKey("credential-theft@component:api"))?.compensating
            == source.answers[0].compensating
    )

    // A read of nothing is one error, not an empty file of answers.
    let empty = gateway.read("")
    #expect(empty.source == nil)
    #expect(empty.hasErrors)
    for diagnostic in empty.diagnostics {
        #expect(diagnostic.line > 0)
        #expect(diagnostic.column > 0)
    }
}
