import Testing
import ThreatModelKit

/// What every architecture source gateway owes its callers.
public func verifyArchitectureSourceGatewayContract(_ make: () -> ArchitectureSourceGateway) {
    let gateway = make()

    let source = ArchitectureSource(
        systemName: "Payments",
        zones: [
            SourceZone(
                id: "app",
                components: [SourceComponent(id: "api", technologyId: "aws-ec2")]
            )
        ],
        components: [SourceComponent(id: "attacker", technologyId: "actor-attacker")],
        flows: [SourceFlow(sourceId: "attacker", targetId: "api")]
    )

    // Writing then reading gives back what was written.
    let read = gateway.read(gateway.write(source))
    #expect(read.hasErrors == false, "a gateway refused what it wrote: \(read.diagnostics)")
    #expect(read.source == source)

    // A read of nothing is one error, not a crash and not an empty model.
    let empty = gateway.read("")
    #expect(empty.source == nil)
    #expect(empty.hasErrors)

    // Every fault names where it is, because that is what a user reads.
    for diagnostic in empty.diagnostics {
        #expect(diagnostic.line > 0, "a fault with no line: \(diagnostic)")
        #expect(diagnostic.column > 0, "a fault with no column: \(diagnostic)")
        #expect(diagnostic.message.isEmpty == false)
    }
}
