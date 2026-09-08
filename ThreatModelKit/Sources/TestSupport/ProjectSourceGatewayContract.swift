import Testing
import ThreatModelKit

/// What every project gateway owes its callers. The convention is stated here
/// once, and both gateways answer to it.
public func verifyProjectSourceGatewayContract(
    root: String,
    put: (_ text: String, _ path: String) -> Void,
    make: () -> ProjectSourceGateway
) {
    let gateway = make()
    let inside = ProjectConvention.path(root, "threatmodel")

    // A root holding nothing is a project with no systems, not a fault.
    put("", ProjectConvention.path(root, ".keep"))
    #expect((try? gateway.discover(root: root))?.systems.isEmpty == true)

    // The convention directory wins over the root.
    put("system \"Loose\" { }", ProjectConvention.path(root, "loose.arch"))
    put("system \"Payments\" { }", ProjectConvention.path(inside, "payments.arch"))
    put("system \"Reporting\" { }", ProjectConvention.path(inside, "reporting.arch"))

    guard let layout = try? gateway.discover(root: root) else {
        Issue.record("a project with two systems did not open")
        return
    }
    #expect(layout.directory == inside)
    // Sorted by name, so two reads of one project list the same thing.
    #expect(layout.systems.map(\.name) == ["payments", "reporting"])

    // Each system pairs with the two files that take its name.
    guard let payments = layout.system(named: "payments") else {
        Issue.record("the payments system was not found")
        return
    }
    #expect(payments.architecturePath == ProjectConvention.path(inside, "payments.arch"))
    #expect(payments.controlsPath == ProjectConvention.path(inside, "payments.controls"))
    #expect(payments.reportPath == ProjectConvention.path(inside, "payments.md"))
    // The answers need not exist yet.
    #expect(gateway.exists(path: payments.controlsPath) == false)

    // Writing then reading gives back what was written.
    #expect(throws: Never.self) {
        try gateway.write("answers", to: payments.controlsPath)
    }
    #expect((try? gateway.read(path: payments.controlsPath)) == "answers")
    #expect(gateway.exists(path: payments.controlsPath))

    // A read of a file that is not there says which file.
    #expect(throws: ProjectError.self) {
        _ = try gateway.read(path: ProjectConvention.path(inside, "no-such-file.arch"))
    }

    // A root that is not a directory is refused by name.
    #expect(throws: ProjectError.notADirectory(path: "/no/such/directory")) {
        _ = try gateway.discover(root: "/no/such/directory")
    }
}
