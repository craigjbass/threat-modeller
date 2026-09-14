/// Reads a `policy.hcl` file.
public protocol PolicySourceGateway: Sendable {
    func read(_ text: String) -> PolicyRead
}
