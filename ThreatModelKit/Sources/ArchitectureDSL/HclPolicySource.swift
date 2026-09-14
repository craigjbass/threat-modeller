import ThreatModelKit

/// Reads a `threatmodel/policy.hcl` file.
public struct HclPolicySource: PolicySourceGateway {
    public init() {}

    public func read(_ text: String) -> PolicyRead {
        let scanned = Lexer(text).scan()
        var parser = PolicyParser(tokens: scanned.tokens, faults: scanned.faults)
        return parser.parse()
    }
}
