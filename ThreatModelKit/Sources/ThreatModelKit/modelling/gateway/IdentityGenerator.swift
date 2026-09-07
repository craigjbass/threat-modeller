import Foundation

public protocol IdentityGenerator {
    func next() -> String
}

public struct UUIDIdentityGenerator: IdentityGenerator {
    public init() {}

    public func next() -> String { UUID().uuidString }
}
