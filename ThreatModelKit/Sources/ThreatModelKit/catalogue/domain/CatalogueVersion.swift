/// Which vendored catalogue a model was last assessed against.
///
/// A saved model stamps this, so opening it against a newer catalogue can say
/// what has drifted rather than quietly dropping it.
public struct CatalogueVersion: Equatable, Sendable {
    public let repository: String
    public let tag: String

    public init(repository: String, tag: String) {
        self.repository = repository
        self.tag = tag
    }

    public var description: String { "\(repository) \(tag)" }
}
