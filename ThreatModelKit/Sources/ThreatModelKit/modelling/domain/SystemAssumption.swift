/// Something the model takes on trust, and who owns it.
public struct SystemAssumption: Equatable, Sendable {
    public let label: String
    public let text: String
    public let owner: String?

    public init(label: String, text: String, owner: String? = nil) {
        self.label = label
        self.text = text
        self.owner = owner
    }
}

/// One thing a person does with the system. The label names it, and the text
/// says what the person does.
public struct SystemUseCase: Equatable, Sendable {
    public let label: String
    public let text: String

    public init(label: String, text: String) {
        self.label = label
        self.text = text
    }
}

/// One thing this model does not cover, and why it does not.
///
/// A rationale is required: an exclusion with no reason is a gap, and a reader
/// cannot tell a decision from an oversight.
public struct SystemExclusion: Equatable, Sendable {
    public let label: String
    public let text: String
    public let rationale: String

    public init(label: String, text: String, rationale: String) {
        self.label = label
        self.text = text
        self.rationale = rationale
    }
}
