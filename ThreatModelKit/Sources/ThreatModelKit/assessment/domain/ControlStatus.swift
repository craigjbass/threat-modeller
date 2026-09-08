/// What a person said about one control.
public enum ControlStatus: String, Equatable, Sendable, CaseIterable {
    case implemented
    case notImplemented = "not_implemented"
    case notApplicable = "not_applicable"
    case accepted

    /// True when a person has answered. `not_implemented` is what a control
    /// starts as, so it is not an answer.
    public var isAnswered: Bool {
        self != .notImplemented
    }

    /// Only `implemented` records the control, exactly as the checkbox does.
    public var isRecorded: Bool {
        self == .implemented
    }

    public var label: String {
        switch self {
        case .implemented: "Implemented"
        case .notImplemented: "Not implemented"
        case .notApplicable: "Not applicable"
        case .accepted: "Accepted"
        }
    }
}
