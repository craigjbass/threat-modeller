/// What a controls file says, as plain values.
public struct ControlsSource: Equatable, Sendable {
    public let systemName: String
    public let catalogueTag: String?
    public let answers: [SourceThreatAnswer]

    public init(
        systemName: String,
        catalogueTag: String? = nil,
        answers: [SourceThreatAnswer] = []
    ) {
        self.systemName = systemName
        self.catalogueTag = catalogueTag
        self.answers = answers
    }

    public func answer(for key: ThreatKey) -> SourceThreatAnswer? {
        answers.first { $0.key == key }
    }
}

public struct SourceThreatAnswer: Equatable, Sendable {
    public let threatId: String
    /// `component`, `zone` or `flow`.
    public let sourceKind: String
    public let sourceId: String
    /// Written by the compiler so the file reads alone. A person editing it
    /// changes nothing: the application recomputes both.
    public let severityLabel: String?
    public let score: Int?
    public let controls: [SourceControlAnswer]
    public let compensating: [CompensatingControl]
    /// True when the architecture no longer raises this threat. Nothing deletes
    /// a stale answer. A person deletes it.
    public let isStale: Bool

    public init(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        severityLabel: String? = nil,
        score: Int? = nil,
        controls: [SourceControlAnswer] = [],
        compensating: [CompensatingControl] = [],
        isStale: Bool = false
    ) {
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
        self.severityLabel = severityLabel
        self.score = score
        self.controls = controls
        self.compensating = compensating
        self.isStale = isStale
    }

    /// The source id the resolver mints: the kind, then the identifier.
    public var key: ThreatKey {
        ThreatKey(threatId: threatId, sourceId: "\(sourceKind):\(sourceId)")
    }

    public var isAnswered: Bool {
        compensating.isEmpty == false || controls.contains { $0.status.isAnswered }
    }
}

public struct SourceControlAnswer: Equatable, Sendable {
    /// The control's description, which is what the catalogue gives and what
    /// the control key is minted from.
    public let description: String
    public let status: ControlStatus
    public let note: String?

    public init(description: String, status: ControlStatus, note: String? = nil) {
        self.description = description
        self.status = status
        self.note = note
    }
}

public struct ControlsRead: Equatable, Sendable {
    public let source: ControlsSource?
    public let diagnostics: [Diagnostic]

    public init(source: ControlsSource?, diagnostics: [Diagnostic]) {
        self.source = source
        self.diagnostics = diagnostics
    }

    public var hasErrors: Bool {
        diagnostics.contains { $0.severity == .error }
    }

    public var warnings: [Diagnostic] {
        diagnostics.filter { $0.severity == .warning }
    }
}
