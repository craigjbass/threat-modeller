/// Reading and writing the `recommendation` blocks of one threat in a
/// system's `.controls` file.
///
/// The threat card's recommendations editor writes through these, the way the
/// severity decision editor writes through `WriteSeverityDecision`. Each reads
/// the file, changes one threat's recommendation list and writes every other
/// block back unchanged, because a person saying what to do about one threat
/// says nothing about the rest.
///
/// A `recommendation` block carries no id. `CompileGovernance` matches a
/// planned work item to a recommendation by its text, so the text names the
/// block here too: a write states the text it replaces, or nil for a new
/// block, and one threat never holds two blocks saying the same text.
public protocol WriteRecommendationUseCase {
    func execute(_ request: WriteRecommendationRequest) -> WriteRecommendationResponse
}

public struct WriteRecommendationRequest: Equatable, Sendable {
    public let root: String
    /// The system's own file name, which names the file to write.
    public let systemName: String
    /// The name the system states for itself, which a new file's header
    /// names. Nil writes the file name.
    public let systemDisplayName: String?
    /// The threat the recommendation names, the way the controls file states
    /// it.
    public let threatId: String
    /// `component`, `zone` or `flow`.
    public let sourceKind: String
    public let sourceId: String
    /// The text of the block this write replaces, or nil to write a new
    /// block.
    public let replacing: String?
    /// What the recommendation says.
    public let text: String
    /// Why, or how. Nil writes no `note` attribute.
    public let note: String?
    /// Where the recommendation comes from. Empty writes no `sources`
    /// attribute.
    public let sources: [String]

    public init(
        root: String,
        systemName: String,
        systemDisplayName: String? = nil,
        threatId: String,
        sourceKind: String,
        sourceId: String,
        replacing: String? = nil,
        text: String,
        note: String? = nil,
        sources: [String] = []
    ) {
        self.root = root
        self.systemName = systemName
        self.systemDisplayName = systemDisplayName
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
        self.replacing = replacing
        self.text = text
        self.note = note
        self.sources = sources
    }
}

public enum WriteRecommendationResponse: Equatable, Sendable {
    case written(path: String)
    case noSuchSystem
    /// Why the block is not one the application would write.
    case refused(reason: String)
    case cannotWrite(reason: String)

    public func describe(into message: inout String?) {
        switch self {
        case .written:
            message = nil
        case .noSuchSystem:
            message = "This project no longer holds that system."
        case .refused(let reason):
            message = "That recommendation was not written: \(reason)."
        case .cannotWrite(let reason):
            message = "That recommendation could not be written: \(reason)"
        }
    }
}

public struct WriteRecommendation: WriteRecommendationUseCase {
    private let projects: ProjectSourceGateway
    private let sources: ControlsSourceGateway

    public init(projects: ProjectSourceGateway, sources: ControlsSourceGateway) {
        self.projects = projects
        self.sources = sources
    }

    public func execute(_ request: WriteRecommendationRequest) -> WriteRecommendationResponse {
        // The parser needs a text to name the block, and the report prints
        // that text as the line a reader acts on.
        let text = request.text.trimmingWhitespace()
        guard text.isEmpty == false else {
            return .refused(reason: "a recommendation needs text")
        }

        let note = request.note?.trimmingWhitespace()
        var seen = Set<String>()
        let citations = request.sources
            .map { $0.trimmingWhitespace() }
            .filter { $0.isEmpty == false && seen.insert($0).inserted }

        let held: ControlsFile.Held
        switch ControlsFile.read(
            root: request.root,
            systemName: request.systemName,
            named: request.systemDisplayName,
            key: ThreatKey(
                threatId: request.threatId,
                sourceId: "\(SourceThreatAnswer.resolverKind(request.sourceKind)):\(request.sourceId)"
            ),
            projects: projects,
            sources: self.sources
        ) {
        case .held(let found):
            held = found
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        var answers = held.source.answers
        var recommendations = held.answerIndex.map { answers[$0].recommendations } ?? []

        // The text names the block, so a second block saying the same text
        // would name one planned work item twice.
        let replacing = request.replacing?.trimmingWhitespace()
        let clash = recommendations.firstIndex { $0.text == text }
        if let clash, recommendations[clash].text != replacing {
            return .refused(reason: "this threat already says \"\(text)\"")
        }

        let written = SourceRecommendation(
            text: text,
            note: note?.isEmpty == false ? note : nil,
            sources: citations
        )

        if let replacing, replacing.isEmpty == false {
            guard let already = recommendations.firstIndex(where: { $0.text == replacing }) else {
                return .refused(reason: "this threat no longer says \"\(replacing)\"")
            }
            recommendations[already] = written
        } else {
            recommendations.append(written)
        }

        if let already = held.answerIndex {
            answers[already] = ControlsFile.changing(
                answers[already],
                recommendationsTo: recommendations
            )
        } else {
            // The compile writes a block for every threat the architecture
            // raises. A file without one is behind it; the recommendation
            // still lands, and the next compile fills the rest in.
            answers.append(
                SourceThreatAnswer(
                    threatId: request.threatId,
                    sourceKind: request.sourceKind,
                    sourceId: request.sourceId,
                    recommendations: recommendations
                )
            )
        }

        do {
            try projects.write(
                sources.write(ControlsFile.replacing(answers: answers, in: held.source)),
                to: held.path
            )
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        return .written(path: held.path)
    }
}

public protocol RemoveRecommendationUseCase {
    func execute(_ request: RemoveRecommendationRequest) -> RemoveRecommendationResponse
}

public struct RemoveRecommendationRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String
    public let threatId: String
    /// `component`, `zone` or `flow`.
    public let sourceKind: String
    public let sourceId: String
    /// The text of the block to remove.
    public let text: String

    public init(
        root: String,
        systemName: String,
        threatId: String,
        sourceKind: String,
        sourceId: String,
        text: String
    ) {
        self.root = root
        self.systemName = systemName
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
        self.text = text
    }
}

public enum RemoveRecommendationResponse: Equatable, Sendable {
    case removed(path: String)
    case noSuchRecommendation
    case noSuchSystem
    case cannotWrite(reason: String)

    public func describe(into message: inout String?) {
        switch self {
        case .removed:
            message = nil
        case .noSuchRecommendation:
            message = "This threat says no such recommendation."
        case .noSuchSystem:
            message = "This project no longer holds that system."
        case .cannotWrite(let reason):
            message = "That recommendation could not be removed: \(reason)"
        }
    }
}

public struct RemoveRecommendation: RemoveRecommendationUseCase {
    private let projects: ProjectSourceGateway
    private let sources: ControlsSourceGateway

    public init(projects: ProjectSourceGateway, sources: ControlsSourceGateway) {
        self.projects = projects
        self.sources = sources
    }

    public func execute(_ request: RemoveRecommendationRequest) -> RemoveRecommendationResponse {
        let text = request.text.trimmingWhitespace()
        let held: ControlsFile.Held
        switch ControlsFile.read(
            root: request.root,
            systemName: request.systemName,
            named: nil,
            key: ThreatKey(
                threatId: request.threatId,
                sourceId: "\(SourceThreatAnswer.resolverKind(request.sourceKind)):\(request.sourceId)"
            ),
            projects: projects,
            sources: sources
        ) {
        case .held(let found):
            held = found
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        guard let already = held.answerIndex else { return .noSuchRecommendation }
        var recommendations = held.source.answers[already].recommendations
        guard let found = recommendations.firstIndex(where: { $0.text == text }) else {
            return .noSuchRecommendation
        }
        recommendations.remove(at: found)

        var answers = held.source.answers
        answers[already] = ControlsFile.changing(
            answers[already],
            recommendationsTo: recommendations
        )

        do {
            try projects.write(
                sources.write(ControlsFile.replacing(answers: answers, in: held.source)),
                to: held.path
            )
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        return .removed(path: held.path)
    }
}
