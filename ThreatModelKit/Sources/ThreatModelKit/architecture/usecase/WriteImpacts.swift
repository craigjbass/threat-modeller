/// Reading and writing the `impacts` list of one threat in a system's
/// `.controls` file.
///
/// The threat card's chips write through this, the way the severity
/// decision editor writes through `WriteSeverityDecision`. It reads the
/// file, changes one threat's `impacts` list and writes every other block
/// back unchanged, because a person stating what one threat harms decides
/// nothing about the rest.
///
/// `ThreatResolver` and `ApplyControlAnswers` both read an empty list the
/// same way they read a missing one, so an empty write cannot mean "this
/// threat harms nothing" — it can only mean "no override", which is not what
/// a person meant by turning every chip off. This writer refuses that
/// request instead of writing a list that means something else.
public protocol WriteImpactsUseCase {
    func execute(_ request: WriteImpactsRequest) -> WriteImpactsResponse
}

public struct WriteImpactsRequest: Equatable, Sendable {
    public let root: String
    /// The system's own file name, which names the file to write.
    public let systemName: String
    /// The name the system states for itself, which a new file's header
    /// names. Nil writes the file name.
    public let systemDisplayName: String?
    /// The threat the list names, the way the controls file states it.
    public let threatId: String
    /// `component`, `zone` or `flow`.
    public let sourceKind: String
    public let sourceId: String
    /// The whole list, in the order to write it. Writing it again replaces
    /// the list that is there.
    public let impacts: [String]

    public init(
        root: String,
        systemName: String,
        systemDisplayName: String? = nil,
        threatId: String,
        sourceKind: String,
        sourceId: String,
        impacts: [String]
    ) {
        self.root = root
        self.systemName = systemName
        self.systemDisplayName = systemDisplayName
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
        self.impacts = impacts
    }
}

public enum WriteImpactsResponse: Equatable, Sendable {
    case written(path: String)
    case noSuchSystem
    /// Why the list is not one the application would write.
    case refused(reason: String)
    case cannotWrite(reason: String)

    public func describe(into message: inout String?) {
        switch self {
        case .written:
            message = nil
        case .noSuchSystem:
            message = "This project no longer holds that system."
        case .refused(let reason):
            message = "Those impacts were not written: \(reason)."
        case .cannotWrite(let reason):
            message = "Those impacts could not be written: \(reason)"
        }
    }
}

public struct WriteImpacts: WriteImpactsUseCase {
    private let projects: ProjectSourceGateway
    private let sources: ControlsSourceGateway

    public init(projects: ProjectSourceGateway, sources: ControlsSourceGateway) {
        self.projects = projects
        self.sources = sources
    }

    public func execute(_ request: WriteImpactsRequest) -> WriteImpactsResponse {
        var seen = Set<String>()
        let wanted = request.impacts
            .map { $0.trimmingWhitespace() }
            .filter { $0.isEmpty == false && seen.insert($0).inserted }

        guard wanted.isEmpty == false else {
            return .refused(reason: "a threat needs at least one impact")
        }

        for word in wanted where ThreatImpact(rawValue: word) == nil {
            return .refused(
                reason: "this application holds "
                    + ThreatImpact.allCases.map { "\"\($0.rawValue)\"" }.joined(separator: ", ")
            )
        }

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
            sources: sources
        ) {
        case .held(let found):
            held = found
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        var answers = held.source.answers
        if let already = held.answerIndex {
            answers[already] = ControlsFile.changing(answers[already], impactsTo: wanted)
        } else {
            // The compile writes a block for every threat the architecture
            // raises. A file without one is behind it; the list still lands,
            // and the next compile fills the rest in.
            answers.append(
                SourceThreatAnswer(
                    threatId: request.threatId,
                    sourceKind: request.sourceKind,
                    sourceId: request.sourceId,
                    impacts: wanted
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
