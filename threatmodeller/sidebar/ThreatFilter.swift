import ThreatModelKit

/// What the sidebar's search field and filter keep.
///
/// A model with hundreds of threats is read by narrowing it, not by scrolling
/// it. The filter narrows what the list draws and changes no score: the risk
/// summary keeps counting the whole model.
struct ThreatFilter: Equatable {
    /// Whether a threat is answered, for the filter menu.
    enum Answered: String, CaseIterable, Identifiable {
        case either
        case answered
        case unanswered

        var id: String { rawValue }

        var label: String {
            switch self {
            case .either: "Answered or not"
            case .answered: "Answered"
            case .unanswered: "Unanswered"
            }
        }
    }

    /// What a person typed. Empty means every threat.
    var text = ""
    /// A risk level id, or nil for every level.
    var levelId: String?
    /// A STRIDE category id, or nil for every category.
    var strideId: String?
    var answered: Answered = .either

    var isNarrowing: Bool {
        text.isEmpty == false || levelId != nil || strideId != nil || answered != .either
    }

    /// The threats this filter keeps, in the order they were given.
    func narrow(_ threats: [AssessedThreat]) -> [AssessedThreat] {
        threats.filter { keeps($0) }
    }

    /// A threat matches the text by its title, by the name of the element that
    /// raised it, or by its threat id, so a person can type either the words
    /// they read on the card or the id they read in a file.
    func keeps(_ threat: AssessedThreat) -> Bool {
        if let levelId, threat.riskLevel != levelId { return false }
        if let strideId, threat.stride.contains(strideId) == false { return false }
        switch answered {
        case .either: break
        case .answered: if Self.isAnswered(threat) == false { return false }
        case .unanswered: if Self.isAnswered(threat) { return false }
        }

        let wanted = text.trimmed().lowercased()
        guard wanted.isEmpty == false else { return true }
        return threat.name.lowercased().contains(wanted)
            || threat.source.displayName.lowercased().contains(wanted)
            || threat.threatId.lowercased().contains(wanted)
    }

    /// A threat is answered when a person has said something about at least
    /// one of its controls, or written a compensating control against it.
    static func isAnswered(_ threat: AssessedThreat) -> Bool {
        threat.compensatingLabels.isEmpty == false
            || threat.controls.contains { $0.statusId != "not_implemented" }
    }
}

private extension String {
    func trimmed() -> String {
        var characters = Array(self)
        while characters.first?.isWhitespace == true { characters.removeFirst() }
        while characters.last?.isWhitespace == true { characters.removeLast() }
        return String(characters)
    }
}
