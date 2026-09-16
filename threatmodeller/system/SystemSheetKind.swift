import ThreatModelKit

/// One editor the System menu opens in a sheet.
///
/// `docs/superpowers/specs/2026-09-16-system-menu-and-sheets-design.md` states
/// the rule: an editor with an add form that writes a fact about the document
/// or about the system as a whole, rather than about the parts the canvas
/// draws, moves out of the architecture sidebar and into one of these.
enum SystemSheetKind: String, CaseIterable, Identifiable, Sendable {
    case documentControl
    case assets
    case thirdParties
    case useCases
    case exclusions
    case diagrams
    case threatActors

    var id: String { rawValue }

    /// The sheet's own heading.
    var title: String {
        switch self {
        case .documentControl: "Document Control"
        case .assets: "Assets"
        case .thirdParties: "Third Parties"
        case .useCases: "Use Cases"
        case .exclusions: "Exclusions"
        case .diagrams: "Diagrams"
        case .threatActors: "Threat Actors"
        }
    }

    /// The menu item's words, without the badge. The ellipsis says the item
    /// opens a sheet rather than acting at once.
    var menuTitle: String { "\(title)\u{2026}" }

    /// How many entries the model holds for this sheet.
    ///
    /// Document control counts the named fields the document states as well
    /// as the free attributes, because both are what the document says about
    /// itself.
    @MainActor
    func count(in session: ThreatModelSession) -> Int {
        switch self {
        case .documentControl:
            let facts = session.canvas.systemFacts
            let stated = [
                facts.owner.isEmpty == false,
                facts.description.isEmpty == false,
                facts.version.isEmpty == false,
                facts.created.isEmpty == false,
                facts.reviewed.isEmpty == false,
                facts.authors.isEmpty == false,
                facts.links.isEmpty == false,
                facts.repositories.isEmpty == false
            ]
            return stated.filter { $0 }.count + facts.attributes.count
        case .assets: session.canvas.systemAssets.count
        case .thirdParties: session.canvas.thirdParties.count
        case .useCases: session.canvas.useCases.count
        case .exclusions: session.canvas.exclusions.count
        case .diagrams: session.canvas.diagrams.count
        case .threatActors: session.threatActorsInUse.filter(\.isFaced).count
        }
    }

    /// What the menu item states beside its words: the count, or a dash for a
    /// section that holds nothing, so a person reads what the system states
    /// without opening every sheet.
    @MainActor
    func badge(in session: ThreatModelSession?) -> String {
        guard let session else { return "\u{2014}" }
        let held = count(in: session)
        return held == 0 ? "\u{2014}" : "\(held)"
    }

    /// The whole menu item, words and badge, separated by an en space.
    @MainActor
    func rowTitle(in session: ThreatModelSession?) -> String {
        "\(menuTitle)\u{2002}\(badge(in: session))"
    }
}
