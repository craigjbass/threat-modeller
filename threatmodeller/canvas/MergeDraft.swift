import ThreatModelKit

/// What the merge sheet holds: which component stays, and which value stays
/// for each attribute the components differ in.
///
/// A value, not a view, so a test reads the differences and the resolved
/// request without SwiftUI. The design in
/// `docs/superpowers/specs/2026-09-16-merge-components-design.md` states the
/// attributes and their labels.
struct MergeDraft: Equatable {
    /// The attributes the sheet resolves, in the order the sheet lists them.
    enum Attribute: String, CaseIterable, Identifiable {
        case technology
        case shape
        case name
        case sensitivity
        case runsAs
        case holds
        case zone
        case status
        case tags
        case providedBy

        var id: String { rawValue }

        var label: String {
            switch self {
            case .technology: "Technology"
            case .shape: "Shape"
            case .name: "Name"
            case .sensitivity: "Sensitivity"
            case .runsAs: "Runs As"
            case .holds: "Holds"
            case .zone: "Zone"
            case .status: "Status"
            case .tags: "Tags"
            case .providedBy: "Provided By"
            }
        }
    }

    /// One distinct value, with the first component that states it.
    struct Choice: Equatable, Identifiable {
        let componentId: String
        let componentName: String
        let label: String

        var id: String { componentId }
    }

    /// One attribute the components do not all agree on.
    struct Difference: Equatable, Identifiable {
        let attribute: Attribute
        let choices: [Choice]

        var id: String { attribute.rawValue }
    }

    /// What the verb writes: the survivor, the sources and the ten values.
    struct Resolved: Equatable {
        let survivorId: String
        let sourceIds: [String]
        let technologyId: String
        let shapeId: String?
        let name: String?
        let sensitivityId: String
        let runsAsId: String
        let holds: [String]
        let zoneId: String?
        let statusId: String
        let tags: [String]
        let providedById: String?
    }

    /// The components the merge joins, in model order.
    let components: [ViewedComponent]
    /// The component that stays. Starts on the first in model order.
    private(set) var survivorId: String
    private var picks: [Attribute: String] = [:]
    private let labels: [Attribute: [String: String]]
    private let values: [Attribute: [String: String]]

    @MainActor
    init(session: ThreatModelSession, componentIds: [String]) {
        let wanted = Set(componentIds)
        let components = session.canvas.components.filter { wanted.contains($0.id) }
        self.components = components
        survivorId = components.first?.id ?? ""

        let technologies = Dictionary(
            session.technologyChoices.flatMap(\.technologies).map { ($0.id, $0.label) },
            uniquingKeysWith: { first, _ in first }
        )
        let classifications = Dictionary(
            session.classificationChoices.map { ($0.id, $0.label) },
            uniquingKeysWith: { first, _ in first }
        )
        let zones = Dictionary(
            session.canvas.zones.map { ($0.id, $0.name) },
            uniquingKeysWith: { first, _ in first }
        )
        let thirdParties = Dictionary(
            session.canvas.thirdParties.map { ($0.id, $0.name) },
            uniquingKeysWith: { first, _ in first }
        )
        let privileges = Dictionary(
            ElementMenu.privileges.map { ($0.0, $0.1) },
            uniquingKeysWith: { first, _ in first }
        )

        var labels: [Attribute: [String: String]] = [:]
        var values: [Attribute: [String: String]] = [:]
        for component in components {
            for attribute in Attribute.allCases {
                let read = Self.read(
                    attribute,
                    of: component,
                    technologies: technologies,
                    classifications: classifications,
                    zones: zones,
                    thirdParties: thirdParties,
                    privileges: privileges
                )
                values[attribute, default: [:]][component.id] = read.value
                labels[attribute, default: [:]][component.id] = read.label
            }
        }
        self.labels = labels
        self.values = values
    }

    /// The value the attribute holds on one component, and the words the
    /// sheet shows for it.
    private static func read(
        _ attribute: Attribute,
        of component: ViewedComponent,
        technologies: [String: String],
        classifications: [String: String],
        zones: [String: String],
        thirdParties: [String: String],
        privileges: [String: String]
    ) -> (value: String, label: String) {
        switch attribute {
        case .technology:
            (component.technologyId, technologies[component.technologyId] ?? component.technologyId)
        case .shape:
            (
                component.shapeOverrideId ?? "",
                component.shapeOverrideId.flatMap { DiagramShape(rawValue: $0)?.label } ?? "From the technology"
            )
        case .name:
            (component.name, component.name)
        case .sensitivity:
            (component.sensitivityId, classifications[component.sensitivityId] ?? component.sensitivityId)
        case .runsAs:
            (component.runsAsId, privileges[component.runsAsId] ?? component.runsAsId)
        case .holds:
            (component.holds.joined(separator: "\u{1F}"), component.holds.isEmpty ? "Nothing" : component.holds.joined(separator: ", "))
        case .zone:
            (component.zoneId ?? "", component.zoneId.flatMap { zones[$0] } ?? "No zone")
        case .status:
            (component.statusId, ComponentStatus(rawValue: component.statusId)?.label ?? component.statusId)
        case .tags:
            (component.tags.joined(separator: "\u{1F}"), component.tags.isEmpty ? "None" : component.tags.joined(separator: ", "))
        case .providedBy:
            (component.providedById ?? "", component.providedById.flatMap { thirdParties[$0] } ?? "Nobody")
        }
    }

    /// One row per attribute the components do not all agree on, each with
    /// every distinct value once, in model order.
    var differences: [Difference] {
        Attribute.allCases.compactMap { attribute in
            var seen: Set<String> = []
            var choices: [Choice] = []
            for component in components {
                let value = values[attribute]?[component.id] ?? ""
                guard seen.insert(value).inserted else { continue }
                choices.append(
                    Choice(
                        componentId: component.id,
                        componentName: component.name,
                        label: labels[attribute]?[component.id] ?? value
                    )
                )
            }
            return choices.count > 1 ? Difference(attribute: attribute, choices: choices) : nil
        }
    }

    /// The component whose value stays for the attribute: the pick, or the
    /// survivor.
    func picked(_ attribute: Attribute) -> String {
        picks[attribute] ?? survivorId
    }

    mutating func pick(_ attribute: Attribute, from componentId: String) {
        picks[attribute] = componentId
    }

    /// Keeps another component, and starts every row on it again.
    mutating func keep(_ componentId: String) {
        survivorId = componentId
        picks = [:]
    }

    var sourceIds: [String] {
        components.map(\.id).filter { $0 != survivorId }
    }

    var resolved: Resolved {
        func component(_ attribute: Attribute) -> ViewedComponent? {
            let id = picked(attribute)
            return components.first { $0.id == id } ?? components.first { $0.id == survivorId }
        }
        let named = component(.name)
        return Resolved(
            survivorId: survivorId,
            sourceIds: sourceIds,
            technologyId: component(.technology)?.technologyId ?? "",
            shapeId: component(.shape)?.shapeOverrideId,
            name: named?.customName ?? (named?.id == survivorId ? nil : named?.name),
            sensitivityId: component(.sensitivity)?.sensitivityId ?? "",
            runsAsId: component(.runsAs)?.runsAsId ?? "",
            holds: component(.holds)?.holds ?? [],
            zoneId: component(.zone)?.zoneId,
            statusId: component(.status)?.statusId ?? ComponentStatus.default.rawValue,
            tags: component(.tags)?.tags ?? [],
            providedById: component(.providedBy)?.providedById
        )
    }
}
