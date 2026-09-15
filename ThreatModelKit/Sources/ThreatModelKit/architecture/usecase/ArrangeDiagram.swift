public protocol ArrangeDiagramUseCase {
    func execute(_ request: ArrangeDiagramRequest) -> ArrangeDiagramResponse
}

public struct ArrangeDiagramRequest: Equatable, Sendable {
    /// The components to move, or empty to move every component and every
    /// zone.
    public let componentIds: [String]
    /// The zones to move, read only when `componentIds` is not empty.
    public let zoneIds: [String]

    public init(componentIds: [String] = [], zoneIds: [String] = []) {
        self.componentIds = componentIds
        self.zoneIds = zoneIds
    }
}

public enum ArrangeDiagramResponse: Equatable, Sendable {
    /// What moved.
    case arranged(componentIds: [String], zoneIds: [String])
    /// The model holds nothing to lay out.
    case nothingToArrange
}

/// Lays the drawn model out again, and moves the elements to the result.
///
/// The layout reads an architecture source, so this writes the model out as
/// one, lays that out, and writes the coordinates back as one change. One undo
/// puts every element where it was.
///
/// With elements named, only those move. A layout of part of a diagram can put
/// a component where another one already is, and that is what the person
/// asked for: the rest of the diagram stays where they put it.
public struct ArrangeDiagram: ArrangeDiagramUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let layout: LayOutModelUseCase

    public init(
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        layout: LayOutModelUseCase
    ) {
        self.models = models
        self.catalogue = catalogue
        self.layout = layout
    }

    public func execute(_ request: ArrangeDiagramRequest) -> ArrangeDiagramResponse {
        let model = models.current()
        guard model.components.isEmpty == false || model.zones.isEmpty == false else {
            return .nothingToArrange
        }

        let source = ArchitectureSourceBuilder.source(from: model)
        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        // The layout holds no catalogue, and measures the picture it drew, so
        // it needs the shape each component resolves to.
        let shapes = Dictionary(
            uniqueKeysWithValues: model.components.map { component -> (String, String) in
                let technology = lookup.findById(component.technologyId)
                let resolved = component.shape ?? DiagramShapeMap.derived(
                    providerId: technology?.provider.value ?? "",
                    categoryId: technology?.category.value ?? ""
                )
                return (component.id.value, resolved.rawValue)
            }
        )

        let placed = layout.execute(LayOutModelRequest(source: source, shapes: shapes))
        let positions = Dictionary(
            uniqueKeysWithValues: placed.components.map { ($0.id, Point(x: $0.x, y: $0.y)) }
        )
        let rects = Dictionary(
            uniqueKeysWithValues: placed.zones.map {
                ($0.id, Rect(x: $0.x, y: $0.y, width: $0.width, height: $0.height))
            }
        )

        let everything = request.componentIds.isEmpty && request.zoneIds.isEmpty
        let wantedComponents = Set(request.componentIds)
        let wantedZones = Set(request.zoneIds)

        return models.mutate(label: ChangeLabel.arrangeDiagram) { model in
            var movedComponents: [String] = []
            var movedZones: [String] = []

            for index in model.components.indices {
                let id = model.components[index].id.value
                guard everything || wantedComponents.contains(id) else { continue }
                guard let position = positions[id] else { continue }
                model.components[index].position = position
                movedComponents.append(id)
            }

            for index in model.zones.indices {
                let id = model.zones[index].id.value
                guard everything || wantedZones.contains(id) else { continue }
                guard let rect = rects[id] else { continue }
                model.zones[index].rect = rect
                movedZones.append(id)
            }

            return .arranged(componentIds: movedComponents, zoneIds: movedZones)
        }
    }
}
