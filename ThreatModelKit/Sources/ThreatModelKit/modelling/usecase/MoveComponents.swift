public protocol MoveComponentsUseCase {
    func execute(_ request: MoveComponentsRequest) -> MoveComponentsResponse
}

/// One component's new position, in model coordinates.
public struct ComponentMove: Equatable, Sendable {
    public let componentId: String
    public let x: Double
    public let y: Double

    public init(componentId: String, x: Double, y: Double) {
        self.componentId = componentId
        self.x = x
        self.y = y
    }
}

public struct MoveComponentsRequest: Equatable, Sendable {
    public let moves: [ComponentMove]

    public init(moves: [ComponentMove]) {
        self.moves = moves
    }
}

public enum MoveComponentsResponse: Equatable, Sendable {
    /// The number of distinct components that moved.
    case moved(count: Int)
    case unknownComponent(componentId: String)
}

/// Puts components at new positions.
///
/// Positions are absolute, not offsets, so the same request applied twice
/// leaves the same model. The move is all or nothing: one unknown component
/// leaves every position as it was. Naming a component twice in one request
/// takes the last position given for it.
public struct MoveComponents: MoveComponentsUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: MoveComponentsRequest) -> MoveComponentsResponse {
        return models.mutate { model in
            var positions: [ComponentId: Point] = [:]

            for move in request.moves {
                let id = ComponentId(move.componentId)
                guard model.component(id) != nil else {
                    return .unknownComponent(componentId: move.componentId)
                }
                positions[id] = Point(x: move.x, y: move.y)
            }

            guard positions.isEmpty == false else { return .moved(count: 0) }

            for index in model.components.indices {
                if let position = positions[model.components[index].id] {
                    model.components[index].position = position
                }
            }
            return .moved(count: positions.count)
        }
    }
}
