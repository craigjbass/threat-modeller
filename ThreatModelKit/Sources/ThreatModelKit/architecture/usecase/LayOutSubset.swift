import Foundation

public protocol LayOutSubsetUseCase {
    func execute(_ request: LayOutSubsetRequest) -> LayOutSubsetResponse
}

public struct LayOutSubsetRequest: Equatable, Sendable {
    /// The components to lay out. Empty lays nothing out.
    public let componentIds: [String]
    /// The zones to lay out. A component whose zone is not named lays out
    /// loose.
    public let zoneIds: [String]

    public init(componentIds: [String] = [], zoneIds: [String] = []) {
        self.componentIds = componentIds
        self.zoneIds = zoneIds
    }
}

public enum LayOutSubsetResponse: Equatable, Sendable {
    /// Where the named elements go. The caller draws these; nothing writes
    /// them to the model.
    case laidOut(components: [LaidOutComponent], zones: [LaidOutZone])
    /// The request names nothing the model holds.
    case nothingToLayOut
}

/// Lays a named part of the model out, and moves nothing.
///
/// The canvas narrows the diagram with the tag filter and with Focus. The
/// narrowed set keeps the coordinates the full layout gave it, so a view of
/// six components out of sixty draws six boxes across a canvas sized for
/// sixty. This lays the narrowed set out on its own.
///
/// It never calls `models.mutate`: there is no model change, no undo entry,
/// and nothing reaches the `.arch` file. `ArrangeDiagram` is the use case
/// that moves the model; this one answers the caller and stops.
///
/// An empty request lays nothing out. `ArrangeDiagramRequest` reads an empty
/// request as the whole model; a narrowed set that names nothing draws
/// nothing, so this reads it as nothing to lay out.
public struct LayOutSubset: LayOutSubsetUseCase {
    /// How long one narrowed layout of ten elements may take.
    ///
    /// One frame at 60 Hz is 0.0167 seconds. An optimised build lays six
    /// components and two zones out in 0.0095 seconds, inside that frame, so
    /// the shipped canvas draws the result in the frame the person asked for
    /// it. A debug build runs the same search in 0.513 seconds, and the kit
    /// tests run a debug build, so the budget a debug build states is the
    /// measured debug number with room for a slower machine and for the
    /// other tests the suite runs beside this one.
    ///
    /// `docs/superpowers/specs/2026-09-17-filtered-layout-design.md` states
    /// both measurements.
    #if DEBUG
    public static let frameBudget: TimeInterval = 3.0
    #else
    public static let frameBudget: TimeInterval = 0.0167
    #endif

    /// The number of drawn elements above which a preview shows, where an
    /// element is a drawn component or a drawn zone.
    ///
    /// At or below this size the search finishes inside one frame, so the
    /// canvas draws the result in the frame the person asked for it and
    /// there is nothing to preview.
    /// `docs/superpowers/specs/2026-09-17-filtered-layout-design.md` states
    /// the number and states that #147 adds the constant that holds it.
    public static let previewAboveElements = 24

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

    public func execute(_ request: LayOutSubsetRequest) -> LayOutSubsetResponse {
        let model = models.current()
        let wantedComponents = Set(request.componentIds)
        let wantedZones = Set(request.zoneIds)

        // The model's own order, not the request's. Two picks of the same set
        // in either order lay out the same way.
        var subset = model
        subset.components = model.components.filter { wantedComponents.contains($0.id.value) }
        subset.zones = model.zones.filter { wantedZones.contains($0.id.value) }

        guard subset.components.isEmpty == false || subset.zones.isEmpty == false else {
            return .nothingToLayOut
        }

        // A flow needs both its ends in the picture, the way the tag filter
        // draws one. An edge to a component the subset leaves out states
        // nothing the picture shows, so the layout never reads it.
        let drawnIds = Set(subset.components.map(\.id))
        subset.connections = model.connections.filter {
            drawnIds.contains($0.source) && drawnIds.contains($0.target)
        }
        subset.mitigatesEdges = model.mitigatesEdges.filter {
            drawnIds.contains($0.source) && drawnIds.contains($0.target)
        }

        let source = ArchitectureSourceBuilder.source(from: subset)
        let lookup = TechnologyLookup(model: subset, catalogue: catalogue)
        // The layout holds no catalogue, and measures the picture it drew, so
        // it needs the shape each component resolves to.
        let shapes = Dictionary(
            uniqueKeysWithValues: subset.components.map { component -> (String, String) in
                let technology = lookup.findById(component.technologyId)
                let resolved = component.shape ?? DiagramShapeMap.derived(
                    providerId: technology?.provider.value ?? "",
                    categoryId: technology?.category.value ?? ""
                )
                return (component.id.value, resolved.rawValue)
            }
        )

        let placed = layout.execute(LayOutModelRequest(source: source, shapes: shapes))
        return .laidOut(components: placed.components, zones: placed.zones)
    }
}
