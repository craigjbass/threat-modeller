public protocol ListThreatChoicesUseCase {
    func execute(_ request: ListThreatChoicesRequest) -> ListThreatChoicesResponse
}

public struct ListThreatChoicesRequest: Equatable, Sendable {
    public init() {}
}

public struct ThreatChoice: Equatable, Sendable {
    public let id: String
    public let name: String
    public let severityLabel: String
    public let strideLabels: [String]

    public init(id: String, name: String, severityLabel: String, strideLabels: [String]) {
        self.id = id
        self.name = name
        self.severityLabel = severityLabel
        self.strideLabels = strideLabels
    }
}

public struct ListThreatChoicesResponse: Equatable, Sendable {
    /// Worst first, then by name, so the list does not shuffle between reads.
    public let threats: [ThreatChoice]

    public init(threats: [ThreatChoice]) {
        self.threats = threats
    }
}

/// Every threat the editor can attach to a custom technology.
///
/// A user naming their own service says which of the catalogue's threats it
/// carries; they cannot invent one the rest of the application knows nothing
/// about.
public struct ListThreatChoices: ListThreatChoicesUseCase {
    private let catalogue: TechnologyCatalogue

    public init(catalogue: TechnologyCatalogue) {
        self.catalogue = catalogue
    }

    public func execute(_ request: ListThreatChoicesRequest) -> ListThreatChoicesResponse {
        let taxonomy = catalogue.taxonomy()
        var found: [ThreatId: Threat] = [:]
        for technology in catalogue.all() {
            for threat in catalogue.threatsFor(technologyId: technology.id) {
                found[threat.id] = threat
            }
        }
        for threat in catalogue.connectionThreats() + catalogue.zoneThreats() {
            found[threat.id] = threat
        }

        let ordered = found.values.sorted {
            if $0.severity.rank != $1.severity.rank { return $0.severity.rank > $1.severity.rank }
            return $0.name < $1.name
        }

        return ListThreatChoicesResponse(
            threats: ordered.map { threat in
                ThreatChoice(
                    id: threat.id.value,
                    name: threat.name,
                    severityLabel: threat.severity.label,
                    strideLabels: threat.stride.compactMap { taxonomy.strideCategory(id: $0)?.label }
                )
            }
        )
    }
}
