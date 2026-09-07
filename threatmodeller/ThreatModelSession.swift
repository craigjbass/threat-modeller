import Observation
import ThreatModelKit

/// Translates user intent into use case calls and publishes the responses.
/// Holds no business rules and names no gateway.
@Observable
final class ThreatModelSession {
    private let useCases: UseCaseFactory

    private(set) var palette: [ListedProvider] = []
    private(set) var threats: [AssessedThreat] = []
    private(set) var errorMessage: String?

    init(useCases: UseCaseFactory) {
        self.useCases = useCases
        palette = useCases.listTechnologies().execute(ListTechnologiesRequest()).providers
    }

    func add(technologyId: String) {
        let response = useCases.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 0, y: 0, sensitivity: "internal")
        )

        switch response {
        case .added:
            errorMessage = nil
        case .unknownTechnology:
            errorMessage = "That technology is not in the catalogue."
        case .unknownSensitivity:
            errorMessage = "That data sensitivity is not recognised."
        }

        reassess()
    }

    private func reassess() {
        threats = useCases.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }
}
