/// The set of use cases a delivery mechanism may call.
///
/// Two composition roots conform: `Dependencies` in the application, wired to
/// real gateways, and `TestDependencies` in `TestSupport`, wired to fakes.
/// The protocol keeps the two in step. A use case added here does not compile
/// until both roots vend it.
public protocol UseCaseFactory {
    func listTechnologies() -> ListTechnologiesUseCase
    func viewThreatModel() -> ViewThreatModelUseCase
    func addComponent() -> AddComponentUseCase
    func moveComponents() -> MoveComponentsUseCase
    func connectComponents() -> ConnectComponentsUseCase
    func assessThreatModel() -> AssessThreatModelUseCase
}
