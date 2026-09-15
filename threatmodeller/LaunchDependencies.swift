import ThreatModelKit

/// The one dependency graph this application runs on.
///
/// Building it parses the vendored catalogue, which is the slowest thing a
/// launch does. The About window and the project window each used to build
/// their own, so the catalogue was parsed twice. This builds it once and hands
/// the same one to both.
@MainActor
final class LaunchDependencies {
    /// The graph, or nil when it could not be built. Both windows say so when
    /// it is nil.
    let useCases: UseCaseFactory?
    /// What the About window states about the catalogue, or nil for the same
    /// reason.
    let catalogue: ViewCatalogueVersionResponse?

    /// `build` is a closure so a test counts how many times it runs and states
    /// what a failure leaves behind.
    init(build: () throws -> UseCaseFactory = { try Dependencies() }) {
        let built = try? build()
        useCases = built
        catalogue = built?.viewCatalogueVersion().execute(ViewCatalogueVersionRequest())
    }
}
