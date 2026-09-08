/// Reads and writes the architecture language.
///
/// A read never throws: it returns every fault it found, because a user fixing
/// a file wants the list, not the first line of it.
public protocol ArchitectureSourceGateway: Sendable {
    func read(_ text: String) -> ArchitectureRead
    func write(_ source: ArchitectureSource) -> String
}
