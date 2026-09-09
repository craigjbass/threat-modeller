/// Reads and writes the library language.
///
/// Text and tokens stay inside the language target. This is the only shape a
/// use case sees.
public protocol LibrarySourceGateway: Sendable {
    func read(_ text: String) -> LibraryRead
    func write(_ source: LibrarySource) -> String
}
