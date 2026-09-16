/// Reads and writes the architecture language.
///
/// A read never throws: it returns every fault it found, because a user fixing
/// a file wants the list, not the first line of it.
public protocol ArchitectureSourceGateway: Sendable {
    func read(_ text: String) -> ArchitectureRead
    /// One file of a split system, which may hold blocks and no `system`
    /// block. A gateway that reads only whole systems reads it as one.
    func readPart(_ text: String) -> ArchitectureRead
    func write(_ source: ArchitectureSource) -> String
    /// One file of a split system: the blocks, at the top level, with no
    /// `system` block around them.
    func writePart(_ source: ArchitectureSource) -> String
}

public extension ArchitectureSourceGateway {
    /// A gateway that states no part reader reads a part as a whole file.
    func readPart(_ text: String) -> ArchitectureRead { read(text) }

    /// A gateway that states no part writer writes the whole file.
    func writePart(_ source: ArchitectureSource) -> String { write(source) }

    /// Every file of one system, read and merged.
    ///
    /// Each part is parsed on its own, so a fault names the file and the line
    /// it is on, and the merge joins them into one source with one namespace.
    /// A flat system is the one-part case and reads exactly what it reads
    /// today.
    func read(_ parts: [SourcePart], named directoryName: String? = nil) -> MergedArchitecture.Merged {
        guard parts.count > 1 || directoryName != nil else {
            let one = parts.first ?? SourcePart(file: "", text: "")
            let read = read(one.text)
            // A whole file declares every zone it names, and the parser has
            // refused one that names a zone it does not declare, so the
            // placement here finds every zone.
            let source = read.source.map { MergedArchitecture.placed($0).source }
            return MergedArchitecture.Merged(
                source: source,
                // A part with no path states none: the caller names the file
                // it read, the way it always has.
                diagnostics: one.file.isEmpty
                    ? read.diagnostics
                    : read.diagnostics.map { $0.in(file: one.file) },
                origins: MergedArchitecture.origins(of: source, in: one.file)
            )
        }
        return MergedArchitecture.merge(
            parts.map { (part: $0, read: readPart($0.text)) },
            named: directoryName
        )
    }
}
