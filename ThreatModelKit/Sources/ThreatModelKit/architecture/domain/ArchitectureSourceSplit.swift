/// Writes one source back into the files its blocks came from.
///
/// A save reads the files as they are on disk, takes the origins from that
/// read, and writes each file again. A block nobody has seen before — one a
/// person added in the application — goes into the header file.
///
/// A part file that loses its last block is written empty rather than deleted:
/// a person who cut every block out of a file still owns that file.
public enum ArchitectureSourceSplit {
    public static func parts(
        of source: ArchitectureSource,
        origins: [BlockOrigin: String],
        headerFile: String?,
        sources: ArchitectureSourceGateway
    ) -> [SourcePart] {
        let header = headerFile ?? origins[.assumption("")] ?? ""
        var files = Set(origins.values)
        if header.isEmpty == false { files.insert(header) }

        func file(of origin: BlockOrigin) -> String { origins[origin] ?? header }

        var written: [SourcePart] = []
        for path in files.sorted() {
            // A zone nests the components that sit in its own file. A
            // component whose block is in another file stays there, as a
            // top-level block that states the zone with `zone = "<id>"`.
            let zones = source.zones
                .filter { file(of: .zone($0.id)) == path }
                .map { zone in
                    zone.holding(zone.components.filter { file(of: .component($0.id)) == path })
                }
            let statingAZone = source.zones
                .filter { file(of: .zone($0.id)) != path }
                .flatMap { zone in
                    zone.components
                        .filter { file(of: .component($0.id)) == path }
                        .map { $0.stating(zone: zone.id) }
                }
            let loose = source.components.filter { file(of: .component($0.id)) == path }
                + statingAZone

            let part = ArchitectureSource(
                systemName: source.systemName,
                catalogueTag: path == header ? source.catalogueTag : nil,
                technologies: source.technologies.filter { file(of: .technology($0.id)) == path },
                zones: zones,
                components: loose,
                flows: source.flows.filter { file(of: .flow($0.id)) == path },
                mitigates: source.mitigates.filter { file(of: .mitigates($0.id)) == path },
                riskTolerance: path == header ? source.riskTolerance : nil,
                assumptions: source.assumptions.filter { file(of: .assumption($0.label)) == path },
                requiresEvidenceAbove: path == header ? source.requiresEvidenceAbove : nil,
                owner: path == header ? source.owner : nil,
                faces: path == header ? source.faces : [],
                threatActors: path == header ? source.threatActors : []
            )

            written.append(
                SourcePart(
                    file: path,
                    text: path == header ? sources.write(part) : sources.writePart(part)
                )
            )
        }
        return written
    }
}
