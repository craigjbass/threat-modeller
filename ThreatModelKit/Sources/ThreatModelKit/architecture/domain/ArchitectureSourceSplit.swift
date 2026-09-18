/// Writes one source back into the files its blocks came from.
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
                threatActors: path == header ? source.threatActors : [],
                users: source.users.filter { file(of: .user($0.id)) == path }
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
