import Foundation
import ThreatModelKit

/// Reads and writes the document format of spec section 8.
///
/// The file is pretty-printed with sorted keys: a threat model is a document a
/// team reviews in a pull request, and a diff of one line should be one line.
public struct ThreatModelCodec: ThreatModelFileGateway {
    /// This application's own format version, separate from the catalogue's.
    ///
    /// Version 2 adds the technologies a model defines for itself. Version 3
    /// adds a status per control and the compensating controls. An older file
    /// has neither, and its recorded controls become `implemented` statuses,
    /// so a user's saved work does not stop opening. Version 4 adds a flow's
    /// kind and description, a component's privilege and assets, a zone's
    /// boundary and description, the mitigates edges and the recommendations.
    /// Version 5 adds the likelihood findings, the severity decisions, the
    /// assumptions and the risk tolerance. An older build does not know these
    /// fields, so it would open a version 5 file and then drop them again on
    /// the next save; refusing the file by its version number stops that
    /// silent loss instead. Version 6 adds the action an assumed edge
    /// carries. Version 7 adds the zone a component sits in, which was read
    /// from the coordinates before and is now written on the component. A file
    /// at version 6 or below reads back with the same membership, filled in
    /// from the coordinates the file holds.
    /// Version 8 adds the system's owner and what the model states about
    /// itself: the description, the authors, the links, the repositories, the
    /// dates, the version and the team's own attributes. A file at version 7
    /// or below states none of them and reads back with none.
    /// Version 10 adds what proves a control: the evidence tier, the reference
    /// and the verified-on date, on a control and on a compensating control. A
    /// file at version 9 or below states none and reads back with none.
    /// Version 11 adds what a person wrote about a control, beside its
    /// evidence. A file at version 10 or below states none and reads back
    /// with none.
    public static let formatVersion = 11
    private static let readableFormatVersions: Set<Int> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]

    public init() {}

    public func encode(_ model: ThreatModel) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        return try encoder.encode(
            DocumentJSON(
                formatVersion: Self.formatVersion,
                name: model.name,
                createdAt: model.createdAt,
                updatedAt: model.updatedAt,
                catalogue: model.catalogueVersion.map {
                    CatalogueStampJSON(repository: $0.repository, tag: $0.tag)
                },
                components: model.components.map(Self.json(from:)),
                connections: model.connections.map(Self.json(from:)),
                zones: model.zones.map(Self.json(from:)),
                customTechnologies: model.customTechnologies.map(Self.json(from:)),
                severityOverrides: Dictionary(
                    uniqueKeysWithValues: model.severityOverrides.map { ($0.key.value, $0.value) }
                ),
                implementedControls: model.implementedControls.map(\.value).sorted(),
                controlStatuses: Dictionary(
                    uniqueKeysWithValues: model.controlStatuses.map { ($0.key.value, $0.value.rawValue) }
                ),
                compensatingControls: Dictionary(
                    uniqueKeysWithValues: model.compensatingControls.map { key, controls in
                        (
                            key.value,
                            controls.map {
                                CompensatingControlJSON(
                                    label: $0.label,
                                    reducesRiskBy: $0.reducesRiskBy,
                                    rationale: $0.rationale,
                                    sources: $0.sources,
                                    evidence: $0.proof.evidence?.rawValue,
                                    reference: $0.proof.reference.isEmpty ? nil : $0.proof.reference,
                                    verifiedOn: $0.proof.verifiedOn?.description
                                )
                            }
                        )
                    }
                ),
                controlProofs: Dictionary(
                    uniqueKeysWithValues: model.controlProofs.map { key, proof in
                        (
                            key.value,
                            ControlProofJSON(
                                evidence: proof.evidence?.rawValue,
                                reference: proof.reference.isEmpty ? nil : proof.reference,
                                verifiedOn: proof.verifiedOn?.description
                            )
                        )
                    }
                ),
                controlNotes: Dictionary(
                    uniqueKeysWithValues: model.controlNotes.map { ($0.key.value, $0.value) }
                ),
                pathwayMitigations: PathwayMitigationsJSON(
                    isMasterEnabled: model.pathwayMitigations.isMasterEnabled,
                    configs: Dictionary(
                        uniqueKeysWithValues: model.pathwayMitigations.configs.map {
                            (
                                $0.key.value,
                                PathwayMitigationConfigJSON(
                                    isEnabled: $0.value.isEnabled,
                                    mode: $0.value.mode.rawValue,
                                    reductionPercent: $0.value.reductionPercent
                                )
                            )
                        }
                    )
                ),
                mitigatesEdges: model.mitigatesEdges.map {
                    MitigatesEdgeJSON(
                        source: $0.source.value,
                        target: $0.target.value,
                        threatIds: $0.threatIds.map(\.value),
                        reducesRiskBy: $0.reducesRiskBy,
                        status: $0.status?.rawValue,
                        action: $0.action.map {
                            EdgeActionJSON(
                                label: $0.label,
                                text: $0.text,
                                note: $0.note,
                                blockedBy: $0.blockedBy,
                                sources: $0.sources.isEmpty ? nil : $0.sources
                            )
                        }
                    )
                },
                recommendations: Dictionary(
                    uniqueKeysWithValues: model.recommendations.map { key, recommendations in
                        (
                            key.value,
                            recommendations.map {
                                RecommendationJSON(text: $0.text, note: $0.note, sources: $0.sources)
                            }
                        )
                    }
                ),
                likelihoodFindings: Dictionary(
                    uniqueKeysWithValues: model.likelihoodFindings.map { key, finding in
                        (
                            key.value,
                            LikelihoodFindingJSON(
                                label: finding.label,
                                likelihood: finding.likelihood.id,
                                rationale: finding.rationale,
                                sources: finding.sources
                            )
                        )
                    }
                ),
                severityDecisions: Dictionary(
                    uniqueKeysWithValues: model.severityDecisions.map { key, decision in
                        (
                            key.value,
                            SeverityDecisionJSON(
                                severityId: decision.severityId,
                                rationale: decision.rationale,
                                sources: decision.sources
                            )
                        )
                    }
                ),
                assumptions: model.assumptions.map {
                    SystemAssumptionJSON(label: $0.label, text: $0.text, owner: $0.owner)
                },
                riskTolerance: model.riskTolerance?.rawValue,
                owner: model.owner.isEmpty ? nil : model.owner,
                documentFacts: model.documentFacts.isEmpty
                    ? nil
                    : DocumentFactsJSON(
                        description: model.documentFacts.description,
                        authors: model.documentFacts.authors,
                        links: model.documentFacts.links,
                        repositories: model.documentFacts.repositories,
                        created: model.documentFacts.created,
                        reviewed: model.documentFacts.reviewed,
                        version: model.documentFacts.version,
                        attributes: model.documentFacts.attributes.map {
                            DocumentFactsJSON.AttributeJSON(name: $0.name, value: $0.value)
                        }
                    ),
                impactOverrides: model.impactOverrides.isEmpty
                    ? nil
                    : Dictionary(
                        uniqueKeysWithValues: model.impactOverrides.map { key, impacts in
                            (key.value, impacts.map(\.rawValue))
                        }
                    ),
                useCases: model.useCases.isEmpty
                    ? nil
                    : model.useCases.map { SystemUseCaseJSON(label: $0.label, text: $0.text) },
                exclusions: model.exclusions.isEmpty
                    ? nil
                    : model.exclusions.map {
                        SystemExclusionJSON(
                            label: $0.label,
                            text: $0.text,
                            rationale: $0.rationale
                        )
                    },
                systemAssets: model.systemAssets.isEmpty
                    ? nil
                    : model.systemAssets.map {
                        SystemAssetJSON(
                            id: $0.id,
                            name: $0.name,
                            classification: $0.classification.rawValue,
                            description: $0.description,
                            owner: $0.owner
                        )
                    },
                thirdParties: model.thirdParties.isEmpty
                    ? nil
                    : model.thirdParties.map {
                        ThirdPartyJSON(
                            id: $0.id,
                            name: $0.name,
                            description: $0.description,
                            kind: $0.kind.rawValue,
                            payingCustomer: $0.payingCustomer,
                            uptime: $0.uptime.rawValue,
                            uptimeNotes: $0.uptimeNotes,
                            owner: $0.owner,
                            link: $0.link
                        )
                    },
                diagrams: model.diagrams.isEmpty
                    ? nil
                    : model.diagrams.map {
                        SystemDiagramJSON(label: $0.label, kind: $0.kind, text: $0.text)
                    }
            )
        )
    }

    public func decode(_ data: Data) throws -> ThreatModel {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let document = try decoder.decode(DocumentJSON.self, from: data)

        guard Self.readableFormatVersions.contains(document.formatVersion) else {
            throw ThreatModelFileError.unsupportedFormatVersion(
                found: document.formatVersion,
                supported: Self.formatVersion
            )
        }

        var components = try document.components.map(Self.component(from:))
        let zones = try document.zones.map(Self.zone(from:))

        // A file written before version 7 states no membership, so it is read
        // from the coordinates the file holds. The picture and the membership
        // then say what they said when the file was written.
        if document.formatVersion < 7 {
            for index in components.indices {
                components[index].zoneId = ZoneContainment.zone(
                    holding: components[index].centre,
                    in: zones
                )?.id
            }
        }

        return ThreatModel(
            name: document.name,
            components: components,
            connections: try document.connections.map(Self.connection(from:)),
            zones: zones,
            // A file written before the element keying keys a component
            // override by its technology. Reading it forward writes that
            // override onto every component of that technology, so the user's
            // work survives the change.
            severityOverrides: SeverityOverrideMigration.migrated(
                Dictionary(
                    uniqueKeysWithValues: document.severityOverrides.map {
                        (SeverityOverrideKey($0.key), $0.value)
                    }
                ),
                components: components
            ),
            implementedControls: Set(document.implementedControls.map(ControlKey.init)),
            controlStatuses: Dictionary(
                uniqueKeysWithValues: (document.controlStatuses ?? [:]).compactMap { key, raw in
                    ControlStatus(rawValue: raw).map { (ControlKey(key), $0) }
                }
            ),
            compensatingControls: Dictionary(
                uniqueKeysWithValues: (document.compensatingControls ?? [:]).map { key, controls in
                    (
                        ThreatKey(key),
                        controls.map {
                            CompensatingControl(
                                label: $0.label,
                                reducesRiskBy: $0.reducesRiskBy,
                                rationale: $0.rationale,
                                sources: $0.sources ?? [],
                                proof: Self.proof(
                                    evidence: $0.evidence,
                                    reference: $0.reference,
                                    verifiedOn: $0.verifiedOn
                                )
                            )
                        }
                    )
                }
            ),
            mitigatesEdges: try (document.mitigatesEdges ?? []).map {
                MitigatesEdge(
                    source: ComponentId($0.source),
                    target: ComponentId($0.target),
                    threatIds: $0.threatIds.map(ThreatId.init),
                    reducesRiskBy: $0.reducesRiskBy,
                    status: try $0.status.map { raw in
                        try Self.value(MitigationStatus(rawValue: raw), field: "status", raw: raw)
                    },
                    action: $0.action.map {
                        EdgeAction(
                            label: $0.label,
                            text: $0.text,
                            note: $0.note,
                            blockedBy: $0.blockedBy,
                            sources: $0.sources ?? []
                        )
                    }
                )
            },
            recommendations: Dictionary(
                uniqueKeysWithValues: (document.recommendations ?? [:]).map { key, recommendations in
                    (
                        ThreatKey(key),
                        recommendations.map {
                            Recommendation(text: $0.text, note: $0.note, sources: $0.sources ?? [])
                        }
                    )
                }
            ),
            likelihoodFindings: Dictionary(
                uniqueKeysWithValues: try (document.likelihoodFindings ?? [:]).map { key, json in
                    (
                        ThreatKey(key),
                        LikelihoodFinding(
                            label: json.label,
                            likelihood: try Self.value(
                                Self.likelihood(from: json.likelihood),
                                field: "likelihood",
                                raw: json.likelihood
                            ),
                            rationale: json.rationale,
                            sources: json.sources ?? []
                        )
                    )
                }
            ),
            severityDecisions: Dictionary(
                uniqueKeysWithValues: (document.severityDecisions ?? [:]).map { key, json in
                    (
                        ThreatKey(key),
                        SeverityDecision(
                            severityId: json.severityId,
                            rationale: json.rationale,
                            sources: json.sources ?? []
                        )
                    )
                }
            ),
            impactOverrides: Dictionary(
                uniqueKeysWithValues: (document.impactOverrides ?? [:]).map { key, raw in
                    (ThreatKey(key), raw.compactMap(ThreatImpact.init(rawValue:)))
                }
            ),
            useCases: (document.useCases ?? []).map {
                SystemUseCase(label: $0.label, text: $0.text)
            },
            exclusions: (document.exclusions ?? []).map {
                SystemExclusion(label: $0.label, text: $0.text, rationale: $0.rationale)
            },
            systemAssets: (document.systemAssets ?? []).map {
                SystemAsset(
                    id: $0.id,
                    name: $0.name,
                    classification: DataSensitivity($0.classification),
                    description: $0.description,
                    owner: $0.owner
                )
            },
            thirdParties: (document.thirdParties ?? []).map {
                ThirdParty(
                    id: $0.id,
                    name: $0.name,
                    description: $0.description,
                    kind: ThirdPartyKind(rawValue: $0.kind) ?? .saas,
                    payingCustomer: $0.payingCustomer,
                    uptime: UptimeDependency(rawValue: $0.uptime) ?? .none,
                    uptimeNotes: $0.uptimeNotes,
                    owner: $0.owner,
                    link: $0.link
                )
            },
            diagrams: (document.diagrams ?? []).map {
                SystemDiagram(label: $0.label, kind: $0.kind, text: $0.text)
            },
            assumptions: (document.assumptions ?? []).map {
                SystemAssumption(label: $0.label, text: $0.text, owner: $0.owner)
            },
            riskTolerance: try document.riskTolerance.map { raw in
                try Self.value(RiskLevel(rawValue: raw), field: "riskTolerance", raw: raw)
            },
            pathwayMitigations: PathwayMitigationSettings(
                isMasterEnabled: document.pathwayMitigations.isMasterEnabled,
                configs: Dictionary(
                    uniqueKeysWithValues: try document.pathwayMitigations.configs.map { id, config in
                        (
                            PathwayMitigationId(id),
                            PathwayMitigationConfig(
                                isEnabled: config.isEnabled,
                                mode: try Self.value(
                                    PathwayMitigationMode(rawValue: config.mode),
                                    field: "mode",
                                    raw: config.mode
                                ),
                                reductionPercent: config.reductionPercent
                            )
                        )
                    }
                )
            ),
            customTechnologies: document.customTechnologies.map(Self.customTechnology(from:)),
            owner: document.owner ?? "",
            documentFacts: DocumentFacts(
                description: document.documentFacts?.description ?? "",
                authors: document.documentFacts?.authors ?? [],
                links: document.documentFacts?.links ?? [],
                repositories: document.documentFacts?.repositories ?? [],
                created: document.documentFacts?.created ?? "",
                reviewed: document.documentFacts?.reviewed ?? "",
                version: document.documentFacts?.version ?? "",
                attributes: (document.documentFacts?.attributes ?? []).map {
                    (name: $0.name, value: $0.value)
                }
            ),
            controlProofs: Dictionary(
                uniqueKeysWithValues: (document.controlProofs ?? [:]).map { key, proof in
                    (
                        ControlKey(key),
                        Self.proof(
                            evidence: proof.evidence,
                            reference: proof.reference,
                            verifiedOn: proof.verifiedOn
                        )
                    )
                }
            ),
            controlNotes: Dictionary(
                uniqueKeysWithValues: (document.controlNotes ?? [:]).map { (ControlKey($0.key), $0.value) }
            ),
            createdAt: document.createdAt,
            updatedAt: document.updatedAt,
            catalogueVersion: document.catalogue.map {
                CatalogueVersion(repository: $0.repository, tag: $0.tag)
            }
        )
    }

    public func encodeSelection(_ selection: SelectionSnippet) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        let data = try encoder.encode(
            SelectionJSON(
                formatVersion: Self.formatVersion,
                components: selection.components.map(Self.json(from:)),
                connections: selection.connections.map(Self.json(from:)),
                zones: selection.zones.map(Self.json(from:)),
                controlStatuses: Dictionary(
                    uniqueKeysWithValues: selection.controlStatuses.map {
                        ($0.key.value, $0.value.rawValue)
                    }
                ),
                severityOverrides: Dictionary(
                    uniqueKeysWithValues: selection.severityOverrides.map {
                        ($0.key.value, $0.value)
                    }
                ),
                likelihoodFindings: Dictionary(
                    uniqueKeysWithValues: selection.likelihoodFindings.map { key, finding in
                        (
                            key.value,
                            LikelihoodFindingJSON(
                                label: finding.label,
                                likelihood: finding.likelihood.id,
                                rationale: finding.rationale,
                                sources: finding.sources
                            )
                        )
                    }
                )
            )
        )
        return String(decoding: data, as: UTF8.self)
    }

    public func decodeSelection(_ text: String) throws -> SelectionSnippet {
        let snippet = try JSONDecoder().decode(SelectionJSON.self, from: Data(text.utf8))

        guard Self.readableFormatVersions.contains(snippet.formatVersion) else {
            throw ThreatModelFileError.unsupportedFormatVersion(
                found: snippet.formatVersion,
                supported: Self.formatVersion
            )
        }

        return SelectionSnippet(
            components: try snippet.components.map(Self.component(from:)),
            connections: try snippet.connections.map(Self.connection(from:)),
            zones: try snippet.zones.map(Self.zone(from:)),
            controlStatuses: Dictionary(
                uniqueKeysWithValues: (snippet.controlStatuses ?? [:]).compactMap { key, raw in
                    ControlStatus(rawValue: raw).map { (ControlKey(key), $0) }
                }
            ),
            severityOverrides: Dictionary(
                uniqueKeysWithValues: (snippet.severityOverrides ?? [:]).map {
                    (SeverityOverrideKey($0.key), $0.value)
                }
            ),
            likelihoodFindings: Dictionary(
                uniqueKeysWithValues: try (snippet.likelihoodFindings ?? [:]).map { key, json in
                    (
                        ThreatKey(key),
                        LikelihoodFinding(
                            label: json.label,
                            likelihood: try Self.value(
                                Self.likelihood(from: json.likelihood),
                                field: "likelihood",
                                raw: json.likelihood
                            ),
                            rationale: json.rationale,
                            sources: json.sources ?? []
                        )
                    )
                }
            )
        )
    }

    // MARK: one value at a time, shared by the document and the snippet

    private static func json(from component: ThreatModelKit.Component) -> ComponentJSON {
        ComponentJSON(
            id: component.id.value,
            technologyId: component.technologyId.value,
            x: component.position.x,
            y: component.position.y,
            sensitivity: component.sensitivity.rawValue,
            customName: component.customName,
            threatsDisabled: component.threatsDisabled,
            runsAs: component.runsAs.rawValue,
            assets: component.assets.map {
                AssetJSON(name: $0.name, sensitivity: $0.sensitivity.rawValue)
            },
            shape: component.shape?.rawValue,
            zoneId: component.zoneId?.value,
            holds: component.holds.isEmpty ? nil : component.holds,
            statesOwnSensitivity: component.statesOwnSensitivity ? nil : false,
            providedBy: component.providedBy,
            user: component.user.map {
                UserJSON(role: $0.role, reaches: $0.reaches, threatActorId: $0.threatActorId)
            }
        )
    }

    private static func json(from technology: CustomTechnology) -> CustomTechnologyJSON {
        CustomTechnologyJSON(
            id: technology.id.value,
            name: technology.name,
            category: technology.category.value,
            description: technology.description,
            threatIds: technology.threatIds.map(\.value),
            enforcesEncryption: technology.enforcesEncryption,
            controls: technology.controls.isEmpty ? nil : technology.controls
        )
    }

    private static func customTechnology(from json: CustomTechnologyJSON) -> CustomTechnology {
        CustomTechnology(
            id: TechnologyId(json.id),
            name: json.name,
            category: CategoryId(json.category),
            description: json.description,
            threatIds: json.threatIds.map(ThreatId.init),
            enforcesEncryption: json.enforcesEncryption,
            controls: json.controls ?? []
        )
    }

    private static func json(from connection: Connection) -> ConnectionJSON {
        ConnectionJSON(
            id: connection.id.value,
            source: connection.source.value,
            target: connection.target.value,
            kind: connection.kind.rawValue,
            description: connection.description,
            carries: connection.carries.isEmpty ? nil : connection.carries
        )
    }

    private static func json(from zone: Zone) -> ZoneJSON {
        ZoneJSON(
            id: zone.id.value,
            x: zone.rect.origin.x,
            y: zone.rect.origin.y,
            width: zone.rect.size.width,
            height: zone.rect.size.height,
            name: zone.name,
            networkZone: zone.networkZone.rawValue,
            networkType: zone.networkType.rawValue,
            riskReductionEnabled: zone.riskReductionEnabled,
            riskReductionPercent: zone.riskReductionPercent,
            boundary: zone.boundary.rawValue,
            description: zone.description
        )
    }

    private static func component(from json: ComponentJSON) throws -> ThreatModelKit.Component {
        ThreatModelKit.Component(
            id: ComponentId(json.id),
            technologyId: TechnologyId(json.technologyId),
            position: Point(x: json.x, y: json.y),
            sensitivity: try value(
                DataSensitivity(json.sensitivity),
                field: "sensitivity",
                raw: json.sensitivity
            ),
            customName: json.customName,
            threatsDisabled: json.threatsDisabled,
            runsAs: try optionalValue(PrivilegeLevel.self, field: "runsAs", raw: json.runsAs, default: .default),
            assets: (json.assets ?? []).map {
                Asset(
                    name: $0.name,
                    sensitivity: DataSensitivity($0.sensitivity)
                )
            },
            holds: json.holds ?? [],
            providedBy: json.providedBy,
            statesOwnSensitivity: json.statesOwnSensitivity ?? true,
            shape: try optionalShape(from: json.shape),
            zoneId: json.zoneId.map(ZoneId.init),
            user: json.user.map {
                UserFacts(role: $0.role, reaches: $0.reaches, threatActorId: $0.threatActorId)
            }
        )
    }

    private static func connection(from json: ConnectionJSON) throws -> Connection {
        Connection(
            id: ConnectionId(json.id),
            source: ComponentId(json.source),
            target: ComponentId(json.target),
            kind: try optionalValue(FlowKind.self, field: "kind", raw: json.kind, default: .default),
            description: json.description,
            carries: json.carries ?? []
        )
    }

    private static func zone(from json: ZoneJSON) throws -> Zone {
        Zone(
            id: ZoneId(json.id),
            rect: Rect(x: json.x, y: json.y, width: json.width, height: json.height),
            name: json.name,
            networkZone: try value(
                NetworkZone(rawValue: json.networkZone),
                field: "networkZone",
                raw: json.networkZone
            ),
            networkType: try value(
                ZoneNetworkType(rawValue: json.networkType),
                field: "networkType",
                raw: json.networkType
            ),
            riskReductionEnabled: json.riskReductionEnabled,
            riskReductionPercent: json.riskReductionPercent,
            boundary: try optionalValue(ZoneBoundary.self, field: "boundary", raw: json.boundary, default: .default),
            description: json.description
        )
    }

    /// What proves a control, read back. A tier or a date this application
    /// does not hold is dropped, not refused: the file was written by a build
    /// that held it, and the rest of the proof still reads.
    private static func proof(
        evidence: String?,
        reference: String?,
        verifiedOn: String?
    ) -> ControlProof {
        ControlProof(
            evidence: evidence.flatMap(ControlEvidence.init(rawValue:)),
            reference: reference ?? "",
            verifiedOn: verifiedOn.flatMap { try? GovernanceDate.read($0).get() }
        )
    }

    /// A likelihood is a named tier or a whole-number prior, either read back
    /// from the string a finding's `id` already is. Nil when the string is
    /// neither.
    private static func likelihood(from raw: String) -> Likelihood? {
        Likelihood(rawValue: raw) ?? Int(raw).flatMap(Likelihood.init(prior:))
    }

    /// A vocabulary value this application does not hold is refused by name, so
    /// the message says which field and which value rather than "corrupt file".
    private static func value<T>(_ decoded: T?, field: String, raw: String) throws -> T {
        guard let decoded else {
            throw ThreatModelFileError.unknownValue(field: field, value: raw)
        }
        return decoded
    }

    /// A field added after version 1: an absent value takes the default, the
    /// way every field this format has ever added does. A present value this
    /// application does not hold is refused by name, the same as `value`
    /// refuses one of its older, required neighbours.
    /// The shape the file states, or nil when it states none. A word this
    /// application does not hold is refused by name, the way `optionalValue`
    /// refuses one.
    private static func optionalShape(from raw: String?) throws -> DiagramShape? {
        guard let raw else { return nil }
        guard let shape = DiagramShape(rawValue: raw) else {
            throw ThreatModelFileError.unknownValue(field: "shape", value: raw)
        }
        return shape
    }

    private static func optionalValue<T: RawRepresentable>(
        _ type: T.Type,
        field: String,
        raw: String?,
        default fallback: T
    ) throws -> T where T.RawValue == String {
        guard let raw else { return fallback }
        guard let decoded = T(rawValue: raw) else {
            throw ThreatModelFileError.unknownValue(field: field, value: raw)
        }
        return decoded
    }
}
