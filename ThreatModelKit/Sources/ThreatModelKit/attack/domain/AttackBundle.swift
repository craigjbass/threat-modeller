import Foundation

/// One ATT&CK group, as the data directory holds it.
public struct AttackGroup: Equatable, Sendable {
    public let id: String
    public let attackId: String
    public let name: String
    public let aliases: [String]
    public let description: String
    /// A `uses` relationship from the group straight to a technique.
    public let techniques: [String]
    /// A `uses` relationship from the group to a tool, and from that tool to a
    /// technique. Written and not read by the likelihood rule: a group using a
    /// tool that does a hundred things is not the group doing them.
    public let techniquesViaSoftware: [String]

    public init(
        id: String,
        attackId: String,
        name: String,
        aliases: [String] = [],
        description: String = "",
        techniques: [String] = [],
        techniquesViaSoftware: [String] = []
    ) {
        self.id = id
        self.attackId = attackId
        self.name = name
        self.aliases = aliases
        self.description = description
        self.techniques = techniques
        self.techniquesViaSoftware = techniquesViaSoftware
    }
}

/// One ATT&CK technique, as the data directory holds it.
public struct AttackTechnique: Equatable, Sendable {
    public let id: String
    public let name: String
    public let tactics: [String]
    public let isSubTechnique: Bool

    public init(id: String, name: String, tactics: [String] = [], isSubTechnique: Bool = false) {
        self.id = id
        self.name = name
        self.tactics = tactics
        self.isSubTechnique = isSubTechnique
    }
}

/// Reads a STIX bundle and states the groups and the techniques it holds.
///
/// A pure function of the bytes, so a test runs it over a small fixture. It
/// reads `intrusion-set` and `attack-pattern` objects and the `uses`
/// relationships between them, and drops anything revoked, anything deprecated
/// and anything with no `mitre-attack` reference to name it by.
public enum AttackBundle {
    public enum Fault: Error, Equatable, Sendable {
        case notAStixBundle

        public var message: String {
            switch self {
            case .notAStixBundle:
                "that file is not a STIX bundle this application reads"
            }
        }
    }

    public struct Extracted: Equatable, Sendable {
        public let groups: [AttackGroup]
        public let techniques: [AttackTechnique]

        public init(groups: [AttackGroup], techniques: [AttackTechnique]) {
            self.groups = groups
            self.techniques = techniques
        }
    }

    public static func extract(_ data: Data) throws -> Extracted {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let objects = json["objects"] as? [[String: Any]] else {
            throw Fault.notAStixBundle
        }

        var groupsByStixId: [String: [String: Any]] = [:]
        var techniquesByStixId: [String: AttackTechnique] = [:]
        var softwareStixIds: Set<String> = []
        var relationships: [[String: Any]] = []

        for object in objects {
            let kind = object["type"] as? String ?? ""
            switch kind {
            case "intrusion-set":
                guard isLive(object), attackId(of: object) != nil else { continue }
                groupsByStixId[object["id"] as? String ?? ""] = object
            case "attack-pattern":
                guard isLive(object), let attack = attackId(of: object) else { continue }
                techniquesByStixId[object["id"] as? String ?? ""] = AttackTechnique(
                    id: attack,
                    name: object["name"] as? String ?? attack,
                    tactics: (object["kill_chain_phases"] as? [[String: Any]] ?? [])
                        .compactMap { $0["phase_name"] as? String },
                    isSubTechnique: object["x_mitre_is_subtechnique"] as? Bool ?? false
                )
            case "malware", "tool":
                softwareStixIds.insert(object["id"] as? String ?? "")
            case "relationship":
                guard object["relationship_type"] as? String == "uses" else { continue }
                relationships.append(object)
            default:
                continue
            }
        }

        // A group's own techniques, and the techniques of the software it uses.
        var direct: [String: [String]] = [:]
        var viaSoftware: [String: Set<String>] = [:]
        var softwareTechniques: [String: [String]] = [:]
        var groupSoftware: [String: [String]] = [:]

        for relationship in relationships {
            let source = relationship["source_ref"] as? String ?? ""
            let target = relationship["target_ref"] as? String ?? ""

            if groupsByStixId[source] != nil, let technique = techniquesByStixId[target] {
                if direct[source]?.contains(technique.id) != true {
                    direct[source, default: []].append(technique.id)
                }
            } else if groupsByStixId[source] != nil, softwareStixIds.contains(target) {
                groupSoftware[source, default: []].append(target)
            } else if softwareStixIds.contains(source), let technique = techniquesByStixId[target] {
                softwareTechniques[source, default: []].append(technique.id)
            }
        }

        for (group, software) in groupSoftware {
            for tool in software {
                for technique in softwareTechniques[tool] ?? [] {
                    viaSoftware[group, default: []].insert(technique)
                }
            }
        }

        let groups = groupsByStixId.map { stixId, object -> AttackGroup in
            let name = object["name"] as? String ?? ""
            return AttackGroup(
                id: identifier(of: name),
                attackId: attackId(of: object) ?? "",
                name: name,
                aliases: (object["aliases"] as? [String] ?? []).filter { $0 != name },
                description: firstParagraph(of: object["description"] as? String ?? ""),
                techniques: (direct[stixId] ?? []).sorted(),
                techniquesViaSoftware: (viaSoftware[stixId] ?? []).sorted()
            )
        }
        .sorted { $0.id < $1.id }

        return Extracted(
            groups: groups,
            techniques: techniquesByStixId.values.sorted { $0.id < $1.id }
        )
    }

    /// The group's identifier: its name, lower case, with every run of
    /// characters that is not a letter or a digit becoming one hyphen.
    public static func identifier(of name: String) -> String {
        var parts: [String] = []
        var current = ""
        for character in name.lowercased() {
            if character.isLetter || character.isNumber {
                current.append(character)
            } else if current.isEmpty == false {
                parts.append(current)
                current = ""
            }
        }
        if current.isEmpty == false { parts.append(current) }
        return parts.joined(separator: "-")
    }

    private static func isLive(_ object: [String: Any]) -> Bool {
        (object["revoked"] as? Bool ?? false) == false
            && (object["x_mitre_deprecated"] as? Bool ?? false) == false
    }

    private static func attackId(of object: [String: Any]) -> String? {
        let references = object["external_references"] as? [[String: Any]] ?? []
        return references
            .first { $0["source_name"] as? String == "mitre-attack" }?["external_id"] as? String
    }

    /// The first paragraph, cut at 400 characters, so a description reads on
    /// one card.
    private static func firstParagraph(of text: String) -> String {
        let paragraph = text.components(separatedBy: "\n\n").first ?? text
        guard paragraph.count > 400 else { return paragraph }
        return String(paragraph.prefix(400))
    }
}
