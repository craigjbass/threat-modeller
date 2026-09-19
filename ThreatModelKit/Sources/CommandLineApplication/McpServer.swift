import ArchitectureDSL
import CatalogueGateways
import Foundation
import ThreatModelKit

/// Offers the model, the catalogue and the verbs to a Model Context Protocol
/// client.
///
/// An assistant reading the files as text guesses what they mean. This hands
/// it the assessed model, the catalogue and the verbs, each through the same
/// use case a person's own run goes through, so the answers are the
/// application's answers.
///
/// The server is text in and text out: one JSON-RPC request, one JSON-RPC
/// response. A test drives it with a fake client and no pipe.
public struct McpServer {
    /// What this server calls itself when a client asks.
    public static let name = "threatmodeller"
    /// The version of the Model Context Protocol this speaks.
    public static let protocolVersion = "2025-06-18"

    private let application: CommandLineApplication
    private let projects: ProjectSourceGateway
    private let root: String
    /// False keeps every tool read only: a tool that would write a file says
    /// what it would write and writes nothing.
    private let allowsWrites: Bool

    public init(
        application: CommandLineApplication,
        projects: ProjectSourceGateway,
        root: String,
        allowsWrites: Bool
    ) {
        self.application = application
        self.projects = projects
        self.root = root
        self.allowsWrites = allowsWrites
    }

    /// One request, and what to write back. Nil for a notification, which
    /// takes no answer.
    public func answer(to line: String) -> String? {
        guard let data = line.data(using: .utf8),
              let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let method = request["method"] as? String else {
            return Self.error(id: nil, code: -32700, message: "the request is not JSON")
        }
        let id = request["id"]
        guard id != nil else { return nil }

        switch method {
        case "initialize":
            return Self.result(
                id: id,
                [
                    "protocolVersion": Self.protocolVersion,
                    "capabilities": ["tools": [String: Any](), "resources": [String: Any]()],
                    "serverInfo": ["name": Self.name, "version": Self.version]
                ]
            )
        case "tools/list":
            return Self.result(id: id, ["tools": tools()])
        case "tools/call":
            let parameters = request["params"] as? [String: Any] ?? [:]
            let name = parameters["name"] as? String ?? ""
            let arguments = parameters["arguments"] as? [String: Any] ?? [:]
            return call(name: name, arguments: arguments, id: id)
        case "resources/list":
            return Self.result(id: id, ["resources": resources()])
        case "resources/read":
            let parameters = request["params"] as? [String: Any] ?? [:]
            return read(uri: parameters["uri"] as? String ?? "", id: id)
        case "ping":
            return Self.result(id: id, [String: Any]())
        default:
            return Self.error(id: id, code: -32601, message: "there is no method \"\(method)\"")
        }
    }

    /// The version this server states. It is the tool's own version.
    static let version = "1.0.0"

    // MARK: the tools

    /// Every tool, and what each takes. A tool that writes is listed only
    /// when the server was started with `--allow-writes`, so a client never
    /// offers a person a tool that would refuse.
    func tools() -> [[String: Any]] {
        var listed: [[String: Any]] = [
            tool(
                "list_systems",
                "Say what each system in the project holds and what it scores.",
                properties: [:]
            ),
            tool(
                "read_system",
                "Read one system's whole assessment, in the shape"
                    + " docs/threatmodel-export.schema.json states.",
                properties: ["system": ["type": "string", "description": "the system's name"]]
            ),
            tool(
                "check",
                "Say what has no answer, the way `threatmodeller check` does."
                    + " It writes nothing.",
                properties: [
                    "tolerance": [
                        "type": "string",
                        "description": "low, medium, high or critical"
                    ]
                ]
            ),
            tool(
                "compile",
                allowsWrites
                    ? "Write or merge every .controls file."
                    : "Say what a compile would write. This server is read only,"
                        + " so it writes nothing.",
                properties: [:]
            ),
            tool(
                "describe_threat",
                "Describe one threat the catalogue holds: its severity, its stride"
                    + " categories, what it harms and its controls.",
                properties: ["id": ["type": "string", "description": "the threat's id"]]
            ),
            tool(
                "describe_technology",
                "Describe one technology the catalogue holds and the threats it raises.",
                properties: ["id": ["type": "string", "description": "the technology's id"]]
            ),
            tool(
                "describe_control",
                "Find every threat the catalogue answers with a control whose"
                    + " description holds these words.",
                properties: ["words": ["type": "string", "description": "what to look for"]]
            ),
            tool(
                "open_threats_above",
                "List the threats nobody has answered at this risk level or worse.",
                properties: [
                    "level": ["type": "string", "description": "low, medium, high or critical"],
                    "system": ["type": "string", "description": "the system's name, or every one"]
                ]
            )
        ]

        guard allowsWrites else { return listed }
        listed.append(
            tool(
                "answer_control",
                "Answer one control on one threat and write the .controls file.",
                properties: [
                    "system": ["type": "string", "description": "the system's name"],
                    "threat": ["type": "string", "description": "the threat's id"],
                    "element": [
                        "type": "string",
                        "description": "the component, flow or zone the threat is raised on"
                    ],
                    "control": [
                        "type": "string",
                        "description": "the control's description, word for word"
                    ],
                    "status": [
                        "type": "string",
                        "description": "implemented, not_implemented, not_applicable or accepted"
                    ],
                    "note": ["type": "string", "description": "why, in the team's own words"]
                ]
            )
        )
        listed.append(
            tool(
                "set_likelihood",
                "Write a likelihood finding on one threat and write the .controls file.",
                properties: [
                    "system": ["type": "string", "description": "the system's name"],
                    "threat": ["type": "string", "description": "the threat's id"],
                    "element": [
                        "type": "string",
                        "description": "the component, flow or zone the threat is raised on"
                    ],
                    "label": ["type": "string", "description": "what the finding is called"],
                    "tier": [
                        "type": "string",
                        "description": Likelihood.tierWordsAsProse
                    ],
                    "prior": [
                        "type": "integer",
                        "description": "a percentage, 0 to 100, instead of a tier"
                    ],
                    "rationale": ["type": "string", "description": "why"]
                ]
            )
        )
        return listed
    }

    private func tool(
        _ name: String,
        _ description: String,
        properties: [String: Any]
    ) -> [String: Any] {
        [
            "name": name,
            "description": description,
            "inputSchema": [
                "type": "object",
                "properties": properties
            ]
        ]
    }

    private func call(name: String, arguments: [String: Any], id: Any?) -> String? {
        func text(_ key: String) -> String? {
            (arguments[key] as? String).flatMap { $0.isEmpty ? nil : $0 }
        }

        switch name {
        case "list_systems":
            return answered(id: id, run(["list", root, "--json"]))
        case "read_system":
            return answered(id: id, run(["export", systemRoot(named: text("system")), "--format", "json", "--stdout"]))
        case "check":
            var words = ["check", root, "--format", "json"]
            if let tolerance = text("tolerance") { words += ["--tolerance", tolerance] }
            return answered(id: id, run(words))
        case "compile":
            guard allowsWrites else {
                let said = run(["check", root, "--format", "json"])
                return answered(
                    id: id,
                    "This server is read only, so nothing was written. What a compile"
                        + " would answer, from `check`:\n\(said)"
                )
            }
            return answered(id: id, run(["compile", root]))
        case "describe_threat", "describe_technology", "describe_control", "open_threats_above":
            return answered(id: id, describe(name, arguments: arguments))
        case "answer_control", "set_likelihood":
            guard allowsWrites else {
                return Self.error(
                    id: id,
                    code: -32000,
                    message: "this server is read only; start it with --allow-writes to write"
                )
            }
            return answered(id: id, write(name, arguments: arguments))
        default:
            return Self.error(id: id, code: -32602, message: "there is no tool \"\(name)\"")
        }
    }

    /// A system's own directory when a project holds many, so a verb reading
    /// one system reads that one.
    private func systemRoot(named name: String?) -> String {
        guard let name,
              let layout = try? projects.discover(root: root),
              layout.systems.count > 1,
              let system = layout.systems.first(where: { $0.name == name }) else { return root }
        // A split system is a directory; a flat one is a file beside others.
        return system.isSplit
            ? String(system.architecturePath.dropLast(system.headerPath.count - system.name.count))
            : root
    }

    // MARK: what the catalogue says

    private func describe(_ name: String, arguments: [String: Any]) -> String {
        switch name {
        case "describe_threat":
            return catalogueAnswer { catalogue in
                let wanted = (arguments["id"] as? String) ?? ""
                let every = catalogue.connectionThreats() + catalogue.zoneThreats()
                    + catalogue.all().flatMap { catalogue.threatsFor(technologyId: $0.id) }
                guard let threat = every.first(where: { $0.id.value == wanted }) else {
                    return "the catalogue holds no threat \"\(wanted)\""
                }
                var said = [
                    "\(threat.id.value): \(threat.name)",
                    threat.description,
                    "severity: \(threat.severity.label)",
                    "stride: \(threat.stride.map(\.value).joined(separator: ", "))",
                    "harms: \(threat.impacts.map(\.label).joined(separator: ", "))"
                ]
                if threat.controls.isEmpty == false {
                    said.append("controls:")
                    said += threat.controls.map { "- \($0.description)" }
                }
                return said.joined(separator: "\n")
            }
        case "describe_technology":
            return catalogueAnswer { catalogue in
                let wanted = (arguments["id"] as? String) ?? ""
                guard let technology = catalogue.findById(TechnologyId(wanted)) else {
                    return "the catalogue holds no technology \"\(wanted)\""
                }
                let threats = catalogue.threatsFor(technologyId: technology.id)
                return (
                    [
                        "\(technology.id.value): \(technology.name)",
                        technology.description,
                        "category: \(technology.category.value)",
                        "raises \(threats.count) threats:"
                    ] + threats.map { "- \($0.id.value): \($0.name) (\($0.severity.label))" }
                ).joined(separator: "\n")
            }
        case "describe_control":
            return catalogueAnswer { catalogue in
                let words = ((arguments["words"] as? String) ?? "").lowercased()
                guard words.isEmpty == false else { return "state the words to look for" }
                var found: [String] = []
                for technology in catalogue.all() {
                    for threat in catalogue.threatsFor(technologyId: technology.id) {
                        for control in threat.controls
                        where control.description.lowercased().contains(words) {
                            found.append(
                                "\(technology.id.value) / \(threat.id.value): \(control.description)"
                            )
                        }
                    }
                }
                return found.isEmpty
                    ? "no control holds \"\(words)\""
                    : found.sorted().joined(separator: "\n")
            }
        case "open_threats_above":
            let level = (arguments["level"] as? String) ?? "high"
            guard let wanted = RiskLevel(rawValue: level) else {
                return "there is no level \"\(level)\"; this application holds low, medium,"
                    + " high, critical"
            }
            let text = run(["export", systemRoot(named: arguments["system"] as? String), "--format", "json", "--stdout"])
            guard let data = text.data(using: .utf8),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let threats = json["threats"] as? [[String: Any]] else {
                return text
            }
            let open = threats.filter { threat in
                guard threat["isOpen"] as? Bool == true,
                      let named = threat["riskLevel"] as? String,
                      let level = RiskLevel(rawValue: named) else { return false }
                return level.rank >= wanted.rank
            }
            guard open.isEmpty == false else {
                return "no threat at \(wanted.label) or worse is unanswered"
            }
            return open
                .map { threat in
                    "\(threat["riskScore"] as? Int ?? 0) \(threat["riskLevel"] as? String ?? "")"
                        + " \(threat["name"] as? String ?? "")"
                        + " on \(threat["sourceName"] as? String ?? "")"
                }
                .joined(separator: "\n")
        default:
            return "there is no tool \"\(name)\""
        }
    }

    /// The catalogue this project reads, or what stopped it being read.
    private func catalogueAnswer(_ say: (TechnologyCatalogue) -> String) -> String {
        do {
            return say(try BundledTechnologyCatalogue())
        } catch {
            return "the catalogue could not be loaded: \(error)"
        }
    }

    // MARK: what writes

    /// A write goes through the file the application writes, so a person's
    /// next compile reads what an assistant wrote.
    private func write(_ name: String, arguments: [String: Any]) -> String {
        let system = (arguments["system"] as? String) ?? ""
        let threat = (arguments["threat"] as? String) ?? ""
        let element = (arguments["element"] as? String) ?? ""
        guard threat.isEmpty == false, element.isEmpty == false else {
            return "state the threat and the element it is raised on"
        }

        guard let layout = try? projects.discover(root: root),
              let found = layout.systems.first(where: { system.isEmpty || $0.name == system })
        else {
            return "this project holds no system \"\(system)\""
        }
        guard let controlsText = try? projects.read(path: found.controlsPath) else {
            return "there is no \(found.controlsPath); run compile first"
        }

        let source = HclControlsSource()
        guard let read = source.read(controlsText).source else {
            return "\(found.controlsPath) does not parse"
        }
        guard let answer = read.answers.first(where: {
            $0.threatId == threat && $0.sourceId == element
        }) else {
            return "this system raises no \"\(threat)\" on \"\(element)\""
        }

        let written: SourceThreatAnswer
        switch name {
        case "answer_control":
            let description = (arguments["control"] as? String) ?? ""
            let status = ControlStatus(rawValue: (arguments["status"] as? String) ?? "")
            guard let status else {
                return "state a status: "
                    + ControlStatus.allCases.map(\.rawValue).joined(separator: ", ")
            }
            guard answer.controls.contains(where: { $0.description == description }) else {
                return "\"\(threat)\" offers no control \"\(description)\""
            }
            written = SourceThreatAnswer(
                threatId: answer.threatId,
                sourceKind: answer.sourceKind,
                sourceId: answer.sourceId,
                severityLabel: answer.severityLabel,
                score: answer.score,
                likelihood: answer.likelihood,
                severityDecision: answer.severityDecision,
                impacts: answer.impacts,
                controls: answer.controls.map { control in
                    guard control.description == description else { return control }
                    return SourceControlAnswer(
                        description: control.description,
                        status: status,
                        note: arguments["note"] as? String,
                        proof: control.proof
                    )
                },
                compensating: answer.compensating,
                recommendations: answer.recommendations,
                isStale: answer.isStale
            )
        default:
            let tier = arguments["tier"] as? String
            let prior = arguments["prior"] as? Int
            let likelihood = prior.flatMap(Likelihood.init(prior:))
                ?? tier.flatMap(Likelihood.init(rawValue:))
            guard let likelihood else {
                return "state a tier — \(Likelihood.tierWordsAsProse) — or a prior from 0 to 100"
            }
            written = SourceThreatAnswer(
                threatId: answer.threatId,
                sourceKind: answer.sourceKind,
                sourceId: answer.sourceId,
                severityLabel: answer.severityLabel,
                score: answer.score,
                likelihood: LikelihoodFinding(
                    label: (arguments["label"] as? String) ?? "Likelihood",
                    likelihood: likelihood,
                    rationale: (arguments["rationale"] as? String) ?? "",
                    sources: []
                ),
                severityDecision: answer.severityDecision,
                impacts: answer.impacts,
                controls: answer.controls,
                compensating: answer.compensating,
                recommendations: answer.recommendations,
                isStale: answer.isStale
            )
        }

        let rewritten = source.write(
            ControlsSource(
                systemName: read.systemName,
                catalogueTag: read.catalogueTag,
                riskTolerance: read.riskTolerance,
                answers: read.answers.map {
                    $0.threatId == threat && $0.sourceId == element ? written : $0
                },
                trees: read.trees
            )
        )
        do {
            try projects.write(rewritten, to: found.controlsPath)
        } catch {
            return "\(found.controlsPath) could not be written: \(error)"
        }
        return "wrote \(found.controlsPath)"
    }

    // MARK: the files

    /// Every source file the project holds, read only.
    func resources() -> [[String: Any]] {
        guard let layout = try? projects.discover(root: root) else { return [] }

        var paths: [String] = []
        for system in layout.systems {
            paths += system.architecturePaths
            paths += system.controlsPaths
            paths += system.attackTreePaths
            paths.append(system.governancePath)
        }
        paths.append(layout.policyPath)
        paths += layout.libraryPaths

        return paths
            .filter { projects.exists(path: $0) }
            .sorted()
            .map { path in
                [
                    "uri": "file://\(path)",
                    "name": path.split(separator: "/").last.map(String.init) ?? path,
                    "mimeType": "text/plain"
                ]
            }
    }

    private func read(uri: String, id: Any?) -> String? {
        let path = uri.hasPrefix("file://") ? String(uri.dropFirst("file://".count)) : uri
        guard resources().contains(where: { ($0["uri"] as? String) == "file://\(path)" }),
              let text = try? projects.read(path: path) else {
            return Self.error(id: id, code: -32602, message: "this project holds no \(uri)")
        }
        return Self.result(
            id: id,
            ["contents": [["uri": uri, "mimeType": "text/plain", "text": text]]]
        )
    }

    // MARK: running a verb

    /// One verb, and everything it said. The verb is the application's own,
    /// so an assistant and a person read the same answer.
    private func run(_ words: [String]) -> String {
        var lines: [String] = []
        _ = application.run(arguments: ["threatmodeller"] + words, output: { lines.append($0) })
        return lines.joined(separator: "\n")
    }

    // MARK: JSON-RPC

    private func answered(id: Any?, _ text: String) -> String {
        Self.result(id: id, ["content": [["type": "text", "text": text]]])
    }

    static func result(id: Any?, _ value: [String: Any]) -> String {
        write(["jsonrpc": "2.0", "id": id ?? NSNull(), "result": value])
    }

    static func error(id: Any?, code: Int, message: String) -> String {
        write([
            "jsonrpc": "2.0",
            "id": id ?? NSNull(),
            "error": ["code": code, "message": message]
        ])
    }

    private static func write(_ value: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(
            withJSONObject: value,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ) else {
            return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"unwritable\"}}"
        }
        return String(decoding: data, as: UTF8.self)
    }
}
