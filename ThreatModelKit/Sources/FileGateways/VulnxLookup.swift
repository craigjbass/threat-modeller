import Foundation
import ThreatModelKit

/// Runs `vulnx` as a child process, the way `git` and `curl` are run.
///
/// The tool is found on `PATH` through `/usr/bin/env`, so the person's own
/// install is the one that runs. The `PATH` is the one `ShellPath` reads, so a
/// window started from the Finder finds a tool under `~/go/bin` the way a
/// terminal does. The application ships no tool. The command
/// is `vulnx search --json --limit 50 <product> [<version>]`, and the records
/// are read from the JSON it prints, one object per line or one array.
public struct VulnxLookup: VulnerabilityLookup {
    private let timeout: TimeInterval
    /// The `PATH` the tool is looked for on.
    private let path: String
    /// How many records the tool is asked for.
    public static let limit = 50

    public init(timeout: TimeInterval = 60, path: String = ShellPath.value) {
        self.timeout = timeout
        self.path = path
    }

    public func search(_ query: VulnerabilityQuery) throws -> [KnownVulnerability] {
        // A word that reads as a flag is refused rather than passed on.
        for word in query.words where word.hasPrefix("-") {
            throw VulnerabilityLookupFault.cannotRead(reason: "\(word) reads as a flag")
        }

        let answer: ChildProcessAnswer
        do {
            answer = try ChildProcess.run(
                "/usr/bin/env",
                ["vulnx", "search", "--json", "--limit", String(Self.limit)] + query.words,
                environment: ShellPath.environment(path: path, of: ProcessInfo.processInfo.environment),
                timeout: timeout
            )
        } catch {
            throw VulnerabilityLookupFault.toolIsNotInstalled
        }

        if answer.timerKilledIt { throw VulnerabilityLookupFault.timedOut }
        // `env` exits 127 when the tool is not on PATH.
        if answer.exitCode == 127 { throw VulnerabilityLookupFault.toolIsNotInstalled }
        guard answer.exitCode == 0 else {
            throw VulnerabilityLookupFault.cannotRead(
                reason: answer.errors.isEmpty
                    ? "vulnx exited with code \(answer.exitCode)"
                    : answer.errors.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }
        return Self.records(from: Data(answer.output.utf8))
    }

    /// The records in what the tool printed: one JSON object per line, or
    /// one JSON array. A field is read under the names the tool and its
    /// predecessor `cvemap` print.
    public static func records(from bytes: Data) -> [KnownVulnerability] {
        var objects: [[String: Any]] = []
        if let parsed = try? JSONSerialization.jsonObject(with: bytes) {
            if let array = parsed as? [[String: Any]] {
                objects = array
            } else if let object = parsed as? [String: Any] {
                objects = object["results"] as? [[String: Any]]
                    ?? object["data"] as? [[String: Any]]
                    ?? [object]
            }
        } else {
            for line in String(decoding: bytes, as: UTF8.self).split(separator: "\n") {
                guard let data = line.data(using: .utf8),
                      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
                else { continue }
                objects.append(object)
            }
        }
        return objects.compactMap(record)
    }

    private static func record(_ object: [String: Any]) -> KnownVulnerability? {
        guard let id = text(object, "cve_id") ?? text(object, "id"), CveId.isValid(id) else {
            return nil
        }
        let epss = number(object, "epss_score")
            ?? number(object, "epss")
            ?? (object["epss"] as? [String: Any]).flatMap { number($0, "epss_score") ?? number($0, "score") }
        let kev = (object["is_kev"] as? Bool)
            ?? (object["kev"] as? Bool)
            ?? ((object["kev"] as? [String: Any])?["is_kev"] as? Bool)
            ?? false
        return KnownVulnerability(
            id: id,
            cvss: number(object, "cvss_score") ?? number(object, "cvss"),
            epss: epss,
            isKnownExploited: kev,
            summary: text(object, "description") ?? text(object, "cve_description") ?? text(object, "summary") ?? ""
        )
    }

    private static func text(_ object: [String: Any], _ key: String) -> String? {
        object[key] as? String
    }

    private static func number(_ object: [String: Any], _ key: String) -> Double? {
        if let value = object[key] as? Double { return value }
        if let value = object[key] as? String { return Double(value) }
        return nil
    }
}
